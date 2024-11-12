

from hashlib import sha3_256
from os import urandom
from string import ascii_letters

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from peewee import CharField, Model, SqliteDatabase, BigIntegerField
from redis import Redis
from sanic import Sanic
from sanic.response import json
from functools import wraps
from time import time_ns
from sanic_ext import Extend

db = SqliteDatabase("main.db")

def rand_code():
    return sha3_256(urandom(64) + hex(time_ns()).encode()).hexdigest()

class Base(Model):
    id = CharField(primary_key=True, default=rand_code())

    class Meta:
        database = db


class User(Base):
    username = CharField(unique=True)
    password = CharField()


db.connect()
db.create_tables([User], safe=True)

# create a default user
users = [("username", "password")]

for username, password in users:
    User.delete().where(User.username == username).execute()

    hasher = PasswordHasher()
    hashed = hasher.hash(password)
    try:
        User.create(username=username, password=hashed)
    except Exception as e:
        print("Failed to create user:", e)

redis = Redis()

app = Sanic(__name__)
app.config.CORS_ORIGINS = "*"
app.config.CORS_ALWAYS_SEND = True
Extend(app)

@app.route("/")
async def main(request):
    return json("Hello, World!")


@app.route("/ping")
async def ping(request):
    return json("pong")


@app.post("/signup")
async def signup(request):
    data = request.json

    username = data.get("username")
    password = data.get("password")

    if not (
        len(username) >= 4
        and len(password) >= 8
        and username.replace("_", "").isalnum()
        and username[0] in ascii_letters
    ):
        return json({"error": "Invalid username or password!"}, status=400)

    if User.select().where(User.username == username).exists():
        return json({"error": "Username already exists!"}, status=400)

    hasher = PasswordHasher()
    hashed = hasher.hash(password)

    User.create(username=username, password=hashed)
    return json("User created!")

REQUEST_TOKEN_LIFESPAN = 60 * 60
REFRESH_TOKEN_LIFESPAN = 60 * 60 * 24

def tokenize(user_id, refresh_token=rand_code(), request_token=rand_code()):
    redis.set(f"request::{request_token}", user_id, ex=REQUEST_TOKEN_LIFESPAN)
    redis.set(f"refresh::{refresh_token}", user_id, ex=REFRESH_TOKEN_LIFESPAN)

    return json({
        "access_token" : request_token,
        "refresh_token": refresh_token,
        "access_expires_in" : REQUEST_TOKEN_LIFESPAN,
        "refresh_expires_in": REFRESH_TOKEN_LIFESPAN
    })


@app.post("/signin")
async def signin(request):
    data = request.json

    username = data.get("username")
    password = data.get("password")

    user = User.select().where(User.username == username).first()

    if not user:
        return json({"error": "User not found!"}, status=404)

    try:
        hasher = PasswordHasher()
        assert hasher.verify(user.password, password)
    except VerifyMismatchError:
        return json({"error": "Invalid password!"}, status=400)
    except Exception as e:
        return json({"error": ""}, status=500)

    code = sha3_256(urandom(32).__bytes__()).hexdigest()
    redis.set(code, user.id)

    return tokenize(user.id)

@app.post("/refresh")
async def refresh(request):
    refresh_token = request.json.get("refresh_token")

    # check if refresh token is valid
    user_id = redis.get(f"refresh::{refresh_token}")
    if not user_id:
        return json({"error": "Invalid refresh token!"}, status=400)

    resp = tokenize(user_id, refresh_token)
    return resp

@app.post("/signout")
async def logout(request):
    token = request.headers.get("Authorization")
    token = token.split(" ")[-1] if token else None

    if not token:
        return json({"error": "Unauthorized!"}, status=401)
    
    redis.delete(f"request::{token}")

    resp = json("Logged out!")
    return resp

def login_required(f):
    @wraps(f)
    async def decorated_function(request, *args, **kwargs):
        # get the Authorization header
        token = request.headers.get("Authorization")
        token = token.split(" ")[-1] if token else None
        if not token:
            return json({"error": "Unauthorized!"}, status=401)

        user = User.select().where(User.id == redis.get(f"request::{token}")).first()
        if not user:
            return json({"error": "Unauthorized!"}, status=401)

        if "user" in f.__code__.co_varnames:
            return await f(request, user, *args, **kwargs)
        else:
            return await f(request, *args, **kwargs)
    return decorated_function


@app.get("/secret")
@login_required
async def secret(request, user):
    return json("Secret!")

@app.get("/username")
@login_required
async def username(request, user):
    return json(user.username)


if __name__ == "__main__":
    app.run(port=8000, debug=True, auto_reload=True)
