from hashlib import sha3_256
from os import urandom
from string import ascii_letters

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from peewee import CharField, Model, SqliteDatabase
from redis import Redis
from sanic import Sanic
from sanic.response import json

db = SqliteDatabase("main.db")


class Base(Model):
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
    User.create(username=username, password=hashed)

redis = Redis()

app = Sanic(__name__)


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
    redis.set(code, username)

    # set cookies
    resp = json("Logged in!")
    resp.cookies["session"] = code
    resp.cookies["session"]["httponly"] = True

    return resp


@app.post("/logout")
async def logout(request):
    code = request.cookies.get("session")
    redis.delete(code)

    # remove cookies
    resp = json("Logged out!")
    resp.cookies["session"] = ""
    resp.cookies["session"]["max-age"] = 0
    return resp


def logged_in(request) -> bool:
    code = request.cookies.get("session") or ""
    name = redis.get(code)
    user = User.select().where(User.username == name).first()
    return bool(user)


@app.get("/secret")
async def secret(request):
    if not logged_in(request):
        return json({"error": "Unauthorized!"}, status=401)
    return json("Secret!")


if __name__ == "__main__":
    app.run(port=8000, dev=True)
