from requests import Session, get

host = "http://localhost:8000/"


def test_ping():
    resp = get(f"{host}ping")
    assert resp.status_code == 200
    assert resp.json() == "pong"


def test_logn():
    s = Session()
    data = {"username": "username", "password": "password"}
    resp = s.post(f"{host}signin", json=data)
    
    assert resp.status_code == 200
    access_token = resp.json()["access_token"]
    assert access_token

    auth = {"Authorization": f"Bearer {access_token}"}
    resp = s.get(f"{host}secret", headers=auth)
    assert resp.status_code == 200

    resp = s.post(f"{host}signout", headers=auth)
    print(resp)
    assert resp.status_code == 200

    resp = s.get(f"{host}secret", headers=auth)
    assert resp.status_code == 401


if __name__ == "__main__":
    for func in dir():
        if not func.startswith("test_"):
            continue

        func = globals()[func]
        if not callable(func):
            continue

        func()
        print(f"{func.__name__} passed")
