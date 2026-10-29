import subprocess
from fastapi import FastAPI
from .auth import Session, make_repo

app = FastAPI()


@app.get("/users/{user_id}")
def read_user(user_id: str):
    s = Session()
    return s.login(user_id, "pw")


@app.post("/backup")
def backup(name: str):
    subprocess.call("tar czf " + name + ".tgz data/", shell=True)
    r = make_repo()
    r.save({"name": name})
    return {"ok": True}


def helper():
    def inner():
        return 1
    return inner()
