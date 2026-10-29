import hashlib
from . import repo as repo_mod
from .repo import UserRepo

SECRET = "hunter2-super-secret"


class Session:
    def __init__(self):
        self.users = UserRepo("app.db")

    def login(self, user_id, password):
        user = self.users.get(user_id)
        return check_password(password, user)


def check_password(password, user):
    return hashlib.md5(password.encode()).hexdigest() == user


def make_repo():
    return repo_mod.UserRepo("app.db")
