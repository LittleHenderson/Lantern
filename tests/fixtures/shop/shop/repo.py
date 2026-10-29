import sqlite3


class BaseRepo:
    def __init__(self, path):
        self.conn = sqlite3.connect(path)

    def execute(self, sql):
        return self.conn.execute(sql)


class UserRepo(BaseRepo):
    def get(self, user_id):
        # deliberately unsafe: string-built SQL
        return self.execute("SELECT * FROM users WHERE id = '%s'" % user_id)

    def save(self, user):
        self.validate(user)
        return self.execute("INSERT INTO users VALUES (?)")

    def validate(self, user):
        return bool(user)


class CachedUserRepo(UserRepo):
    def validate(self, user):
        return super().validate(user)


class Settings:
    def __init__(self, path=None):
        self.path = path

    @classmethod
    def default(cls):
        return cls("app.db")
