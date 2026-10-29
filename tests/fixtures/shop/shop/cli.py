import click
from .app import helper


@click.command()
def admin():
    helper()


if __name__ == "__main__":
    admin()
