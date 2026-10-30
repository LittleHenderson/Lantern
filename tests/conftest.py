import pytest


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Tests never call vulnerability databases; tests/test_depaudit.py fakes those calls instead."""
    monkeypatch.setenv("LANTERN_OFFLINE", "1")
