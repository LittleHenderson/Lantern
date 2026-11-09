import ipaddress
import socket

import pytest

# Every variable that can point Lantern at a real model or the hosted allowance. A developer's own shell often has one
# set; a test must never inherit it (an independent review on 2026-11-09 found one test reaching a real model that way).
PROVIDER_ENV = ("ANTHROPIC_API_KEY", "DEEPSEEK_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY", "MISTRAL_API_KEY",
                "GEMINI_API_KEY", "LANTERN_API_KEY", "LANTERN_TOKEN", "LANTERN_MODEL", "LANTERN_GATEWAY_URL",
                "LANTERN_PRIMARY")


@pytest.fixture(autouse=True)
def _no_network(monkeypatch, tmp_path_factory):
    """Tests never call vulnerability databases or model providers; tests/test_depaudit.py and the fake model server
    stand in for them. Provider settings from the developer's shell are removed, LANTERN_HOME (saved keys and sign-in
    tokens) points at an empty folder, and any connection to a non-local address fails."""
    monkeypatch.setenv("LANTERN_OFFLINE", "1")
    for k in PROVIDER_ENV:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("LANTERN_HOME", str(tmp_path_factory.mktemp("lantern-home")))
    real = socket.socket.connect

    def connect(self, address):
        host = address[0] if isinstance(address, tuple) else None
        if host is not None:
            try:
                local = ipaddress.ip_address(host.split("%")[0]).is_loopback
            except ValueError:
                local = host == "localhost"
            if not local:
                raise OSError(f"tests may not reach the network ({host})")
        return real(self, address)

    monkeypatch.setattr(socket.socket, "connect", connect)
