"""Run only by tests/test_isolation.py: a test file that tries the network while it is being imported, where there is
no test to fail. The run itself has to fail. Not collected in the normal run (the name does not start with `test_`)."""
import socket

try:
    socket.create_connection(("192.0.2.1", 9), timeout=1)
except OSError:
    pass


def test_probe_nothing_wrong_in_the_test_itself():
    assert True
