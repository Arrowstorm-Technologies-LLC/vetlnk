import pytest


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch):
    """Belt-and-suspenders: fail loudly if a test tries to hit the real network."""

    def _blocked(*args, **kwargs):
        raise RuntimeError("Network access attempted in a test — mock it instead.")

    monkeypatch.setattr("socket.create_connection", _blocked)
