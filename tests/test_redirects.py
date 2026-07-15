import httpx
import respx

from vetlnk import redirects


def _patch_no_network(monkeypatch):
    monkeypatch.setattr(redirects, "_get_tls_info", lambda hostname, port=443: None)
    monkeypatch.setattr(redirects, "_resolve_ip", lambda hostname: "203.0.113.10")
    monkeypatch.setattr(redirects, "lookup_asn", lambda ip: (None, None))


class _PoisonBodyStream:
    """A response body that fails the test the moment anything tries to read
    it — used to prove redirect tracking never consumes the response body.
    """

    def __iter__(self):
        raise AssertionError(
            "response body was read during redirect tracking — it should only "
            "ever be touched by filetype.py's own bounded HEAD/ranged-GET probe"
        )

    def close(self):
        pass


@respx.mock
def test_follows_manual_redirect_chain(monkeypatch):
    _patch_no_network(monkeypatch)
    respx.get("http://short.example/a").mock(
        return_value=httpx.Response(302, headers={"Location": "https://final.example/b"})
    )
    respx.get("https://final.example/b").mock(return_value=httpx.Response(200))

    with httpx.Client(follow_redirects=False) as client:
        hops = redirects.follow_redirects("http://short.example/a", client=client)

    assert [h.url for h in hops] == ["http://short.example/a", "https://final.example/b"]
    assert hops[0].status_code == 302
    assert hops[1].status_code == 200


@respx.mock
def test_no_redirect_single_hop(monkeypatch):
    _patch_no_network(monkeypatch)
    respx.get("https://example.com/").mock(return_value=httpx.Response(200))

    with httpx.Client(follow_redirects=False) as client:
        hops = redirects.follow_redirects("https://example.com/", client=client)

    assert len(hops) == 1
    assert hops[0].status_code == 200


@respx.mock
def test_redirect_loop_is_detected_and_stopped(monkeypatch):
    _patch_no_network(monkeypatch)
    respx.get("https://loop.example/a").mock(
        return_value=httpx.Response(302, headers={"Location": "https://loop.example/b"})
    )
    respx.get("https://loop.example/b").mock(
        return_value=httpx.Response(302, headers={"Location": "https://loop.example/a"})
    )

    with httpx.Client(follow_redirects=False) as client:
        hops = redirects.follow_redirects("https://loop.example/a", client=client)

    assert hops[-1].error == "redirect loop detected"
    assert len(hops) <= redirects.MAX_HOPS + 1


@respx.mock
def test_response_body_is_never_read_during_redirect_tracking(monkeypatch):
    _patch_no_network(monkeypatch)
    respx.get("https://example.com/file.bin").mock(
        return_value=httpx.Response(
            200,
            headers={"content-type": "application/octet-stream"},
            stream=_PoisonBodyStream(),
        )
    )

    with httpx.Client(follow_redirects=False) as client:
        hops = redirects.follow_redirects("https://example.com/file.bin", client=client)

    # Reaching here at all (no AssertionError from _PoisonBodyStream) is the
    # proof: the hop was recorded from headers/status alone.
    assert len(hops) == 1
    assert hops[0].status_code == 200


@respx.mock
def test_connection_error_recorded_on_hop(monkeypatch):
    _patch_no_network(monkeypatch)
    respx.get("https://down.example/").mock(side_effect=httpx.ConnectError("boom"))

    with httpx.Client(follow_redirects=False) as client:
        hops = redirects.follow_redirects("https://down.example/", client=client)

    assert len(hops) == 1
    assert hops[0].error is not None
