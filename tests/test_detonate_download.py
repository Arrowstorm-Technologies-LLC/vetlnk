"""Regression test for the download-cleanup gap found while verifying the
detonation path's SIGTERM/kill behavior: the streaming download loop must
clean up its temp file on *any* exception, not just httpx.HTTPError/ValueError
— a KeyboardInterrupt from the SIGTERM handler in cli.py firing mid-download
previously left the partial file on disk, because it fell through the
narrower except clause untouched.
"""

import httpx
import respx

from vetlnk import detonate


class _InterruptedStream:
    """Yields a couple of chunks, then raises KeyboardInterrupt — simulating
    a SIGTERM (or Ctrl+C) arriving mid-download, the exact scenario a plain
    `except (httpx.HTTPError, ValueError)` would fail to clean up after.
    """

    def __iter__(self):
        yield b"PK\x03\x04" + b"\x00" * 60
        raise KeyboardInterrupt()

    def close(self):
        pass


@respx.mock
def test_interrupted_download_still_cleans_up_temp_file():
    respx.get("http://example.com/payload.zip").mock(
        return_value=httpx.Response(200, stream=_InterruptedStream())
    )

    created_paths = []
    real_mkdtemp = detonate.tempfile.mkdtemp

    def _tracking_mkdtemp(*args, **kwargs):
        path = real_mkdtemp(*args, **kwargs)
        created_paths.append(path)
        return path

    detonate.tempfile.mkdtemp = _tracking_mkdtemp
    try:
        try:
            detonate._download_for_detonation("http://example.com/payload.zip")
            raised = False
        except KeyboardInterrupt:
            raised = True
    finally:
        detonate.tempfile.mkdtemp = real_mkdtemp

    assert raised, "KeyboardInterrupt should propagate, not be swallowed"
    assert len(created_paths) == 1
    from pathlib import Path

    assert not Path(created_paths[0]).exists(), (
        "temp directory should have been removed by the finally-block cleanup "
        "even though the interruption wasn't an httpx.HTTPError or ValueError"
    )
