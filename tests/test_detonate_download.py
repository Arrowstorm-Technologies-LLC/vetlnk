"""Regression test for the download-cleanup gap found while verifying the
detonation path's SIGTERM/kill behavior: the streaming download loop must
clean up its temp file on *any* exception, not just httpx.HTTPError/ValueError
— a KeyboardInterrupt from the SIGTERM handler in cli.py firing mid-download
previously left the partial file on disk, because it fell through the
narrower except clause untouched.
"""

import stat

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


@respx.mock
def test_downloaded_sample_is_readable_by_the_analyzer_containers_fixed_uid():
    """Found via a live end-to-end run: `tempfile.mkdtemp()` defaults to 0700
    (owner-only), but the analyzer container always runs as a fixed non-root
    uid (10001) that never matches the host user who downloaded the file —
    so once bind-mounted read-only into the container, a 0700 tempdir left
    analyze.py unable to even open the sample (`PermissionError: Permission
    denied`). Both the file and its containing directory need to be
    "other"-readable for the container's uid to read across that boundary.
    """
    respx.get("http://example.com/payload.exe").mock(
        return_value=httpx.Response(200, content=b"MZ" + b"\x00" * 60)
    )

    downloaded = detonate._download_for_detonation("http://example.com/payload.exe")
    assert downloaded is not None
    path, _sha256, _size = downloaded

    try:
        dir_mode = stat.S_IMODE(path.parent.stat().st_mode)
        file_mode = stat.S_IMODE(path.stat().st_mode)
        assert dir_mode & stat.S_IROTH and dir_mode & stat.S_IXOTH, (
            "tempdir must be other-readable+executable for the container's "
            "fixed non-root uid to traverse into it"
        )
        assert file_mode & stat.S_IROTH, (
            "sample file must be other-readable for the container's fixed "
            "non-root uid to read it"
        )
    finally:
        detonate._secure_delete(path)
