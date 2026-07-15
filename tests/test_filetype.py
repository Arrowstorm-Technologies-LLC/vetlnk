import httpx
import respx

from vetlnk import filetype


class _IgnoresRangeStream:
    """Simulates a server that ignores the Range header and just keeps
    sending data — proves the ~256-byte cap is enforced by us, not merely
    requested of the server.
    """

    def __init__(self, first_chunk: bytes, total_chunks: int = 100_000):
        self.first_chunk = first_chunk
        self.total_chunks = total_chunks
        self.chunks_yielded = 0

    def __iter__(self):
        yield self.first_chunk
        self.chunks_yielded += 1
        for _ in range(self.total_chunks - 1):
            self.chunks_yielded += 1
            yield b"A" * 8192

    def close(self):
        pass


@respx.mock
def test_true_type_mismatch_detected_for_pe_disguised_as_pdf():
    respx.head("http://evil.example/invoice.pdf").mock(
        return_value=httpx.Response(200, headers={"content-type": "application/pdf"})
    )
    respx.get("http://evil.example/invoice.pdf").mock(
        return_value=httpx.Response(
            206,
            headers={"content-type": "application/pdf", "content-length": "51200"},
            content=b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 40,
        )
    )

    with httpx.Client() as client:
        info = filetype.probe_file("http://evil.example/invoice.pdf", client=client)

    assert info is not None
    assert info.true_type == "Windows PE executable (.exe/.dll/.scr/.com)"
    assert info.type_mismatch is True
    assert info.declared_filename == "invoice.pdf"


@respx.mock
def test_matching_declared_and_true_type_not_flagged():
    respx.head("http://example.com/report.pdf").mock(
        return_value=httpx.Response(200, headers={"content-type": "application/pdf"})
    )
    respx.get("http://example.com/report.pdf").mock(
        return_value=httpx.Response(
            206,
            headers={"content-type": "application/pdf"},
            content=b"%PDF-1.4\n" + b"\x00" * 40,
        )
    )

    with httpx.Client() as client:
        info = filetype.probe_file("http://example.com/report.pdf", client=client)

    assert info is not None
    assert info.true_type == "PDF document"
    assert info.type_mismatch is False


@respx.mock
def test_html_page_is_not_treated_as_a_file_download():
    respx.head("https://example.com/").mock(
        return_value=httpx.Response(200, headers={"content-type": "text/html; charset=utf-8"})
    )

    with httpx.Client() as client:
        info = filetype.probe_file("https://example.com/", client=client)

    assert info is None


@respx.mock
def test_unrecognized_binary_returns_none():
    respx.head("http://example.com/data.bin").mock(
        return_value=httpx.Response(200, headers={"content-type": "application/octet-stream"})
    )
    respx.get("http://example.com/data.bin").mock(
        return_value=httpx.Response(
            206,
            headers={"content-type": "application/octet-stream"},
            content=b"\x01\x02\x03\x04" * 10,
        )
    )

    with httpx.Client() as client:
        info = filetype.probe_file("http://example.com/data.bin", client=client)

    assert info is None


@respx.mock
def test_range_ignoring_server_does_not_force_a_full_download():
    stream = _IgnoresRangeStream(first_chunk=b"MZ\x90\x00" + b"\x00" * 60)
    respx.head("http://evil.example/payload.exe").mock(
        return_value=httpx.Response(200, headers={"content-type": "application/octet-stream"})
    )
    respx.get("http://evil.example/payload.exe").mock(
        return_value=httpx.Response(
            206, headers={"content-type": "application/octet-stream"}, stream=stream
        )
    )

    with httpx.Client() as client:
        info = filetype.probe_file("http://evil.example/payload.exe", client=client)

    assert info is not None
    assert info.true_type == "Windows PE executable (.exe/.dll/.scr/.com)"
    # A server willing to send 100,000 chunks never got the chance to: we
    # stopped reading as soon as we had our ~256 bytes.
    assert stream.chunks_yielded < 10
