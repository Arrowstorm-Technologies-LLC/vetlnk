import httpx
import respx

from vetlnk import filetype


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
