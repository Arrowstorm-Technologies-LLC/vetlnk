"""Determine the TRUE type of a linked file without downloading it.

Sends a HEAD request first; if headers are ambiguous, follows with a short
ranged GET (first ~256 bytes only) and matches magic-byte signatures rather
than trusting the server's Content-Type header.
"""

from __future__ import annotations

from urllib.parse import unquote, urlsplit

import httpx

from vetlnk.models import FileInfo

_RANGE_BYTES = 256
_TIMEOUT = 10.0
_USER_AGENT = "vetlnk/0.1 (+https://github.com/Arrowstorm-Technologies-LLC/vetlnk)"

# (signature bytes, offset, true type label, risk note)
_SIGNATURES: list[tuple[bytes, int, str, str]] = [
    (b"MZ", 0, "Windows PE executable (.exe/.dll/.scr/.com)",
     "This is a Windows executable — running it grants it full access to your system."),
    (b"\x7fELF", 0, "Linux ELF executable/library",
     "This is a native Linux executable — running it grants it full access to your system."),
    (b"%PDF-", 0, "PDF document", "PDFs can embed scripts — treat unexpected ones with caution."),
    (b"PK\x03\x04", 0, "ZIP archive (or Office/JAR/APK container)",
     "Archives can hide executables inside — inspect contents before extracting/running."),
    (b"PK\x05\x06", 0, "ZIP archive (empty)", "Empty ZIP container."),
    (b"Rar!\x1a\x07", 0, "RAR archive",
     "Archives can hide executables inside — inspect contents before extracting/running."),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip archive",
     "Archives can hide executables inside — inspect contents before extracting/running."),
    (b"\x1f\x8b", 0, "GZIP archive", "Compressed archive — inspect contents before extracting."),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0,
     "Legacy MS Office / OLE compound file (.doc/.xls/.ppt/.msi)",
     "Legacy Office documents can carry macros — treat unexpected ones with caution."),
    (b"\x89PNG\r\n\x1a\n", 0, "PNG image", "Image file — low inherent execution risk."),
    (b"\xff\xd8\xff", 0, "JPEG image", "Image file — low inherent execution risk."),
    (b"GIF87a", 0, "GIF image", "Image file — low inherent execution risk."),
    (b"GIF89a", 0, "GIF image", "Image file — low inherent execution risk."),
    (b"%!PS", 0, "PostScript document", "Document file."),
    (b"#!", 0, "Script with shebang (shell/interpreter)",
     "This is an executable script — running it executes arbitrary commands as you."),
    (b"\xca\xfe\xba\xbe", 0, "Java class / Mach-O fat binary",
     "This is executable code — running it grants it full access to your system."),
    (b"\xfe\xed\xfa\xce", 0, "Mach-O executable (32-bit)",
     "This is a macOS executable — running it grants it full access to your system."),
    (b"\xfe\xed\xfa\xcf", 0, "Mach-O executable (64-bit)",
     "This is a macOS executable — running it grants it full access to your system."),
    (b"\xcf\xfa\xed\xfe", 0, "Mach-O executable (64-bit, little-endian)",
     "This is a macOS executable — running it grants it full access to your system."),
]

# Extensions we treat as "declared type" for mismatch comparison, mapped to
# what magic-byte families we'd expect. Anything not covered isn't flagged.
_EXT_EXPECTATION: dict[str, tuple[str, ...]] = {
    "pdf": ("PDF document",),
    "png": ("PNG image",),
    "jpg": ("JPEG image",),
    "jpeg": ("JPEG image",),
    "gif": ("GIF image",),
    "zip": ("ZIP archive (or Office/JAR/APK container)", "ZIP archive (empty)"),
    "doc": ("Legacy MS Office / OLE compound file (.doc/.xls/.ppt/.msi)",),
    "xls": ("Legacy MS Office / OLE compound file (.doc/.xls/.ppt/.msi)",),
    "ppt": ("Legacy MS Office / OLE compound file (.doc/.xls/.ppt/.msi)",),
}

# Declared extensions that most people expect NOT to be executable — a magic-byte
# hit for any executable family here is the "major red flag" case from the spec.
_NON_EXECUTABLE_EXTENSIONS = {
    "pdf", "png", "jpg", "jpeg", "gif", "txt", "csv", "doc", "docx", "xls", "xlsx",
    "ppt", "pptx", "mp3", "mp4", "mov", "avi", "log", "json", "xml",
}
_EXECUTABLE_TYPE_LABELS = {
    "Windows PE executable (.exe/.dll/.scr/.com)",
    "Linux ELF executable/library",
    "Script with shebang (shell/interpreter)",
    "Java class / Mach-O fat binary",
    "Mach-O executable (32-bit)",
    "Mach-O executable (64-bit)",
    "Mach-O executable (64-bit, little-endian)",
}


def _match_signature(chunk: bytes) -> tuple[str, str] | None:
    for sig, offset, label, note in _SIGNATURES:
        if chunk[offset : offset + len(sig)] == sig:
            return label, note
    return None


def _declared_filename(url: str, headers: httpx.Headers) -> str | None:
    disposition = headers.get("content-disposition", "")
    if "filename=" in disposition:
        name = disposition.split("filename=", 1)[1].strip().strip('"; ')
        if name:
            return unquote(name)
    path = urlsplit(url).path
    return unquote(path.rsplit("/", 1)[-1]) if path.rsplit("/", 1)[-1] else None


def probe_file(url: str, *, client: httpx.Client | None = None) -> FileInfo | None:
    """HEAD first; ranged GET only if we still need magic bytes. Never downloads the full body."""
    owns_client = client is None
    client = client or httpx.Client(timeout=_TIMEOUT, headers={"User-Agent": _USER_AGENT})

    try:
        head_resp = client.head(url, follow_redirects=True)
        headers = head_resp.headers
        content_type = headers.get("content-type", "").split(";")[0].strip()
        content_length = int(headers["content-length"]) if "content-length" in headers else None

        # A generic/binary content-type or missing one is "ambiguous" — read magic bytes.
        ambiguous = content_type in ("", "application/octet-stream", "binary/octet-stream")

        true_type = None
        risk_note = None
        if ambiguous or content_type not in ("text/html", "text/plain"):
            range_resp = client.get(
                url,
                headers={"Range": f"bytes=0-{_RANGE_BYTES - 1}"},
                follow_redirects=True,
            )
            if range_resp.status_code not in (200, 206) or not range_resp.content:
                owns_client and client.close()
                return None
            chunk = range_resp.content[:_RANGE_BYTES]
            match = _match_signature(chunk)
            if match:
                true_type, risk_note = match
            headers = range_resp.headers
            if content_length is None and "content-length" in headers:
                content_length = int(headers["content-length"])

        if true_type is None:
            # Not a file we recognize as a "download" (e.g. plain HTML page) — nothing to report.
            return None

        filename = _declared_filename(url, headers)
        declared_ext = filename.rsplit(".", 1)[-1].lower() if filename and "." in filename else None

        type_mismatch = False
        if declared_ext:
            expected_labels = _EXT_EXPECTATION.get(declared_ext)
            if expected_labels and true_type not in expected_labels:
                type_mismatch = True
            elif (
                declared_ext in _NON_EXECUTABLE_EXTENSIONS
                and true_type in _EXECUTABLE_TYPE_LABELS
            ):
                type_mismatch = True

        return FileInfo(
            declared_filename=filename,
            declared_content_type=content_type or None,
            content_length=content_length,
            true_type=true_type,
            type_mismatch=type_mismatch,
            risk_note=risk_note,
            hosting_domain=urlsplit(url).hostname,
        )
    except httpx.HTTPError:
        return None
    finally:
        if owns_client:
            client.close()
