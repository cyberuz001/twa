from __future__ import annotations

import base64
import zipfile

from twa.core import (
    Session,
    _redact_header,
    analyze_path,
    decode_text,
    inspect_pcap,
    load_session,
    save_session,
    validate_remote_target,
)


def test_zip_flag_discovery(tmp_path):
    archive = tmp_path / "challenge.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("clue.txt", "The answer is CTF4{inside_zip}")
    session = Session(target=str(archive))
    analyze_path(session, archive)
    assert [flag.value for flag in session.flags] == ["CTF4{inside_zip}"]
    assert session.flags[0].verified is False


def test_base64_decoding():
    encoded = base64.b64encode(b"flag{decoded_here}").decode()
    assert any("flag{decoded_here}" in item["text"] for item in decode_text(encoded))


def test_single_byte_xor_decoding():
    payload = bytes(value ^ 0x23 for value in b"flag{xor_decoded}").hex()
    results = decode_text(payload)
    assert any(
        item["method"] == "xor-single-byte:0x23" and "flag{xor_decoded}" in item["text"]
        for item in results
    )


def test_corrupted_zip_is_factual(tmp_path):
    path = tmp_path / "broken.zip"
    path.write_bytes(b"PK\x03\x04 definitely-not-a-zip")
    session = Session(target=str(path))
    analyze_path(session, path)
    assert session.status == "running"
    assert session.errors
    assert not session.flags


def test_session_atomic_roundtrip(tmp_path):
    session = Session(target="fixture")
    save_session(session, tmp_path)
    assert load_session(session.session_id, tmp_path).target == "fixture"


def test_remote_scope_requires_exact_host():
    assert (
        validate_remote_target("https://example.test/", "example.test") == "https://example.test/"
    )
    try:
        validate_remote_target("https://example.test.evil/", "example.test")
    except ValueError as exc:
        assert "exactly match" in str(exc)
    else:
        raise AssertionError("out-of-scope hostname accepted")


def test_cookie_values_redacted_in_report_headers():
    assert _redact_header("set-cookie", "sessionid=sensitive; HttpOnly") == "sessionid=[REDACTED]"
    assert _redact_header("server", "challenge") == "challenge"


def test_pcap_bad_magic():
    assert inspect_pcap(b"not a pcap")["error"].startswith("Unsupported")


def test_png_text_chunk(tmp_path):
    import struct
    import zlib

    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))

    raw = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">2I5B", 1, 1, 8, 2, 0, 0, 0))
        + chunk(b"tEXt", b"note\x00flag{png_note}")
        + chunk(b"IEND", b"")
    )
    path = tmp_path / "image.png"
    path.write_bytes(raw)
    session = Session(target=str(path))
    analyze_path(session, path)
    assert session.flags[0].value == "flag{png_note}"
