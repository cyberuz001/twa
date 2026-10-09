from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import socket
import struct
import tempfile
import uuid
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx
from pydantic import BaseModel, Field

FLAG_DEFAULT = r"(?i)(?:CTF4|CTF|flag|HTB|picoCTF)\{[^\r\n}]{1,200}\}"
MAX_FILES = 500
MAX_FILE_BYTES = 2_000_000
MAX_ARCHIVE_BYTES = 20_000_000
MAX_TEXT_BYTES = 250_000


class Evidence(BaseModel):
    source: str
    kind: str
    summary: str
    sha256: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class FlagCandidate(BaseModel):
    value: str
    source: str
    evidence: str
    confidence: float = 0.35
    verified: bool = False


class Session(BaseModel):
    session_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    target: str
    scope: str | None = None
    model_id: str | None = None
    category: str = "unknown"
    status: str = "running"
    evidence: list[Evidence] = Field(default_factory=list)
    flags: list[FlagCandidate] = Field(default_factory=list)
    errors: list[dict[str, str]] = Field(default_factory=list)
    recovery_actions: list[str] = Field(default_factory=list)
    ai_summary: str | None = None
    report_path: str | None = None


def workspace_root() -> Path:
    return Path.cwd() / ".twa"


def save_session(session: Session, root: Path | None = None) -> Path:
    directory = (root or workspace_root()) / "sessions"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{session.session_id}.json"
    fd, temporary = tempfile.mkstemp(prefix=f".{session.session_id}-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(session.model_dump_json(indent=2))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return path


def load_session(session_id: str, root: Path | None = None) -> Session:
    if not re.fullmatch(r"[a-f0-9]{12}", session_id):
        raise ValueError("Invalid session ID")
    return Session.model_validate_json(
        ((root or workspace_root()) / "sessions" / f"{session_id}.json").read_text(encoding="utf-8")
    )


def list_sessions(root: Path | None = None) -> list[Session]:
    directory = (root or workspace_root()) / "sessions"
    if not directory.exists():
        return []
    sessions = []
    for path in directory.glob(
        "[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f].json"
    ):
        try:
            sessions.append(Session.model_validate_json(path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    return sorted(sessions, key=lambda item: item.created_at, reverse=True)


def classify_bytes(name: str, data: bytes) -> str:
    lowered = name.lower()
    if data.startswith(b"PK\x03\x04"):
        return "archive"
    if (
        data.startswith(b"\x89PNG\r\n\x1a\n")
        or data.startswith(b"\xff\xd8\xff")
        or data.startswith((b"GIF87a", b"GIF89a"))
    ):
        return "image"
    if data.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a")):
        return "pcap"
    if data.startswith(b"\x7fELF") or data.startswith(b"MZ"):
        return "binary"
    if any(token in lowered for token in (".pcap", ".cap")):
        return "pcap"
    if data and b"\x00" not in data[:4096]:
        return "text"
    return "binary"


def category_for(kinds: list[str], target: str) -> str:
    if target.startswith(("http://", "https://")):
        return "web"
    for kind in ("pcap", "image", "archive", "binary", "text"):
        if kind in kinds:
            return {
                "pcap": "forensics",
                "image": "steganography",
                "archive": "forensics",
                "binary": "reverse",
                "text": "cryptography",
            }[kind]
    return "unknown"


def hash_data(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inspect_png(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {"format": "PNG", "chunks": [], "text": []}
    offset = 8
    while offset + 12 <= min(len(data), MAX_FILE_BYTES):
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        kind = data[offset + 4 : offset + 8]
        end = offset + 12 + length
        if length > MAX_FILE_BYTES or end > len(data):
            result["truncated"] = True
            break
        chunk = data[offset + 8 : offset + 8 + length]
        result["chunks"].append(kind.decode("ascii", "replace"))
        if kind == b"tEXt" and b"\x00" in chunk:
            key, value = chunk.split(b"\x00", 1)
            result["text"].append(
                {
                    "key": key.decode("latin-1", "replace"),
                    "value": value[:4096].decode("latin-1", "replace"),
                }
            )
        if kind == b"IEND":
            break
        offset = end
    return result


def inspect_pcap(data: bytes) -> dict[str, Any]:
    magics = {
        b"\xd4\xc3\xb2\xa1": ("<", "microseconds"),
        b"\xa1\xb2\xc3\xd4": (">", "microseconds"),
        b"\x4d\x3c\xb2\xa1": ("<", "nanoseconds"),
        b"\xa1\xb2\x3c\x4d": (">", "nanoseconds"),
    }
    if data[:4] not in magics or len(data) < 24:
        return {"format": "pcap", "error": "Unsupported or truncated classic PCAP"}
    endian, timestamp_precision = magics[data[:4]]
    network = struct.unpack(endian + "I", data[20:24])[0]
    offset, count, hosts = 24, 0, set()
    while offset + 16 <= len(data) and count < 10000:
        _, _, captured, _ = struct.unpack(endian + "IIII", data[offset : offset + 16])
        offset += 16
        if captured > MAX_FILE_BYTES or offset + captured > len(data):
            break
        packet = data[offset : offset + captured]
        offset += captured
        count += 1
        if (
            network == 1
            and len(packet) >= 34
            and packet[12:14] == b"\x08\x00"
            and packet[23] in (6, 17)
        ):
            hosts.update((socket.inet_ntoa(packet[26:30]), socket.inet_ntoa(packet[30:34])))
    return {
        "format": "pcap",
        "timestamp_precision": timestamp_precision,
        "link_type": network,
        "packets_inspected": count,
        "ipv4_hosts": sorted(hosts),
    }


def decode_text(text: str) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    candidate = "".join(text.split())
    if len(candidate) >= 8:
        attempts = [
            ("base64", base64.b64decode, candidate),
            ("base32", base64.b32decode, candidate.upper()),
        ]
        for label, decoder, value in attempts:
            try:
                decoded = decoder(value, validate=True) if label == "base64" else decoder(value)
                readable = decoded.decode("utf-8", "replace")
                if (
                    readable.strip()
                    and sum(c.isprintable() for c in readable) / len(readable) > 0.8
                ):
                    results.append({"method": label, "text": readable[:MAX_TEXT_BYTES]})
            except (binascii.Error, ValueError):
                pass
    hex_candidate = candidate.removeprefix("0x")
    if (
        len(hex_candidate) >= 8
        and len(hex_candidate) % 2 == 0
        and re.fullmatch("[0-9a-fA-F]+", hex_candidate)
    ):
        try:
            decoded_bytes = bytes.fromhex(hex_candidate)
            results.append(
                {
                    "method": "hex",
                    "text": decoded_bytes.decode("utf-8", "replace")[:MAX_TEXT_BYTES],
                }
            )
            xor_candidates = []
            for key in range(256):
                decoded = bytes(value ^ key for value in decoded_bytes)
                readable = decoded.decode("utf-8", "replace")
                score = sum(char.isprintable() or char in "\r\n\t" for char in readable) / max(
                    len(readable), 1
                )
                if score >= 0.9 and any(
                    token in readable.lower() for token in ("flag", "ctf", "the ")
                ):
                    xor_candidates.append((score, key, readable))
            if xor_candidates:
                _, key, readable = max(xor_candidates)
                results.append(
                    {
                        "method": f"xor-single-byte:0x{key:02x}",
                        "text": readable[:MAX_TEXT_BYTES],
                    }
                )
        except ValueError:
            pass
    rotated = text.translate(
        str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
        )
    )
    if rotated != text:
        results.append({"method": "rot13", "text": rotated[:MAX_TEXT_BYTES]})
    return results


def _add_evidence(
    session: Session,
    source: str,
    kind: str,
    summary: str,
    data: bytes | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    session.evidence.append(
        Evidence(
            source=source,
            kind=kind,
            summary=summary[:2000],
            sha256=hash_data(data) if data is not None else None,
            details=details or {},
        )
    )


def _find_flags(session: Session, text: str, source: str, pattern: str) -> None:
    try:
        matches = set(
            re.findall(pattern, text)
            if not re.compile(pattern).groups
            else [m.group(0) for m in re.finditer(pattern, text)]
        )
    except re.error as exc:
        raise ValueError(f"Invalid flag regular expression: {exc}") from exc
    existing = {flag.value for flag in session.flags}
    for match in sorted(str(item) for item in matches):
        if match not in existing:
            session.flags.append(
                FlagCandidate(
                    value=match,
                    source=source,
                    evidence=f"Regex match in {source}; not independently verified",
                )
            )
            existing.add(match)


def _analyze_member(session: Session, name: str, data: bytes, pattern: str) -> str:
    kind = classify_bytes(name, data)
    details: dict[str, Any] = {"size": len(data)}
    text = data[:MAX_TEXT_BYTES].decode("utf-8", "replace") if kind == "text" else ""
    summary = "Binary evidence retained by SHA-256; no executable was run."
    if kind == "text":
        details["preview"] = text[:4000]
        decodings = decode_text(text.strip()) if len(text) < MAX_TEXT_BYTES else []
        details["decodings"] = decodings[:8]
        summary = (
            f"Text inspected ({len(data)} bytes); bounded preview and common encodings checked."
        )
        _find_flags(session, text, name, pattern)
        for decoded in decodings:
            _find_flags(session, decoded["text"], f"{name} ({decoded['method']})", pattern)
    elif kind == "image" and data.startswith(b"\x89PNG\r\n\x1a\n"):
        details.update(inspect_png(data))
        for entry in details["text"]:
            _find_flags(session, entry["value"], name, pattern)
        summary = f"PNG signature and {len(details['chunks'])} chunk(s) inspected."
    elif kind == "image":
        summary = "Image signature detected; install TWA metadata extra for EXIF inspection."
        try:
            import io

            from PIL import Image

            with Image.open(io.BytesIO(data)) as image:
                details.update(
                    {"format": image.format, "size": image.size, "exif_tags": len(image.getexif())}
                )
                exif_text = " ".join(str(value) for value in image.getexif().values())
                _find_flags(session, exif_text, name, pattern)
                summary = (
                    f"{image.format} image metadata inspected; "
                    f"{len(image.getexif())} EXIF field(s)."
                )
        except ImportError:
            pass
        except Exception as exc:
            details["metadata_error"] = type(exc).__name__
    elif kind == "pcap":
        details.update(inspect_pcap(data))
        for match in re.findall(rb"[ -~]{5,}", data[:MAX_FILE_BYTES]):
            _find_flags(session, match.decode("ascii", "ignore"), name, pattern)
        summary = (
            f"Capture inspected; {details.get('packets_inspected', 0)} packet(s) "
            "parsed where supported."
        )
    elif kind == "archive":
        summary = "Archive directory inspected with bounded reads; no files extracted to disk."
    elif kind == "binary":
        strings = [
            chunk.decode("ascii", "ignore")
            for chunk in re.findall(rb"[ -~]{5,}", data[:MAX_FILE_BYTES])[:2000]
        ]
        details["strings"] = strings[:100]
        _find_flags(session, "\n".join(strings), name, pattern)
        summary = (
            "Binary signature/printable strings inspected; execution is disabled "
            f"({len(strings)} strings)."
        )
    _add_evidence(session, name, kind, summary, data, details)
    return kind


def analyze_path(
    session: Session,
    path: Path,
    pattern: str = FLAG_DEFAULT,
    max_files: int = MAX_FILES,
) -> None:
    resolved = path.expanduser().resolve(strict=True)
    if resolved.is_dir():
        kinds = []
        files = []
        for item in resolved.rglob("*"):
            if item.is_file() and not item.is_symlink():
                files.append(item)
                if len(files) >= min(max_files, MAX_FILES):
                    break
        for item in files:
            try:
                size = item.stat().st_size
                if size > MAX_FILE_BYTES:
                    _add_evidence(
                        session,
                        str(item.relative_to(resolved)),
                        "skipped",
                        f"Skipped oversized file ({size} bytes).",
                    )
                    continue
                data = item.read_bytes()
                kinds.append(
                    _analyze_member(session, str(item.relative_to(resolved)), data, pattern)
                )
            except OSError as exc:
                session.errors.append({"source": str(item), "message": str(exc)[:300]})
        if len(files) >= min(max_files, MAX_FILES):
            session.recovery_actions.append(
                f"Directory traversal capped at {min(max_files, MAX_FILES)} files."
            )
        session.category = category_for(kinds, str(resolved))
        return
    if not resolved.is_file():
        raise ValueError("Input must be a regular file or directory")
    with resolved.open("rb") as stream:
        signature = stream.read(8)
    is_archive = classify_bytes(resolved.name, signature) == "archive"
    max_input = MAX_ARCHIVE_BYTES if is_archive else MAX_FILE_BYTES
    if resolved.stat().st_size > max_input:
        raise ValueError(f"Input exceeds the {max_input}-byte input limit")
    data = resolved.read_bytes()
    kinds: list[str] = []
    if is_archive:
        total = 0
        try:
            with zipfile.ZipFile(resolved) as archive:
                for info in archive.infolist()[: min(max_files, MAX_FILES)]:
                    if info.is_dir():
                        continue
                    name_path = Path(info.filename)
                    if (
                        name_path.is_absolute()
                        or ".." in name_path.parts
                        or info.file_size > MAX_FILE_BYTES
                    ):
                        session.recovery_actions.append(
                            f"Skipped unsafe or oversized archive member: {info.filename[:180]}"
                        )
                        continue
                    total += info.file_size
                    if total > MAX_ARCHIVE_BYTES:
                        session.recovery_actions.append("Archive uncompressed-size limit reached.")
                        break
                    payload = archive.read(info)
                    kinds.append(_analyze_member(session, info.filename, payload, pattern))
        except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
            _add_evidence(
                session, str(resolved), "archive", f"Archive could not be read: {exc}", data
            )
            session.errors.append({"source": str(resolved), "message": f"Corrupted archive: {exc}"})
    else:
        kinds.append(_analyze_member(session, str(resolved), data, pattern))
    session.category = category_for(kinds, str(resolved))


def validate_remote_target(target: str, scope: str | None) -> str:
    value = target if "://" in target else f"http://{target}"
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ValueError("Target must be an http(s) URL without embedded credentials")
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        if len(parsed.hostname) > 253 or not re.fullmatch(
            r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*",
            parsed.hostname,
        ):
            raise ValueError("Target hostname is invalid") from None
    if not scope:
        raise ValueError("Remote analysis requires --scope with the exact authorized host")
    if scope.strip().lower().rstrip(".") != parsed.hostname.lower().rstrip("."):
        raise ValueError("Target host does not exactly match --scope")
    return value


def analyze_remote(
    session: Session,
    target: str,
    scope: str,
    timeout: float = 10,
    pattern: str = FLAG_DEFAULT,
) -> None:
    url = validate_remote_target(target, scope)
    session.category = "web"
    origin = f"{urlsplit(url).scheme}://{urlsplit(url).netloc}"
    paths = [urlsplit(url).path or "/", "/robots.txt", "/sitemap.xml"]
    seen = set()
    with httpx.Client(
        timeout=timeout,
        follow_redirects=False,
        max_redirects=0,
        verify=True,
        headers={"User-Agent": "TWA-CTF-Research/0.1 (passive scoped inspection)"},
    ) as client:
        for path in paths:
            request_url = urljoin(origin, path)
            if request_url in seen:
                continue
            seen.add(request_url)
            try:
                with client.stream("GET", request_url) as response:
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        remaining = MAX_FILE_BYTES - len(body)
                        if remaining <= 0:
                            break
                        body.extend(chunk[:remaining])
                    text = bytes(body).decode(response.encoding or "utf-8", "replace")[
                        :MAX_TEXT_BYTES
                    ]
                details = {
                    "status_code": response.status_code,
                    "content_type": response.headers.get("content-type"),
                    "headers": {
                        key: _redact_header(key, value[:500])
                        for key, value in response.headers.items()
                        if key.lower()
                        in {"server", "content-type", "set-cookie", "location", "x-powered-by"}
                    },
                    "preview": text[:4000],
                    "redirect_not_followed": bool(response.is_redirect),
                }
                _add_evidence(
                    session,
                    request_url,
                    "http",
                    f"Scoped passive GET returned HTTP {response.status_code}; "
                    "redirects are not followed.",
                    bytes(body),
                    details,
                )
                _find_flags(session, text, request_url, pattern)
            except httpx.HTTPError as exc:
                session.errors.append(
                    {"source": request_url, "message": f"{type(exc).__name__}: {str(exc)[:200]}"}
                )
                if path == paths[0]:
                    break


def _redact_header(name: str, value: str) -> str:
    if name.lower() != "set-cookie":
        return value
    cookie_name = value.split("=", 1)[0].strip()
    return f"{cookie_name}=[REDACTED]" if cookie_name else "[REDACTED]"


def report_path(session: Session, root: Path | None = None) -> Path:
    directory = (root or workspace_root()) / "reports"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{session.session_id}.json"
    temp = path.with_suffix(".tmp")
    temp.write_text(
        json.dumps(session.model_dump(mode="json"), indent=2, ensure_ascii=False), encoding="utf-8"
    )
    os.replace(temp, path)
    session.report_path = str(path)
    return path
