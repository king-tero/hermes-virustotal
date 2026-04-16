"""VirusTotal AI (VTAI) helpers for file and hash scanning.

Covers agent registration, file hash lookup, and opt-in file upload via the
VTAI Core endpoints.
"""

from __future__ import annotations

import json
import logging
import mimetypes
import os
import re
import secrets
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from hermes_constants import get_hermes_home

logger = logging.getLogger(__name__)

VTAI_API_URL = "https://ai.virustotal.com/api/v3"
VT_API_URL = "https://www.virustotal.com/api/v3"
REGISTER_TIMEOUT = 30
HASH_HOT_TIMEOUT = 3
HASH_MANUAL_TIMEOUT = 8
UPLOAD_TIMEOUT = 30
MAX_UPLOAD_BYTES = 32 * 1024 * 1024
HASH_RE = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")

BINARY_MAGICS: tuple[bytes, ...] = (
    b"\x7fELF",
    b"MZ",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\x00asm",
    b"dex\n",
)

ARCHIVE_MAGICS: tuple[bytes, ...] = (
    b"PK\x03\x04",
    b"7z\xbc\xaf\x27\x1c",
    b"Rar!\x1a\x07",
    b"\x1f\x8b\x08",
    b"BZh",
    b"\xfd7zXZ\x00",
)

_SECRET_PATTERNS: tuple[re.Pattern[bytes], ...] = tuple(
    re.compile(p)
    for p in (
        rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |)PRIVATE KEY-----",
        rb"AKIA[0-9A-Z]{16}",
        rb"ASIA[0-9A-Z]{16}",
        rb"ghp_[A-Za-z0-9]{36}",
        rb"gho_[A-Za-z0-9]{36}",
        rb"github_pat_[A-Za-z0-9_]{20,200}",
        rb"xox[pabrsoe]-[A-Za-z0-9-]{10,200}",
        rb"AIza[0-9A-Za-z_-]{35}",
        rb"sk-[A-Za-z0-9]{20,200}",
        rb"eyJ[A-Za-z0-9_-]{10,1024}\.eyJ[A-Za-z0-9_-]{10,1024}\.[A-Za-z0-9_-]{5,1024}",
    )
)


def classify_bytes(content: bytes) -> str:
    """Classify a payload as 'binary', 'archive', or 'text' via magic bytes."""
    head = content[:16]
    for sig in BINARY_MAGICS:
        if head.startswith(sig):
            return "binary"
    for sig in ARCHIVE_MAGICS:
        if head.startswith(sig):
            return "archive"
    return "text"


def contains_secrets(content: bytes) -> bool:
    """Best-effort scan for well-known secret shapes in the first 64 KiB."""
    sample = content[:65536]
    return any(pattern.search(sample) for pattern in _SECRET_PATTERNS)


def _timeout(name: str, default: int, fallback_name: Optional[str] = None) -> float:
    raw = os.getenv(name, "").strip()
    if not raw and fallback_name:
        raw = os.getenv(fallback_name, "").strip()
    if not raw:
        return float(default)
    try:
        value = float(raw)
    except ValueError:
        return float(default)
    return max(1.0, min(value, 120.0))


def _get_vtai_credentials() -> Dict[str, str]:
    """Return configured credentials, preferring the user's standard VT key."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if api_key:
        return {"api_key": api_key, "mode": "standard"}

    agent_token = os.getenv("VTAI_AGENT_TOKEN")
    if agent_token:
        return {"api_key": agent_token, "mode": "vtai"}

    return {}


def _upsert_env(content: str, key: str, value: str) -> str:
    if re.search(rf"^{re.escape(key)}=", content, flags=re.MULTILINE):
        return re.sub(
            rf"^{re.escape(key)}=.*$",
            lambda _m: f"{key}={value}",
            content,
            flags=re.MULTILINE,
        )
    if content and not content.endswith("\n"):
        content += "\n"
    return content + f"{key}={value}\n"


def _write_private_file(path: Path, content: str) -> None:
    """Atomically write a 0o600 file, never exposing it with broader perms."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(tmp_path, flags, 0o600)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(content)
    except Exception:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise
    os.replace(tmp_path, path)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _save_vtai_registration(
    token: str,
    agent_id: Optional[str] = None,
    public_handle: Optional[str] = None,
) -> None:
    """Persist VTAI registration details to the active Hermes profile .env."""
    env_path = get_hermes_home() / ".env"
    try:
        content = env_path.read_text() if env_path.exists() else ""

        content = _upsert_env(content, "VTAI_AGENT_TOKEN", token)
        if agent_id:
            content = _upsert_env(content, "VTAI_AGENT_ID", agent_id)
        if public_handle:
            content = _upsert_env(content, "VTAI_AGENT_HANDLE", public_handle)

        _write_private_file(env_path, content)
        os.environ["VTAI_AGENT_TOKEN"] = token
        if agent_id:
            os.environ["VTAI_AGENT_ID"] = agent_id
        if public_handle:
            os.environ["VTAI_AGENT_HANDLE"] = public_handle
        logger.info("Saved VTAI registration to %s", env_path)
        if public_handle:
            logger.info("VTAI public handle: %s", public_handle)
    except Exception as e:
        logger.warning("Failed to save VTAI registration: %s", e)


def _save_vtai_token(token: str) -> None:
    """Persist only a VTAI agent token, for backwards-compatible callers."""
    _save_vtai_registration(token)


def register_vtai_agent() -> Optional[str]:
    """Register a new agent with VTAI and return its x-apikey token."""
    payload = {
        "agent_family": "hermes-virustotal",
        "agent_version": "0.1.1",
        "display_name": "Hermes VirusTotal",
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{VTAI_API_URL}/agents/register",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_timeout("VTAI_REGISTER_TIMEOUT", REGISTER_TIMEOUT)) as resp:
            result = json.loads(resp.read())
            token = result.get("agent_token")
            if token:
                _save_vtai_registration(
                    token,
                    agent_id=result.get("agent_id"),
                    public_handle=result.get("public_handle"),
                )
                return token
    except Exception as e:
        logger.error("VTAI registration failed: %s", e)
    return None


def _ensure_credentials(auto_register: bool = True) -> Dict[str, str]:
    creds = _get_vtai_credentials()
    if creds:
        return creds

    if not auto_register:
        return {}

    token = register_vtai_agent()
    if not token:
        return {}
    return {"api_key": token, "mode": "vtai"}


def _get_headers(creds: Dict[str, str]) -> Dict[str, str]:
    return {"x-apikey": creds["api_key"]}


def _base_url(creds: Dict[str, str]) -> str:
    return VTAI_API_URL if creds["mode"] == "vtai" else VT_API_URL


def _first_ai_analysis(insights: Any) -> str:
    if not insights:
        return "No AI analysis available yet."

    if isinstance(insights, dict):
        if "analysis" in insights:
            candidates = [insights]
        else:
            candidates = list(insights.values())
    elif isinstance(insights, list):
        candidates = insights
    else:
        return str(insights)

    for item in candidates:
        if isinstance(item, dict):
            analysis = item.get("analysis") or item.get("verdict") or item.get("source")
            if analysis:
                return str(analysis)
        elif item:
            return str(item)

    return "No AI analysis available yet."


def _detection_names(last_analysis_results: Any) -> list[str]:
    if not isinstance(last_analysis_results, dict):
        return []
    names: list[str] = []
    for result in last_analysis_results.values():
        if not isinstance(result, dict):
            continue
        if result.get("category") in {"malicious", "suspicious"} and result.get("result"):
            names.append(str(result["result"]))
    return names


def _normalise_file_report(data: Dict[str, Any], mode: str, requested_hash: str = "") -> Dict[str, Any]:
    file_data = data.get("data") or {}
    file_id = file_data.get("id") or requested_hash

    if mode == "vtai":
        stats = file_data.get("last_analysis_stats") or {}
        insights = file_data.get("ai_insights") or []
        detections = file_data.get("detections") or []
        type_description = file_data.get("type_description")
        threat_verdict = file_data.get("threat_verdict")
    else:
        attrs = file_data.get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        insights = attrs.get("crowdsourced_ai_results") or []
        detections = _detection_names(attrs.get("last_analysis_results"))
        type_description = attrs.get("type_description")
        threat_verdict = attrs.get("threat_verdict")
        file_id = file_id or attrs.get("sha256") or requested_hash

    return {
        "id": file_id,
        "stats": stats,
        "detections": detections,
        "type_description": type_description,
        "threat_verdict": threat_verdict,
        "ai_analysis": _first_ai_analysis(insights),
        "link": f"https://www.virustotal.com/gui/file/{file_id}" if file_id else None,
        "source": mode,
    }


def vt_check_hash(
    hash_str: str,
    auto_register: bool = True,
    timeout_env: str = "VTAI_HASH_MANUAL_TIMEOUT",
    default_timeout: int = HASH_MANUAL_TIMEOUT,
) -> str:
    """Check a file hash in VTAI or VirusTotal."""
    hash_str = (hash_str or "").strip()
    if not HASH_RE.match(hash_str):
        return json.dumps({"error": "hash must be MD5, SHA1, or SHA256 hex"})

    creds = _ensure_credentials(auto_register=auto_register)
    if not creds:
        if auto_register:
            return json.dumps({"error": "VirusTotal credentials not available and VTAI registration failed."})
        return json.dumps({"error": "VirusTotal credentials not configured."})

    url = f"{_base_url(creds)}/files/{hash_str}"
    try:
        req = urllib.request.Request(url, headers=_get_headers(creds))
        with urllib.request.urlopen(
            req,
            timeout=_timeout(timeout_env, default_timeout, fallback_name="VTAI_HASH_TIMEOUT"),
        ) as resp:
            data = json.loads(resp.read())
        return json.dumps(_normalise_file_report(data, creds["mode"], hash_str), ensure_ascii=False)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return json.dumps({"status": "not_found", "message": "Hash not found in VirusTotal database."})
        return json.dumps({"error": f"HTTP Error {e.code}: {e.reason}"})
    except Exception as e:
        return json.dumps({"error": str(e)})


def _multipart_body(fields: Dict[str, str], files: Dict[str, tuple[str, bytes, str]]) -> tuple[bytes, str]:
    boundary = f"----hermes-vtai-{secrets.token_hex(16)}"
    lines: list[bytes] = []

    for name, value in fields.items():
        lines.extend(
            [
                f"--{boundary}".encode(),
                f'Content-Disposition: form-data; name="{name}"'.encode(),
                b"",
                value.encode("utf-8"),
            ]
        )

    for name, (filename, content, content_type) in files.items():
        lines.extend(
            [
                f"--{boundary}".encode(),
                (
                    f'Content-Disposition: form-data; name="{name}"; '
                    f'filename="{filename}"'
                ).encode(),
                f"Content-Type: {content_type}".encode(),
                b"",
                content,
            ]
        )

    lines.extend([f"--{boundary}--".encode(), b""])
    return b"\r\n".join(lines), f"multipart/form-data; boundary={boundary}"


_FILENAME_UNSAFE_RE = re.compile(r'[\r\n\t\x00"\\]')


def _safe_upload_filename(filename: str) -> str:
    """Neutralize chars that could break multipart Content-Disposition quoting."""
    clean = _FILENAME_UNSAFE_RE.sub("_", filename or "")[:120]
    return clean or "artifact.bin"


def vt_upload_bytes(content: bytes, filename: str = "artifact.bin", agent_comments: str = "") -> str:
    """Upload bytes for VTAI/VT file analysis. This is opt-in from the hook."""
    if len(content) > MAX_UPLOAD_BYTES:
        return json.dumps({"error": f"file exceeds {MAX_UPLOAD_BYTES} byte upload limit"})

    creds = _ensure_credentials()
    if not creds:
        return json.dumps({"error": "VirusTotal credentials not available and VTAI registration failed."})

    filename = _safe_upload_filename(filename)
    content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    fields = {"agent_comments": agent_comments} if agent_comments else {}
    body, body_type = _multipart_body(fields, {"file": (filename, content, content_type)})
    headers = {**_get_headers(creds), "Content-Type": body_type}

    try:
        req = urllib.request.Request(
            f"{_base_url(creds)}/files/",
            data=body,
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=_timeout("VTAI_UPLOAD_TIMEOUT", UPLOAD_TIMEOUT)) as resp:
            data = json.loads(resp.read())
        return json.dumps(data, ensure_ascii=False)
    except urllib.error.HTTPError as e:
        return json.dumps({"error": f"HTTP Error {e.code}: {e.reason}"})
    except Exception as e:
        return json.dumps({"error": str(e)})


VT_SCHEMA = {
    "name": "vt_check_hash",
    "description": "Check a file hash (SHA256, SHA1, MD5) in VTAI/VirusTotal as a reputation signal.",
    "parameters": {
        "type": "object",
        "properties": {
            "hash": {"type": "string", "description": "The SHA256, SHA1, or MD5 hash of the file."}
        },
        "required": ["hash"],
    },
}
