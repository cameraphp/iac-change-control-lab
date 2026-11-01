"""Canonical serialization and hashing helpers (NFR-001, REQ-007).

Two encodings are used:

* **Evidence JSON**: sorted keys, two-space indent, UTF-8 (no ASCII escaping), LF line endings and
  a single trailing newline. Human-inspectable and byte-stable.
* **Digest JSON**: sorted keys and compact separators. Used only as hash input for the
  change-set digest.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def evidence_json_bytes(value: Any) -> bytes:
    """Return the canonical, human-readable evidence encoding of ``value``."""
    text = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)
    return (text + "\n").encode("utf-8")


def digest_json_bytes(value: Any) -> bytes:
    """Return the compact canonical encoding of ``value`` used as hash input."""
    text = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    return text.encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def text_bytes(text: str) -> bytes:
    """Encode Markdown/text evidence as UTF-8 with LF line endings and one trailing newline."""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n"
    return normalized.encode("utf-8")
