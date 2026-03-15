# SPDX-License-Identifier: Apache-2.0
"""Redaction hook for evidence blobs.

Pre-write filter that detects and removes secrets before persistence.
Pattern-based: catches common secret formats (API keys, tokens, passwords).

The redactor returns both the cleaned data and a report of what was redacted
(without including the actual secret values).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RedactionHit:
    """A single redaction applied to evidence data."""

    pattern_name: str
    offset: int  # byte offset in original data
    length: int  # length of redacted span
    replacement: str  # what replaced the secret


@dataclass
class RedactionReport:
    """Report of all redactions applied to a blob."""

    hits: list[RedactionHit] = field(default_factory=list)
    original_hash: str = ""  # hash of pre-redaction data
    redacted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "hits": [
                {
                    "pattern_name": h.pattern_name,
                    "offset": h.offset,
                    "length": h.length,
                    "replacement": h.replacement,
                }
                for h in self.hits
            ],
            "original_hash": self.original_hash,
            "redacted": self.redacted,
        }


# =============================================================================
# Secret patterns
# =============================================================================

# Each pattern: (name, compiled_regex, replacement_template)
# These are intentionally conservative — better to over-redact than under-redact.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    # API keys (Anthropic, OpenAI, AWS, etc.)
    ("anthropic_api_key", re.compile(r"sk-ant-[a-zA-Z0-9_-]{20,}"), "[REDACTED:anthropic_key]"),
    ("openai_api_key", re.compile(r"sk-[a-zA-Z0-9]{20,}"), "[REDACTED:openai_key]"),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED:aws_key]"),
    ("aws_secret_key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*\S+"), "[REDACTED:aws_secret]"),

    # Generic patterns
    ("bearer_token", re.compile(r"(?i)bearer\s+[a-zA-Z0-9._\-]{20,}"), "[REDACTED:bearer]"),
    ("authorization_header", re.compile(r"(?i)authorization\s*[=:]\s*\S+"), "[REDACTED:auth_header]"),
    ("password_field", re.compile(r'(?i)"?password"?\s*[=:]\s*"[^"]*"'), "[REDACTED:password]"),
    ("password_field_sq", re.compile(r"(?i)'?password'?\s*[=:]\s*'[^']*'"), "[REDACTED:password]"),
    ("private_key_block", re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----[\s\S]*?-----END\s+(RSA\s+)?PRIVATE KEY-----"), "[REDACTED:private_key]"),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"), "[REDACTED:github_token]"),

    # Connection strings
    ("connection_string", re.compile(r"(?i)(mysql|postgres|mongodb|redis)://[^\s]+@[^\s]+"), "[REDACTED:connection_string]"),

    # Generic high-entropy strings that look like secrets (base64, hex)
    # Only match when preceded by key-like identifiers
    ("generic_secret_assign", re.compile(r'(?i)(secret|token|key|apikey|api_key)\s*[=:]\s*"[^"]{16,}"'), "[REDACTED:generic_secret]"),
    ("generic_secret_assign_sq", re.compile(r"(?i)(secret|token|key|apikey|api_key)\s*[=:]\s*'[^']{16,}'"), "[REDACTED:generic_secret]"),
]


def redact(
    data: bytes,
    content_type: str,
    evidence_class: str,
    original_hash: str = "",
) -> tuple[bytes, RedactionReport]:
    """Apply redaction patterns to evidence data.

    Returns (redacted_data, report).
    If no secrets are found, returns the original data unchanged.
    """
    report = RedactionReport(original_hash=original_hash)

    # Only redact text-like content
    if not _is_text_content(content_type):
        return data, report

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data, report

    hits: list[RedactionHit] = []
    result = text

    for name, pattern, replacement in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            hits.append(RedactionHit(
                pattern_name=name,
                offset=match.start(),
                length=match.end() - match.start(),
                replacement=replacement,
            ))

    if not hits:
        return data, report

    # Apply redactions (process in reverse offset order to preserve positions)
    hits.sort(key=lambda h: h.offset, reverse=True)
    for hit in hits:
        result = result[:hit.offset] + hit.replacement + result[hit.offset + hit.length:]

    # Report hits in forward order
    hits.reverse()
    report.hits = hits
    report.redacted = True
    return result.encode("utf-8"), report


def _is_text_content(content_type: str) -> bool:
    """Check if content type is text-like and should be scanned."""
    text_types = {
        "text/plain",
        "text/html",
        "text/csv",
        "application/json",
        "application/yaml",
        "application/x-yaml",
        "text/yaml",
        "text/x-python",
        "text/x-shellscript",
        "application/xml",
        "text/xml",
    }
    return content_type in text_types or content_type.startswith("text/")
