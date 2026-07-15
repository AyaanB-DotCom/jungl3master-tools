#!/usr/bin/env python3
"""
HAR → Markdown converter with automatic sensitive-data sanitization.

Usage:
    python3 har_to_md.py capture.har
    python3 har_to_md.py capture.har output.md
"""

import json
import re
import sys
from pathlib import Path

# ─── Configuration ────────────────────────────────────────────────────────────

KEEP_CHARS = 6                  # chars to show before "xxx"
BODY_TRUNCATE_CHARS = 4000      # max response body chars in output

# Header names whose values are always masked
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-access-token",
    "x-session-token",
    "x-csrf-token",
    "x-amz-security-token",
    "x-amz-content-sha256",
    "proxy-authorization",
}

# Query/form/JSON field names whose values are always masked
SENSITIVE_PARAM_NAMES = {
    "password", "passwd", "pass", "secret", "token", "access_token",
    "refresh_token", "id_token", "api_key", "apikey", "client_secret",
    "auth", "authorization", "session", "session_id", "sessionid",
    "ssn", "social_security", "credit_card", "card_number", "cvv", "cvc",
    "private_key", "private_secret", "signing_key", "encryption_key",
}

# Substrings that flag a JSON/form key as sensitive
SENSITIVE_KEY_SUBSTRINGS = (
    "token", "secret", "password", "passwd", "apikey", "api_key",
    "auth", "credential", "private", "signing", "encrypt",
)

# Inline regex patterns applied to free-text bodies as a last resort.
# Each tuple: (compiled_regex, chars_to_keep)
INLINE_PATTERNS = [
    # JWT tokens  eyJxxx.eyJxxx.xxx
    (re.compile(r'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'), 4),
    # AWS Access Key IDs
    (re.compile(r'\b(AKIA|ASIA|AROA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b'), 4),
    # AWS secret-key keyword followed by 40-char value
    (re.compile(r'(?i)(aws_secret_access_key|secret_access_key)(\s*[=:]\s*)[A-Za-z0-9/+=]{40}'), 0),
    # Generic long hex strings (32+ chars) — tokens, hashes, session IDs
    (re.compile(r'\b[0-9a-fA-F]{32,}\b'), 6),
    # Generic long base64-like strings (48+ chars) — avoids short base64 noise
    (re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{48,}(?![A-Za-z0-9/+=])'), 6),
]


# ─── Masking helpers ──────────────────────────────────────────────────────────

def mask(value: str, keep: int = KEEP_CHARS) -> str:
    """Show first `keep` chars of value followed by 'xxx'."""
    if not value:
        return value
    return value[:keep] + "xxx"


def mask_inline(text: str, keep: int = KEEP_CHARS) -> str:
    """Apply regex-based masking to a free-form text block."""
    if not text:
        return text
    for pattern, pattern_keep in INLINE_PATTERNS:
        # For patterns with groups (AWS keyword+value), only replace the value part
        if pattern.groups:
            def _replace_grouped(m, pk=pattern_keep):
                # reconstruct: keep everything except last group, mask that
                full = m.group(0)
                last = m.lastindex
                if last:
                    val = m.group(last)
                    return full[:m.start(last) - m.start()] + mask(val, pk)
                return mask(full, pk)
            text = pattern.sub(_replace_grouped, text)
        else:
            text = pattern.sub(lambda m, pk=pattern_keep: mask(m.group(0), pk), text)
    return text


# ─── Header sanitization ──────────────────────────────────────────────────────

def sanitize_header_value(name: str, value: str, keep: int) -> str:
    lower = name.lower()
    if lower not in SENSITIVE_HEADERS:
        return value

    if lower == "authorization":
        # Keep the scheme (Bearer / Basic / Digest …) for context
        parts = value.split(" ", 1)
        if len(parts) == 2:
            scheme, cred = parts
            return f"{scheme} {mask(cred, 4)}"
        return mask(value, 4)

    if lower in ("cookie", "set-cookie"):
        return _mask_cookie_string(value, keep)

    return mask(value, 4)


def _mask_cookie_string(cookie_str: str, keep: int) -> str:
    """Mask cookie values while preserving cookie names and attributes."""
    result_parts = []
    # Split on "; " — the first segment is name=value, rest are attributes
    segments = cookie_str.split("; ")
    for i, segment in enumerate(segments):
        if "=" in segment:
            k, v = segment.split("=", 1)
            # Cookie attributes like Path, Domain, Expires are not secret
            if i == 0 or k.strip().lower() not in (
                "path", "domain", "expires", "max-age", "samesite", "httponly", "secure"
            ):
                result_parts.append(f"{k}={mask(v, 4)}")
            else:
                result_parts.append(segment)
        else:
            result_parts.append(segment)
    return "; ".join(result_parts)


def sanitize_headers(headers: list, keep: int) -> list:
    return [
        {"name": h["name"], "value": sanitize_header_value(h["name"], h.get("value", ""), keep)}
        for h in headers
    ]


# ─── Parameter sanitization ───────────────────────────────────────────────────

def _is_sensitive_key(name: str) -> bool:
    lower = name.lower()
    if lower in SENSITIVE_PARAM_NAMES:
        return True
    return any(sub in lower for sub in SENSITIVE_KEY_SUBSTRINGS)


def sanitize_param(name: str, value: str, keep: int) -> str:
    return mask(value, 4) if _is_sensitive_key(name) else value


def sanitize_params(params: list, keep: int) -> list:
    return [
        {"name": p["name"], "value": sanitize_param(p["name"], p.get("value", ""), keep)}
        for p in params
    ]


# ─── Body sanitization ────────────────────────────────────────────────────────

def sanitize_body(mime_type: str, text: str, keep: int) -> str:
    if not text:
        return text

    if "json" in mime_type:
        try:
            data = json.loads(text)
            sanitized = _sanitize_json(data, keep)
            return json.dumps(sanitized, indent=2, ensure_ascii=False)
        except (json.JSONDecodeError, ValueError):
            pass  # fall through to inline masking

    if "form" in mime_type or "x-www-form-urlencoded" in mime_type:
        parts = []
        for pair in text.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                parts.append(f"{k}={sanitize_param(k, v, keep)}")
            else:
                parts.append(pair)
        return "&".join(parts)

    # Fallback: apply inline pattern masking
    return mask_inline(text, keep)


def _sanitize_json(obj, keep: int):
    if isinstance(obj, dict):
        return {
            k: (mask(str(v), 4) if _is_sensitive_key(k) and isinstance(v, str)
                else ("xxx" if _is_sensitive_key(k)
                      else _sanitize_json(v, keep)))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_sanitize_json(item, keep) for item in obj]
    if isinstance(obj, str):
        return mask_inline(obj, keep)
    return obj


# ─── Markdown formatting ──────────────────────────────────────────────────────

def _mime_to_fence(mime: str) -> str:
    if "json" in mime:
        return "json"
    if "html" in mime:
        return "html"
    if "xml" in mime:
        return "xml"
    if "javascript" in mime:
        return "js"
    if "css" in mime:
        return "css"
    return ""


def _format_url(url: str, max_len: int = 120) -> str:
    return url if len(url) <= max_len else url[:max_len - 3] + "..."


def entry_to_md(entry: dict, index: int, keep: int, truncate: bool) -> str:
    req = entry.get("request", {})
    resp = entry.get("response", {})
    timings = entry.get("timings", {})

    method = req.get("method", "?")
    url = req.get("url", "")
    status = resp.get("status", "?")
    status_text = resp.get("statusText", "")

    total_ms = sum(v for v in timings.values() if isinstance(v, (int, float)) and v >= 0)

    lines = [
        f"## [{index}] {method} {_format_url(url)}",
        "",
        f"**Status:** `{status} {status_text}`" + (f"   **Time:** {total_ms:.0f}ms" if total_ms else ""),
        "",
    ]

    # ── Request headers
    req_headers = sanitize_headers(req.get("headers", []), keep)
    if req_headers:
        lines += ["### Request Headers", "```"]
        lines += [f"{h['name']}: {h['value']}" for h in req_headers]
        lines += ["```", ""]

    # ── Query string
    qs = sanitize_params(req.get("queryString", []), keep)
    if qs:
        lines += ["### Query Parameters", "```"]
        lines += [f"{p['name']} = {p['value']}" for p in qs]
        lines += ["```", ""]

    # ── Request body
    post_data = req.get("postData") or {}
    post_text = post_data.get("text", "")
    post_mime = post_data.get("mimeType", "")
    if post_text:
        sanitized_body = sanitize_body(post_mime, post_text, keep)
        fence = _mime_to_fence(post_mime)
        lines += [f"### Request Body", f"```{fence}", sanitized_body, "```", ""]

    # ── Response headers
    resp_headers = sanitize_headers(resp.get("headers", []), keep)
    if resp_headers:
        lines += ["### Response Headers", "```"]
        lines += [f"{h['name']}: {h['value']}" for h in resp_headers]
        lines += ["```", ""]

    # ── Response body
    content = resp.get("content") or {}
    resp_mime = content.get("mimeType", "")
    resp_text = content.get("text", "")
    if resp_text:
        sanitized_resp = sanitize_body(resp_mime, resp_text, keep)
        fence = _mime_to_fence(resp_mime)
        lines.append("### Response Body")
        lines.append(f"```{fence}")
        if truncate and len(sanitized_resp) > BODY_TRUNCATE_CHARS:
            lines.append(sanitized_resp[:BODY_TRUNCATE_CHARS])
            lines.append(f"\n... [truncated — {len(sanitized_resp) - BODY_TRUNCATE_CHARS} more chars]")
        else:
            lines.append(sanitized_resp)
        lines += ["```", ""]

    return "\n".join(lines)


def har_to_md(har: dict, keep: int, truncate: bool) -> str:
    log = har.get("log", {})
    creator = log.get("creator") or {}
    browser = log.get("browser") or {}
    pages = log.get("pages") or []
    entries = log.get("entries") or []

    lines = [
        "# HAR Export — Sanitized",
        "",
        "> **Sanitization notice:** Sensitive values are partially masked as `PREFIXxxx`.",
        "> The prefix shows the value type/start for context. Nothing has been deleted.",
        "",
    ]

    meta_parts = []
    if creator.get("name"):
        meta_parts.append(f"**Creator:** {creator['name']} {creator.get('version', '')}")
    if browser.get("name"):
        meta_parts.append(f"**Browser:** {browser['name']} {browser.get('version', '')}")
    meta_parts.append(f"**Entries:** {len(entries)}")
    lines += meta_parts + [""]

    if pages:
        lines.append("## Pages")
        for page in pages:
            lines.append(f"- **{page.get('id', '?')}** — {page.get('title', 'Untitled')}")
        lines.append("")

    lines.append("---")
    lines.append("")

    for i, entry in enumerate(entries, 1):
        lines.append(entry_to_md(entry, i, keep, truncate))
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 har_to_md.py <file.har> [output.md]", file=sys.stderr)
        sys.exit(1)

    input_path = Path(sys.argv[1])
    if not input_path.exists():
        print(f"Error: {input_path} not found", file=sys.stderr)
        sys.exit(1)

    output_path = Path(sys.argv[2]) if len(sys.argv) >= 3 else input_path.with_suffix(".md")

    print(f"Reading  {input_path}")
    with open(input_path, encoding="utf-8") as f:
        har = json.load(f)

    entry_count = len(har.get("log", {}).get("entries", []))
    print(f"Entries  {entry_count}")
    print("Sanitizing…")

    md = har_to_md(har, keep=KEEP_CHARS, truncate=True)

    output_path.write_text(md, encoding="utf-8")
    print(f"Written  {output_path}  ({len(md):,} chars)")


if __name__ == "__main__":
    main()
