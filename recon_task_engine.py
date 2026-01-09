"""Evidence-driven Recon AUTO engine (extended).

This engine drives Recon AUTO from a YAML taxonomy, selecting tasks based on
missing evidence keys rather than LLM "checklist imagination".

Enhancements in this version:
- Tool gating: requires_tools (auto-skip if missing in PATH)
- File gating: requires_files (auto-skip if missing)
- Port gating: when_ports_any (only run if any listed port is open)
- foreach support: web.base_urls, web.base_urls_internal, web.base_urls_any
- Output capture: capture_stdout, capture_file, ffuf_json, httpx_json, nuclei_jsonl

Parsers are intentionally "minimal but useful": they extract just enough
structured evidence to prevent empty artifacts while keeping runtime safe.

NOTE: This is designed for lab/CTF environments and read-only recon posture.
"""

from __future__ import annotations

import os
import re
import json
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import yaml


# -------------------------
# Canonical analysis schema
# -------------------------

def _ensure_analysis_skeleton(analysis: Dict[str, Any], ip: str) -> Dict[str, Any]:
    if not isinstance(analysis, dict):
        analysis = {}
    analysis.setdefault("target", {"ip": ip})
    analysis.setdefault("ports", {})        # keyed by "80/tcp"
    analysis.setdefault("web", {})          # base_urls, evidence, fingerprints, ...
    analysis.setdefault("meta", {})         # evidence_keys, task_status, captures/files
    meta = analysis["meta"]
    meta.setdefault("evidence_keys", [])
    meta.setdefault("task_status", {})
    meta.setdefault("captures", {})
    meta.setdefault("files", {})
    return analysis


def _evset(analysis: Dict[str, Any]) -> set[str]:
    meta = analysis.get("meta") or {}
    keys = meta.get("evidence_keys") or []
    if not isinstance(keys, list):
        keys = []
    return set(str(k) for k in keys)


def has_evidence(analysis: Dict[str, Any], key: str) -> bool:
    return str(key) in _evset(analysis)


def add_evidence(analysis: Dict[str, Any], key: str) -> None:
    key = str(key)
    meta = analysis.setdefault("meta", {})
    keys = meta.setdefault("evidence_keys", [])
    if key not in keys:
        keys.append(key)


def add_task_status(analysis: Dict[str, Any], instance_id: str, status: str, detail: str = "") -> None:
    meta = analysis.setdefault("meta", {})
    ts = meta.setdefault("task_status", {})
    ts[str(instance_id)] = {"status": str(status), "detail": str(detail)[:4000]}


# -------------------------
# Helpers
# -------------------------

def _render_placeholders(s: str, ctx: Dict[str, Any]) -> str:
    """Replace {key} placeholders from ctx."""
    if not s:
        return s
    def repl(m: re.Match) -> str:
        k = m.group(1)
        return str(ctx.get(k, m.group(0)))
    return re.sub(r"\{([a-zA-Z0-9_]+)\}", repl, s)


def _safe_token(x: str) -> str:
    x = str(x or "")
    x = re.sub(r"[^a-zA-Z0-9_.-]+", "_", x)
    x = re.sub(r"_+", "_", x).strip("_")
    return x[:80] if x else "item"


def _open_tcp_ports(analysis: Dict[str, Any]) -> List[int]:
    ports = analysis.get("ports") or {}
    out: List[int] = []
    if isinstance(ports, dict):
        for k, info in ports.items():
            try:
                p = int(str(k).split("/")[0])
            except Exception:
                continue
            if not isinstance(info, dict):
                continue
            if str(info.get("accessibility") or "").lower() == "open":
                out.append(p)
    return sorted(set(out))


def _list_base_urls(analysis: Dict[str, Any], which: str) -> List[str]:
    web = analysis.get("web") or {}
    if not isinstance(web, dict):
        return []
    if which == "web.base_urls":
        items = web.get("base_urls") or []
    elif which == "web.base_urls_internal":
        items = web.get("base_urls_internal") or []
    else:  # web.base_urls_any
        items = []
        items.extend(list(web.get("base_urls") or []))
        items.extend(list(web.get("base_urls_internal") or []))
    # de-dup while preserving order
    seen = set()
    out = []
    for u in items:
        u = str(u).strip()
        if not u or u in seen:
            continue
        seen.add(u)
        out.append(u)
    return out


def _tool_exists(tool: str) -> bool:
    try:
        p = shutil.which(tool)
        if p is None:
            return False

        # Special-case: "httpx" is commonly confused between:
        # - ProjectDiscovery's httpx (recon tool) vs.
        # - Python's httpx CLI wrapper (HTTP client) which does NOT support recon flags.
        # In a thesis demo, silently skipping the wrong binary is better than "No such option" noise.
        if tool == "httpx":
            try:
                r = subprocess.run([p, "-h"], capture_output=True, text=True, timeout=2)
                t = (r.stdout or "") + "\n" + (r.stderr or "")
                low = t.lower()
                # Heuristics: recon httpx help contains recon flags we use.
                if ("tech-detect" in low) or ("web-server" in low) or ("follow-redirects" in low):
                    return True
                return False
            except Exception:
                return False

        return True
    except Exception:
        return False


# -------------------------
# Parsers (minimal)
# -------------------------

def _clip(s: str, n: int = 200000) -> str:
    s = s or ""
    if len(s) > n:
        return s[:n] + "\n...<clipped>..."
    return s


def _parse_capture_stdout(analysis: Dict[str, Any], key: str, stdout: str) -> Tuple[bool, str]:
    out = (stdout or "").strip()
    if len(out) < 5:
        return False, "empty"
    meta = analysis.setdefault("meta", {})
    cap = meta.setdefault("captures", {})
    cap[str(key)] = _clip(out, 120000)
    return True, f"captured:{len(out)}"


def _parse_capture_file(analysis: Dict[str, Any], filepath: str) -> Tuple[bool, str]:
    if not filepath or not os.path.exists(filepath):
        return False, "missing_file"
    try:
        data = open(filepath, "r", encoding="utf-8", errors="ignore").read()
    except Exception:
        # try binary to detect non-empty
        try:
            b = open(filepath, "rb").read()
            if not b:
                return False, "empty_file"
            data = b[:200000].decode("utf-8", errors="ignore")
        except Exception:
            return False, "unreadable"
    if len((data or "").strip()) < 5:
        return False, "empty_file"
    meta = analysis.setdefault("meta", {})
    files = meta.setdefault("files", {})
    files[str(filepath)] = _clip(data, 200000)
    return True, f"file_bytes:{len(data)}"


def _parse_ffuf_json(analysis: Dict[str, Any], filepath: str, base_url: str) -> Tuple[bool, str]:
    if not filepath or not os.path.exists(filepath):
        return False, "missing_file"
    try:
        obj = json.load(open(filepath, "r", encoding="utf-8", errors="ignore"))
    except Exception:
        return False, "bad_json"
    results = obj.get("results") or []
    if not isinstance(results, list):
        return False, "no_results"
    web = analysis.setdefault("web", {})
    found = web.setdefault("discovered_paths", [])
    count = 0
    for r in results[:500]:
        if not isinstance(r, dict):
            continue
        u = r.get("url") or ""
        if not u:
            continue
        count += 1
        found.append({
            "url": u,
            "status": r.get("status"),
            "length": r.get("length"),
            "words": r.get("words"),
            "lines": r.get("lines"),
            "source": "ffuf",
            "base": base_url,
        })
    # de-dup by url
    seen = set()
    dedup = []
    for x in found:
        u = str(x.get("url") or "")
        if not u or u in seen:
            continue
        seen.add(u)
        dedup.append(x)
    web["discovered_paths"] = dedup
    return True, f"ffuf_paths={count}"


def _parse_httpx_json(analysis: Dict[str, Any], filepath: str) -> Tuple[bool, str]:
    if not filepath or not os.path.exists(filepath):
        return False, "missing_file"
    lines = open(filepath, "r", encoding="utf-8", errors="ignore").read().splitlines()
    if not lines:
        return False, "empty_file"
    web = analysis.setdefault("web", {})
    fps = web.setdefault("fingerprints", [])
    cnt = 0
    for ln in lines[:1000]:
        ln = ln.strip()
        if not ln:
            continue
        try:
            j = json.loads(ln)
        except Exception:
            continue
        u = j.get("url") or j.get("input") or ""
        if not u:
            continue
        cnt += 1
        fps.append({
            "url": u,
            "status_code": j.get("status_code"),
            "title": j.get("title"),
            "webserver": j.get("webserver"),
            "tech": j.get("tech"),
            "content_type": j.get("content_type"),
            "source": "httpx",
        })
    # de-dup by url
    seen = set()
    dedup = []
    for x in fps:
        u = str(x.get("url") or "")
        if not u or u in seen:
            continue
        seen.add(u)
        dedup.append(x)
    web["fingerprints"] = dedup
    return True, f"httpx_entries={cnt}"


def _parse_nuclei_jsonl(analysis: Dict[str, Any], filepath: str, base_url: str) -> Tuple[bool, str]:
    if not filepath or not os.path.exists(filepath):
        return False, "missing_file"
    lines = open(filepath, "r", encoding="utf-8", errors="ignore").read().splitlines()
    if not lines:
        return False, "empty_file"
    web = analysis.setdefault("web", {})
    sig = web.setdefault("vuln_signals", [])
    cnt = 0
    for ln in lines[:2000]:
        ln = ln.strip()
        if not ln:
            continue
        try:
            j = json.loads(ln)
        except Exception:
            continue
        cnt += 1
        info = j.get("info") or {}
        sig.append({
            "template": j.get("template"),
            "name": info.get("name") if isinstance(info, dict) else None,
            "severity": info.get("severity") if isinstance(info, dict) else None,
            "matched_at": j.get("matched-at") or j.get("matched_at"),
            "type": j.get("type"),
            "host": j.get("host"),
            "base": base_url,
            "source": "nuclei",
        })
    return True, f"nuclei_hits={cnt}"


def _parse_nmap_gnmap_ports(analysis: Dict[str, Any], gnmap_path: str) -> Tuple[bool, str]:
    if not os.path.exists(gnmap_path):
        return False, "missing_gnmap"
    data = open(gnmap_path, "r", encoding="utf-8", errors="ignore").read()
    m = re.findall(r"(\d+)/open/tcp", data)
    if not m:
        return False, "no_open_ports_parsed"
    ports = analysis.setdefault("ports", {})
    for p in sorted(set(m)):
        ports.setdefault(f"{p}/tcp", {"accessibility": "open", "service": "", "product": "", "version": ""})
    add_evidence(analysis, "net.tcp_ports")
    return True, f"tcp_ports={len(set(m))}"


def _parse_nmap_xml_services(analysis: Dict[str, Any], xml_path: str, ip: str) -> Tuple[bool, str]:
    if not os.path.exists(xml_path):
        return False, "missing_xml"
    data = open(xml_path, "r", encoding="utf-8", errors="ignore").read()
    # Optional: if the operator also wrote an -oN file alongside -oX,
    # use it as a fallback for HTTP fingerprints that may not appear in XML.
    txt_path = os.path.join(os.path.dirname(xml_path), "nmap_tcp_svc.txt")
    txt_data = ""
    try:
        if os.path.exists(txt_path):
            txt_data = open(txt_path, "r", encoding="utf-8", errors="ignore").read()
    except Exception:
        txt_data = ""
    # very lightweight XML scraping (avoid xml libs)
    ports = analysis.setdefault("ports", {})
    count = 0
    base_urls: List[str] = []
    for pm in re.finditer(r"<port protocol=\"tcp\" portid=\"(\d+)\">(.+?)</port>", data, re.S):
        portid = pm.group(1)
        block = pm.group(2)
        if "state state=\"open\"" not in block:
            continue
        svc = ""
        prod = ""
        ver = ""
        msvc = re.search(r"<service[^>]*name=\"([^\"]+)\"", block)
        if msvc:
            svc = msvc.group(1)
        mprod = re.search(r"product=\"([^\"]+)\"", block)
        if mprod:
            prod = mprod.group(1)
        mver = re.search(r"version=\"([^\"]+)\"", block)
        if mver:
            ver = mver.group(1)
        key = f"{portid}/tcp"
        ports[key] = {"accessibility": "open", "service": svc, "product": prod, "version": ver}
        count += 1
        # heuristic base_url
        svc_l = (svc or "").lower()
        # primary: service name suggests HTTP(S)
        is_http = (svc_l in {"http", "http-alt", "https"} or "http" in svc_l)
        # secondary: Nmap sometimes labels custom HTTP services as "unknown" but embeds HTTP fingerprints in XML.
        # Look for typical HTTP response tokens in the <port> block.
        if not is_http:
            if re.search(r"HTTP/\d\.\d", block) or "content-type" in block.lower() or "location:" in block.lower():
                is_http = True
        # Tertiary: sometimes only the normal output contains the HTTP fingerprint string.
        if not is_http and txt_data:
            if (f"SF-Port{portid}" in txt_data and re.search(r"HTTP/\d\.\d", txt_data)):
                is_http = True
        if is_http:
            scheme = "https" if (svc_l == "https" or portid == "443") else "http"
            base_urls.append(f"{scheme}://{ip}:{portid}".rstrip(":80").rstrip(":443"))
    if count <= 0:
        return False, "no_open_services_parsed"
    add_evidence(analysis, "net.services")
    if base_urls:
        web = analysis.setdefault("web", {})
        web.setdefault("base_urls", [])
        for u in base_urls:
            if u not in web["base_urls"]:
                web["base_urls"].append(u)
        add_evidence(analysis, "web.base_urls")
    return True, f"services={count} base_urls={len(base_urls)}"


def _parse_curl_headers(analysis: Dict[str, Any], url: str, stdout: str) -> Tuple[bool, str]:
    s = (stdout or "").strip()
    if "HTTP/" not in s:
        return False, "no_http"
    web = analysis.setdefault("web", {})
    ev = web.setdefault("evidence", [])
    hdrs = []
    for ln in s.splitlines():
        if ln.lower().startswith("http/") or ":" in ln:
            hdrs.append(ln.strip())
    ev.append({"url": url, "type": "headers", "data": hdrs[:200], "source": "curl"})
    return True, "ok"


def _parse_curl_html_root(analysis: Dict[str, Any], url: str, stdout: str) -> Tuple[bool, str]:
    s = (stdout or "").strip()
    if len(s) < 10:
        return False, "empty"
    title = ""
    mt = re.search(r"<title>(.*?)</title>", s, re.I | re.S)
    if mt:
        title = re.sub(r"\s+", " ", mt.group(1)).strip()[:200]
    web = analysis.setdefault("web", {})
    ev = web.setdefault("evidence", [])
    ev.append({"url": url, "type": "html_root", "title": title, "len": len(s), "source": "curl"})
    return True, f"title={title}" if title else "ok"


def _parse_robots_like(analysis: Dict[str, Any], url: str, stdout: str, kind: str) -> Tuple[bool, str]:
    s = (stdout or "").strip()
    if len(s) < 5:
        return False, "not_found"
    web = analysis.setdefault("web", {})
    ev = web.setdefault("evidence", [])
    lines = [ln.strip() for ln in s.splitlines() if ln.strip()][:300]
    ev.append({"url": url, "type": kind, "lines": lines, "source": "curl"})
    return True, f"{kind}_lines={len(lines)}"


def _parse_git_head(analysis: Dict[str, Any], url: str, stdout: str) -> Tuple[bool, str]:
    s = (stdout or "").strip()
    if not s:
        return False, "empty"
    if "refs/" not in s and "ref:" not in s:
        return False, "not_git_head"
    web = analysis.setdefault("web", {})
    ipaths = web.setdefault("interesting_paths", [])
    ipaths.append({"url": url + "/.git/HEAD", "signal": "exposed_git", "evidence": s[:200]})
    return True, "git_head"


PARSER_MAP = {
    "nmap_gnmap_ports": _parse_nmap_gnmap_ports,
    "nmap_xml_services": _parse_nmap_xml_services,
    "curl_headers": _parse_curl_headers,
    "curl_html_root": _parse_curl_html_root,
    "curl_robots": lambda a, u, s: _parse_robots_like(a, u, s, "robots"),
    "curl_sitemap": lambda a, u, s: _parse_robots_like(a, u, s, "sitemap"),
    "curl_git_head": _parse_git_head,
    "capture_stdout": _parse_capture_stdout,
    "capture_file": _parse_capture_file,
    "ffuf_json": _parse_ffuf_json,
    "httpx_json": _parse_httpx_json,
    "nuclei_jsonl": _parse_nuclei_jsonl,
}


# -------------------------
# Task model + engine
# -------------------------

@dataclass
class TaskInstance:
    task_id: str
    instance_id: str
    title: str
    category: str
    command: str
    parser: str
    produces: List[str]
    requires: List[str]
    optional: bool
    item: Optional[str] = None
    requires_tools: List[str] = None
    requires_files: List[str] = None
    when_ports_any: List[int] = None
    output_file: Optional[str] = None
    capture_key: Optional[str] = None


class ReconTaskEngine:
    def __init__(self, yaml_path: str):
        self.yaml_path = yaml_path
        raw = yaml.safe_load(open(yaml_path, "r", encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(f"Invalid tasks YAML: {yaml_path}")
        self.defaults = raw.get("defaults") or {}
        self.tasks = raw.get("tasks") or []
        if not isinstance(self.tasks, list):
            raise ValueError("tasks must be a list")

    def output_dir(self, project_root: str, topic: str) -> str:
        root = str(self.defaults.get("output_root") or "recon_out")
        out = os.path.join(project_root, root, topic)
        os.makedirs(out, exist_ok=True)
        return out

    def _ctx(self, *, ip: str, out: str, analysis: Dict[str, Any], item: Optional[str] = None) -> Dict[str, Any]:
        tcp_ports = _open_tcp_ports(analysis)
        tcp_ports_csv = ",".join(str(p) for p in tcp_ports) if tcp_ports else ""
        url = str(item or "")
        u = urlparse(url) if url else None
        host = (u.hostname if u else "") or ""
        scheme = (u.scheme if u else "") or ""
        port = (u.port if u else None)
        if port is None and scheme == "https":
            port = 443
        if port is None and scheme == "http":
            port = 80
        safe_item = _safe_token(f"{host}_{port}" if host else (url or "item"))

        # defaults
        user_agent = str(self.defaults.get("user_agent") or "Mozilla/5.0 (PentestAgent-Recon)")
        curl_max_time_sec = int(self.defaults.get("curl_max_time_sec") or 12)
        curl_insecure = str(self.defaults.get("curl_insecure") or "-k")
        wl_dir_common = str(self.defaults.get("wl_dir_common") or "/usr/share/wordlists/dirb/common.txt")
        wl_subdomains = str(self.defaults.get("wl_subdomains") or "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt")
        wl_vhosts = str(self.defaults.get("wl_vhosts") or wl_subdomains)

        return {
            "ip": ip,
            "out": out,
            "topic": str((analysis.get("meta") or {}).get("topic", "")) or "",
            "tcp_ports_csv": tcp_ports_csv,
            "item": url,
            "safe_item": safe_item,
            "host": host,
            "scheme": scheme,
            "port": str(port or ""),
            "user_agent": user_agent,
            "curl_max_time_sec": str(curl_max_time_sec),
            "curl_insecure": curl_insecure,
            "wl_dir_common": wl_dir_common,
            "wl_subdomains": wl_subdomains,
            "wl_vhosts": wl_vhosts,
        }

    def _requirements_satisfied(self, analysis: Dict[str, Any], requires: List[str]) -> bool:
        for r in (requires or []):
            if not has_evidence(analysis, r):
                return False
        return True

    def _already_produced(self, analysis: Dict[str, Any], produces: List[str]) -> bool:
        # if ALL produces are already present, treat as already produced
        if not produces:
            return False
        for p in produces:
            if not has_evidence(analysis, p):
                return False
        return True

    def _tools_satisfied(self, tools: List[str]) -> bool:
        if not tools:
            return True
        for t in tools:
            if not _tool_exists(str(t)):
                return False
        return True

    def _files_satisfied(self, files: List[str], ctx: Dict[str, Any]) -> bool:
        if not files:
            return True
        for f in files:
            fp = _render_placeholders(str(f), ctx)
            if not os.path.isabs(fp):
                # allow relative paths, but resolve from FS root
                fp = fp
            if not os.path.exists(fp):
                return False
        return True

    def _ports_satisfied(self, analysis: Dict[str, Any], ports_any: List[int]) -> bool:
        if not ports_any:
            return True
        openp = set(_open_tcp_ports(analysis))
        for p in ports_any:
            try:
                if int(p) in openp:
                    return True
            except Exception:
                continue
        return False

    def _expand_task(self, task: Dict[str, Any], analysis: Dict[str, Any]) -> List[TaskInstance]:
        task_id = str(task.get("id") or "")
        if not task_id:
            return []
        title = str(task.get("title") or task_id)
        category = str(task.get("category") or "")
        cmd = str(task.get("command") or "")
        parser = str(task.get("parser") or "")
        produces = task.get("produces") or []
        requires = task.get("requires") or []
        optional = bool(task.get("optional", False))
        foreach = task.get("foreach")
        requires_tools = list(task.get("requires_tools") or [])
        requires_files = list(task.get("requires_files") or [])
        when_ports_any = list(task.get("when_ports_any") or [])
        output_file = task.get("output_file")
        capture_key = task.get("capture_key")

        def make_inst(it: Optional[str]) -> TaskInstance:
            inst_id = f"{task_id}@{it}" if it else task_id
            return TaskInstance(
                task_id=task_id,
                instance_id=inst_id,
                title=title,
                category=category,
                command=cmd,
                parser=parser,
                produces=[str(p).replace("{item}", str(it)) for p in produces],
                requires=[str(r) for r in requires],
                optional=optional,
                item=str(it) if it else None,
                requires_tools=[str(x) for x in requires_tools],
                requires_files=[str(x) for x in requires_files],
                when_ports_any=[int(x) for x in when_ports_any if str(x).isdigit()],
                output_file=str(output_file) if output_file else None,
                capture_key=str(capture_key) if capture_key else None,
            )

        if foreach:
            which = str(foreach).strip()
            if which not in {"web.base_urls", "web.base_urls_internal", "web.base_urls_any"}:
                return []
            items = _list_base_urls(analysis, which)
            return [make_inst(it) for it in items]
        return [make_inst(None)]

    def pick_next(self, analysis: Dict[str, Any]) -> Optional[TaskInstance]:
        cands = self.list_candidates(analysis, limit=1)
        return cands[0] if cands else None

    def expand_all(self, analysis: Dict[str, Any]) -> List[TaskInstance]:
        """Expand *all* task instances from the YAML taxonomy.

        Unlike `list_candidates`, this does not filter on requirements/evidence/task_status.
        It is intended for operator-driven/manual execution where we want to map an
        arbitrary command back to a known task instance (so it can be marked completed).
        """
        out: List[TaskInstance] = []
        for t in self.tasks:
            if not isinstance(t, dict):
                continue
            out.extend(self._expand_task(t, analysis))
        return out

    def find_instance_by_command(
        self,
        analysis: Dict[str, Any],
        cmd: str,
        *,
        ip: str,
        out_dir: str,
    ) -> Optional[TaskInstance]:
        """Best-effort mapping: operator CMD -> YAML task instance.

        Matching strategy is intentionally conservative:
          - render each instance command with current ctx
          - normalize whitespace
          - additionally normalize the output directory to the token '{out}' on both sides
          - require exact match after normalization

        This enables 'CMD:' to be treated the same as 'AUTO' when the operator copies
        a task command from the playbook.
        """
        if not cmd:
            return None

        def _norm(s: str) -> str:
            s = (s or "").strip()
            s = re.sub(r"\s+", " ", s)
            if out_dir:
                s = s.replace(out_dir, "{out}")
            return s

        needle = _norm(cmd)
        for inst in self.expand_all(analysis):
            try:
                rendered = self.render_command(inst, ip=ip, out=out_dir, analysis=analysis)
            except Exception:
                continue
            if _norm(rendered) == needle:
                return inst
        return None

    def list_candidates(self, analysis: Dict[str, Any], *, limit: int = 12) -> List[TaskInstance]:
        """List up to `limit` runnable task instances in YAML order.

        This enables an LLM-based selector to choose the *best* next task without
        hardcoding ordering logic into the YAML.
        """
        out: List[TaskInstance] = []
        limit = max(1, int(limit or 12))

        for t in self.tasks:
            if not isinstance(t, dict):
                continue
            for inst in self._expand_task(t, analysis):
                ctx = self._ctx(ip=str((analysis.get("target") or {}).get("ip") or ""), out="", analysis=analysis, item=inst.item)
                if not self._ports_satisfied(analysis, inst.when_ports_any):
                    continue
                if not self._tools_satisfied(inst.requires_tools):
                    # mark skipped once to avoid re-evaluating
                    add_task_status(analysis, inst.instance_id, "skipped", "missing_tool")
                    continue
                if not self._files_satisfied(inst.requires_files, ctx):
                    add_task_status(analysis, inst.instance_id, "skipped", "missing_file")
                    continue
                if not self._requirements_satisfied(analysis, inst.requires):
                    continue
                if self._already_produced(analysis, inst.produces):
                    continue
                ts = (analysis.get("meta") or {}).get("task_status") or {}
                st = (ts.get(inst.instance_id) or {}).get("status")
                if st in {"skipped", "failed"}:
                    continue
                out.append(inst)
                if len(out) >= limit:
                    return out
        return out

    def render_command(self, inst: TaskInstance, *, ip: str, out: str, analysis: Dict[str, Any]) -> str:
        ctx = self._ctx(ip=ip, out=out, analysis=analysis, item=inst.item)
        return _render_placeholders(inst.command, ctx)

    def _render_output_file(self, inst: TaskInstance, *, ip: str, out: str, analysis: Dict[str, Any]) -> Optional[str]:
        if not inst.output_file:
            return None
        ctx = self._ctx(ip=ip, out=out, analysis=analysis, item=inst.item)
        p = _render_placeholders(inst.output_file, ctx)
        if not os.path.isabs(p):
            p = os.path.join(out, p)
        return p

    def parse_and_update(
        self,
        inst: TaskInstance,
        *,
        analysis: Dict[str, Any],
        ip: str,
        out_dir: str,
        stdout: str,
    ) -> Tuple[bool, str]:
        parser = inst.parser
        fn = PARSER_MAP.get(parser)
        if fn is None:
            return False, f"unknown_parser:{parser}"

        ok = False
        detail = ""

        # File-based parsers
        if parser in {"nmap_gnmap_ports"}:
            ok, detail = fn(analysis, os.path.join(out_dir, "nmap_tcp_all.gnmap"))
        elif parser in {"nmap_xml_services"}:
            ok, detail = fn(analysis, os.path.join(out_dir, "nmap_tcp_svc.xml"), ip)
        elif parser in {"capture_file"}:
            fp = self._render_output_file(inst, ip=ip, out=out_dir, analysis=analysis)
            ok, detail = fn(analysis, fp or "")
        elif parser in {"ffuf_json"}:
            fp = self._render_output_file(inst, ip=ip, out=out_dir, analysis=analysis)
            ok, detail = fn(analysis, fp or "", inst.item or "")
        elif parser in {"httpx_json"}:
            fp = self._render_output_file(inst, ip=ip, out=out_dir, analysis=analysis)
            ok, detail = fn(analysis, fp or "")
        elif parser in {"nuclei_jsonl"}:
            fp = self._render_output_file(inst, ip=ip, out=out_dir, analysis=analysis)
            ok, detail = fn(analysis, fp or "", inst.item or "")
        elif parser in {"capture_stdout"}:
            key = inst.capture_key or inst.instance_id or (inst.item or inst.task_id)
            ok, detail = fn(analysis, key, stdout)
        else:
            # stdout-based parsers that are URL-aware
            ok, detail = fn(analysis, inst.item or "", stdout)

        if ok:
            for k in (inst.produces or []):
                add_evidence(analysis, k)
            add_task_status(analysis, inst.instance_id, "done", detail)
        else:
            if inst.optional and detail in {"not_found", "empty", "not_git_head", "missing_file", "empty_file", "no_results"}:
                add_task_status(analysis, inst.instance_id, "skipped", detail)
            else:
                add_task_status(analysis, inst.instance_id, "failed", detail)
        return ok, detail


def load_engine(project_root: str, yaml_rel_path: str) -> ReconTaskEngine:
    path = yaml_rel_path
    if not os.path.isabs(path):
        path = os.path.join(project_root, path)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Recon tasks YAML not found: {path}")
    return ReconTaskEngine(path)

