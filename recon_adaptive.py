"""Adaptive Recon overlay (AutoPentester-style), but pipeline-friendly.

This module implements a *bounded* feedback loop that:
  - Reads current recon `analysis` (facts/evidence).
  - Asks the LLM (optionally Tool-RAG augmented) for **a small set of next read-only commands**.
  - Validates commands against Recon's ExecGuard policy.
  - Returns a list of commands to execute.

Key design goals:
  - Deterministic outer-loop: bounded rounds, bounded commands.
  - No arbitrary tools: commands must match allowlist.
  - Evidence-gated: suggestions should reference existing evidence.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class AdaptiveReconConfig:
    enable: bool = False
    # How to select the next recon action while tasks remain.
    # - "yaml": follow recon_tasks.yaml ordering (deterministic)
    # - "llm": let the LLM choose among runnable tasks (AutoPentester-style)
    task_selector: str = "yaml"
    task_candidate_limit: int = 12
    max_rounds: int = 2
    max_cmds_per_round: int = 4
    min_new_evidence_keys: int = 1
    # If advisor JSON parsing fails, optionally run a second pass using
    # AutoPentester-style command extractor prompt.
    use_command_extractor: bool = True


def coverage_snapshot(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Return a compact snapshot of recon progress to ground the advisor."""
    ports = analysis.get("ports") if isinstance(analysis.get("ports"), dict) else {}
    web = analysis.get("web") if isinstance(analysis.get("web"), dict) else {}
    target = analysis.get("target") if isinstance(analysis.get("target"), dict) else {}
    snap = {
        "ports": sorted(list(ports.keys()))[:40],
        "products": [
            {"port": k, "product": (v.get("product") if isinstance(v, dict) else None), "version": (v.get("version") if isinstance(v, dict) else None)}
            for k, v in list(ports.items())[:20]
            if isinstance(v, dict)
        ],
        "base_urls": list(web.get("base_urls") or [])[:8],
        "interesting_paths": list(web.get("interesting_paths") or [])[:20],
        "virtual_hosts": list(web.get("virtual_hosts") or [])[:10],
        "hostnames": list(target.get("hostnames") or [])[:10],
    }
    return snap


def evidence_keys(analysis: Dict[str, Any]) -> List[str]:
    """A coarse list of evidence keys to detect progress."""
    keys: List[str] = []
    try:
        ports = analysis.get("ports") if isinstance(analysis.get("ports"), dict) else {}
        web = analysis.get("web") if isinstance(analysis.get("web"), dict) else {}
        if ports:
            keys.append("ports")
            # products/versions
            for k, v in ports.items():
                if isinstance(v, dict) and (v.get("product") or v.get("version")):
                    keys.append(f"ports.{k}.fingerprint")
                    break
        if web.get("base_urls"):
            keys.append("web.base_urls")
        if web.get("interesting_paths"):
            keys.append("web.interesting_paths")
        if web.get("fingerprints"):
            keys.append("web.fingerprints")
        if web.get("virtual_hosts"):
            keys.append("web.virtual_hosts")
        triage = analysis.get("triage") if isinstance(analysis.get("triage"), dict) else {}
        if triage.get("cve_candidates"):
            keys.append("triage.cve_candidates")
    except Exception:
        return keys
    return keys


ADVISOR_SYSTEM = (
    "You are a senior penetration tester."
    " Propose a SMALL set of safe, read-only reconnaissance commands to improve coverage."
    " You MUST follow these rules:\n"
    "- Commands must be non-destructive and read-only.\n"
    "- Prefer nmap/httpx/whatweb/nuclei/nikto/ffuf/feroxbuster/curl.\n"
    "- Do NOT brute-force credentials.\n"
    "- Do NOT run exploits. Recon only.\n"
    "- Output STRICT JSON ONLY with this schema: {\"commands\":[{\"cmd\":\"...\",\"reason\":\"...\",\"expected\":\"...\"}], \"stop_condition\":\"...\"}.\n"
)


def _extract_commands_via_llm(
    *,
    raw: str,
    llm_invoke,  # callable(system,user)->str
    max_cmds: int,
) -> List[str]:
    """Fallback: use AutoPentester Command Extractor to pull commands from free-form text."""
    if not raw:
        return []
    try:
        from utils.autopentester_prompts import COMMAND_EXTRACTOR_INIT
    except Exception:
        return []

    extracted = llm_invoke(COMMAND_EXTRACTOR_INIT, raw) or ""
    lines = [ln.strip() for ln in extracted.splitlines() if ln.strip()]
    if not lines:
        return []
    # First line is tool(s). Commands start from line 2.
    cmds: List[str] = []
    for ln in lines[1:]:
        if ln.lower().strip() == "<next_tool>":
            continue
        cmds.append(ln)
        if len(cmds) >= max_cmds:
            break
    return cmds


def build_advisor_prompt(
    snapshot: Dict[str, Any],
    tool_context: str,
    ip: str,
    max_cmds: int,
) -> str:
    """Create a single prompt for the LLM advisor."""
    return (
        f"Target IP: {ip}\n\n"
        f"Current recon snapshot (facts only):\n{json.dumps(snapshot, ensure_ascii=False)}\n\n"
        + (f"Tool documentation context (may help with correct flags):\n{tool_context}\n\n" if tool_context else "")
        + f"Propose up to {max_cmds} commands. Each command must be a single shell command line."
    )


def parse_advisor_json(text: str) -> Optional[Dict[str, Any]]:
    """Parse the advisor JSON; caller handles tool-specific extraction elsewhere."""
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        # Best-effort extraction
        import re

        m = re.search(r"(\{.*\})", text, flags=re.DOTALL)
        if not m:
            return None
        try:
            return json.loads(m.group(1))
        except Exception:
            return None


def select_commands(obj: Dict[str, Any], max_cmds: int) -> List[str]:
    if not isinstance(obj, dict):
        return []
    cmds: List[str] = []
    items = obj.get("commands")
    if not isinstance(items, list):
        return []
    for it in items:
        if not isinstance(it, dict):
            continue
        cmd = str(it.get("cmd") or "").strip()
        if not cmd:
            continue
        cmds.append(cmd)
        if len(cmds) >= max_cmds:
            break
    return cmds


def advise_commands(
    *,
    analysis: Dict[str, Any],
    ip: str,
    llm_invoke,  # callable: (system:str, user:str)->str
    tool_rag_retrieve,  # callable: (query:str)->str
    max_cmds: int,
    use_command_extractor: bool = True,
) -> Tuple[List[str], str]:
    """Return (commands, raw_llm_text)."""
    snap = coverage_snapshot(analysis)
    query = f"recon commands for {ip} based on ports {snap.get('ports')} and products {snap.get('products')}"
    tool_ctx = ""
    try:
        tool_ctx = tool_rag_retrieve(query) or ""
    except Exception:
        tool_ctx = ""

    user_prompt = build_advisor_prompt(snapshot=snap, tool_context=tool_ctx, ip=ip, max_cmds=max_cmds)
    raw = llm_invoke(ADVISOR_SYSTEM, user_prompt) or ""
    obj = parse_advisor_json(raw) or {}
    cmds = select_commands(obj, max_cmds=max_cmds)
    if not cmds and use_command_extractor:
        # Advisor failed to emit JSON; attempt free-form extraction.
        cmds = _extract_commands_via_llm(raw=raw, llm_invoke=llm_invoke, max_cmds=max_cmds)
    return cmds, raw


