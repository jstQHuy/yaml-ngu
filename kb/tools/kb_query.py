#!/usr/bin/env python3
# Offline signature matcher for PentestAgent Recon artifacts (Level 1).
# Requires PyYAML: pip install pyyaml

import argparse
import json
import re
from pathlib import Path

import yaml


def as_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def compile_any(regex_list):
    return [re.compile(r) for r in (regex_list or [])]


def match_first(regexes, items):
    for item in items:
        s = str(item)
        for rx in regexes:
            m = rx.search(s)
            if m:
                return s, m.group(0)
    return None, None


def collect_haystacks(artifact):
    # Support multiple artifact layouts:
    # 1) {"analysis": {...}}
    # 2) {"final_ai_message_json": {"analysis": {...}}}
    # 3) {"final_ai_message_raw": "{...json string...}"}

    analysis = None

    if isinstance(artifact, dict) and "analysis" in artifact and isinstance(artifact["analysis"], dict):
        analysis = artifact["analysis"]

    elif isinstance(artifact, dict) and "final_ai_message_json" in artifact:
        fa = artifact.get("final_ai_message_json") or {}
        if isinstance(fa, dict) and "analysis" in fa and isinstance(fa["analysis"], dict):
            analysis = fa["analysis"]
        elif isinstance(fa, dict):
            # sometimes fa itself is already analysis-like
            analysis = fa

    if analysis is None and isinstance(artifact, dict) and "final_ai_message_raw" in artifact:
        try:
            raw = artifact["final_ai_message_raw"]
            if isinstance(raw, str):
                raw_obj = json.loads(raw)
                if isinstance(raw_obj, dict) and "analysis" in raw_obj:
                    analysis = raw_obj["analysis"]
        except Exception:
            pass

    if analysis is None:
        # fallback
        analysis = artifact if isinstance(artifact, dict) else {}

    ports = analysis.get("ports", {}) or {}
    web = analysis.get("web", {}) or {}

    services, products, versions, banners, port_ids = [], [], [], [], []
    for p, info in ports.items():
        port_ids.append(str(p))
        services.append(str(info.get("service", "")))
        products.append(str(info.get("product", "")))
        versions.append(str(info.get("version", "")))
        banners.append(str(info.get("banner_evidence", "")))

    paths = [str(x) for x in as_list(web.get("interesting_paths"))]
    evidence_lines = [str(x) for x in as_list(web.get("evidence"))]

    return {
        "services": services,
        "products": products,
        "versions": versions,
        "banners": banners,
        "ports": port_ids,
        "paths": paths,
        "evidence_lines": evidence_lines,
    }



def rule_matches(rule, h):
    when = rule.get("when", {})

    if "service_any" in when:
        if not any(s in h["services"] for s in when["service_any"]):
            return None
    if "port_any" in when:
        if not any(p in h["ports"] for p in when["port_any"]):
            return None

    prod_hit, _ = match_first(compile_any(when.get("product_regex")), h["products"]) if when.get("product_regex") else (None, None)
    ver_hit, _ = match_first(compile_any(when.get("version_regex")), h["versions"]) if when.get("version_regex") else (None, None)
    ban_hit, _ = match_first(compile_any(when.get("banner_regex")), h["banners"]) if when.get("banner_regex") else (None, None)
    path_hit, _ = match_first(compile_any(when.get("any_path_regex")), h["paths"]) if when.get("any_path_regex") else (None, None)
    hdr_hit, _ = match_first(compile_any(when.get("any_header_regex")), h["evidence_lines"]) if when.get("any_header_regex") else (None, None)
    body_hit, _ = match_first(compile_any(when.get("any_body_regex")), h["evidence_lines"]) if when.get("any_body_regex") else (None, None)
    title_hit, _ = match_first(compile_any(when.get("http_title_regex")), h["evidence_lines"]) if when.get("http_title_regex") else (None, None)

    required_groups = [k for k in ("product_regex","version_regex","banner_regex","any_path_regex","any_header_regex","any_body_regex","http_title_regex") if when.get(k)]
    group_hits = {
        "product_regex": prod_hit,
        "version_regex": ver_hit,
        "banner_regex": ban_hit,
        "any_path_regex": path_hit,
        "any_header_regex": hdr_hit,
        "any_body_regex": body_hit,
        "http_title_regex": title_hit,
    }
    for g in required_groups:
        if not group_hits.get(g):
            return None

    return {
        "matched_product": prod_hit,
        "matched_version": ver_hit,
        "matched_banner": ban_hit,
        "matched_path": path_hit,
        "matched_header": hdr_hit,
        "matched_body": body_hit,
        "matched_title": title_hit,
    }


def render_evidence(templates, matched):
    rendered = []
    for t in (templates or []):
        s = t
        for k, v in matched.items():
            s = s.replace("{" + k + "}", str(v or ""))
        rendered.append(s)
    return rendered


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifact", required=True)
    ap.add_argument("--signatures", default="kb/signatures.yaml")
    args = ap.parse_args()

    artifact = json.loads(Path(args.artifact).read_text(encoding="utf-8"))
    rules = yaml.safe_load(Path(args.signatures).read_text(encoding="utf-8"))

    h = collect_haystacks(artifact)
    issues, cve_candidates = [], []

    for rule in rules:
        m = rule_matches(rule, h)
        if not m:
            continue

        then = rule.get("then", {})
        evidence = render_evidence(then.get("evidence_template"), m)

        issue = {
            "id": rule.get("id"),
            "title": rule.get("title"),
            "vuln_type": then.get("vuln_type"),
            "confidence": float(then.get("confidence", 0.5)),
            "cve_hints": then.get("cve_hints", []) or [],
            "evidence": evidence,
            "matched": {k: v for k, v in m.items() if v},
        }
        issues.append(issue)

        for cve in issue["cve_hints"]:
            cve_candidates.append({
                "cve_id": cve,
                "confidence": issue["confidence"],
                "source": issue["id"],
                "evidence": evidence[:2],
            })

    out = {
        "triage": {
            "issues": sorted(issues, key=lambda x: x["confidence"], reverse=True),
            "cve_candidates": sorted(cve_candidates, key=lambda x: x["confidence"], reverse=True),
        }
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
