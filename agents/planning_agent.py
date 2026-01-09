import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import json
import logging
import subprocess
import re
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone

from utils.doc_handler import DocHandler
from utils.merge_scores import merge
from utils.version_limit import get_affected_cve
from utils.model_manager import model_manager
from utils.config_loader import load_config, get_runtime_section
from utils.attack_dag import load_recon_artifact, build_dag, write_dag

logger = logging.getLogger(__name__)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
config_path = os.path.join(PROJECT_ROOT, "configs", "config.yaml")
config = load_config(config_path)

planning_config = get_runtime_section(config, "planning")
if not planning_config:
    raise KeyError("Missing runtime.planning in configs/config.yaml")

cvemap_config = planning_config.get("cvemap", {})
if not isinstance(cvemap_config, dict):
    cvemap_config = {}

ECONOMIC_MODE = bool(planning_config.get("economic_mode", False))
if ECONOMIC_MODE:
    from utils.cve_info_ec import get_exp_info
else:
    from utils.cve_info import get_exp_info


# -------------------------
# Helpers
# -------------------------
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _uniq_keep_order(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in items:
        if not x:
            continue
        y = str(x).strip()
        if not y:
            continue
        y = y.upper()
        if y not in seen:
            out.append(y)
            seen.add(y)
    return out


def _extract_cves_from_keywords(planning_keywords: List[str]) -> List[str]:
    found: List[str] = []
    for s in planning_keywords or []:
        if not s:
            continue
        for m in CVE_RE.findall(str(s)):
            found.append(m.upper())
    return _uniq_keep_order(found)


def _safe_abs(base: str, p: str) -> str:
    if not p:
        return os.path.abspath(base)
    if os.path.isabs(p):
        return os.path.abspath(p)
    return os.path.abspath(os.path.join(base, p))


def create_summary_and_index(dir_path: str, summary_prompt: str, query: str, keyword: str) -> str:
    doc_handler = DocHandler()
    doc_handler.create_index(dir_path, summary_prompt, keyword)
    response = doc_handler.query(query)
    return str(response)


def cvemap_product(product: str, output_dir: str, cvemap_cfg: Dict) -> List[Dict]:
    """
    Use ProjectDiscovery 'vulnx search' to obtain CVE candidates.
    Output normalized to a list of dicts:
      - cve_id (str)
      - cve_description (optional str)
    Write to output_dir/cvemap.json for backward compatibility.
    """
    import shutil

    os.makedirs(output_dir, exist_ok=True)
    cvemap_json_path = os.path.join(output_dir, "cvemap.json")

    query = (product or "").strip()
    if not query:
        with open(cvemap_json_path, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2, ensure_ascii=False)
        return []

    vulnx_bin = shutil.which("vulnx") or os.path.join(os.path.expanduser("~"), "go", "bin", "vulnx")
    if not (vulnx_bin and os.path.exists(vulnx_bin)):
        logger.warning("[VULNX] vulnx binary not found in PATH or ~/go/bin. Return empty list.")
        with open(cvemap_json_path, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2, ensure_ascii=False)
        return []

    max_entry = cvemap_cfg.get("max_entry")
    min_year = cvemap_cfg.get("min_year")
    max_year = cvemap_cfg.get("max_year")
    page_limit = int(cvemap_cfg.get("page_limit") or 200)

    cmd = [vulnx_bin, "search", query, "--limit", str(page_limit), "--json"]

    try:
        r = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=90
        )
    except subprocess.CalledProcessError as e:
        logger.warning(
            "[VULNX] vulnx failed (rc=%s). stdout=%s | stderr=%s",
            getattr(e, "returncode", "?"),
            (getattr(e, "stdout", "") or "")[:800],
            (getattr(e, "stderr", "") or "")[:800],
        )
        with open(cvemap_json_path, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2, ensure_ascii=False)
        return []
    except subprocess.TimeoutExpired:
        logger.warning("[VULNX] vulnx timed out.")
        with open(cvemap_json_path, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2, ensure_ascii=False)
        return []

    raw = (r.stdout or "").strip()
    if not raw:
        with open(cvemap_json_path, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2, ensure_ascii=False)
        return []

    cve_re = CVE_RE

    def extract_entries(obj: Any) -> List[Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}

        def walk(x: Any):
            if isinstance(x, dict):
                cve_id = None
                for k in ("cve_id", "cve", "id", "cveId", "cveID"):
                    v = x.get(k)
                    if isinstance(v, str) and cve_re.fullmatch(v.strip()):
                        cve_id = v.strip().upper()
                        break

                if not cve_id:
                    for v in x.values():
                        if isinstance(v, str):
                            m = cve_re.search(v)
                            if m:
                                cve_id = m.group(0).upper()
                                break

                if cve_id:
                    desc = ""
                    for dk in ("cve_description", "description", "summary", "title"):
                        dv = x.get(dk)
                        if isinstance(dv, str) and len(dv.strip()) > len(desc):
                            desc = dv.strip()

                    rec = out.get(cve_id, {"cve_id": cve_id})
                    if desc and len(desc) > len(rec.get("cve_description", "") or ""):
                        rec["cve_description"] = desc
                    out[cve_id] = rec

                for v in x.values():
                    walk(v)

            elif isinstance(x, list):
                for it in x:
                    walk(it)

        walk(obj)
        return list(out.values())

    try:
        obj = json.loads(raw)
        entries = extract_entries(obj)
    except Exception:
        ids = sorted(set(m.upper() for m in cve_re.findall(raw)))
        entries = [{"cve_id": c} for c in ids]

    filtered: List[Dict[str, Any]] = []
    for it in entries:
        cid = it.get("cve_id", "")
        if not isinstance(cid, str) or not cid:
            continue
        try:
            year = int(cid.split("-")[1])
        except Exception:
            continue
        if isinstance(max_year, int) and year > max_year:
            continue
        if isinstance(min_year, int) and year < min_year:
            continue
        filtered.append(it)

    if isinstance(max_entry, int) and max_entry > 0:
        filtered = filtered[:max_entry]

    with open(cvemap_json_path, "w", encoding="utf-8") as f:
        json.dump(filtered, f, indent=2, ensure_ascii=False)

    return filtered


def _load_recon_artifact(topic: str, memory_dir: str) -> Optional[Dict[str, Any]]:
    if not topic or not memory_dir:
        return None

    if not os.path.isabs(memory_dir):
        memory_dir = os.path.join(PROJECT_ROOT, memory_dir)

    p = os.path.join(memory_dir, f"{topic}_artifact.json")
    if not os.path.exists(p):
        return None

    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _load_recon_memory_snapshot_text(topic: str, memory_dir: str, max_msgs: int = 30, max_chars: int = 20000) -> str:
    if not topic or not memory_dir:
        return ""

    if not os.path.isabs(memory_dir):
        memory_dir = os.path.join(PROJECT_ROOT, memory_dir)

    path = os.path.join(memory_dir, f"{topic}.json")
    if not os.path.exists(path):
        return ""

    try:
        payload = json.load(open(path, "r", encoding="utf-8"))
    except Exception:
        return ""

    messages: List[Dict[str, Any]] = []
    if isinstance(payload, list):
        messages = payload
    elif isinstance(payload, dict):
        for k in ("messages", "chat_history", "data"):
            if isinstance(payload.get(k), list):
                messages = payload[k]
                break

    tail = messages[-max_msgs:] if messages else []
    out_parts: List[str] = []
    for m in tail:
        if not isinstance(m, dict):
            continue
        role = m.get("type") or m.get("role") or "unknown"
        data = m.get("data") if isinstance(m.get("data"), dict) else m
        content = data.get("content") if isinstance(data, dict) else None
        if not content:
            continue
        out_parts.append(f"[{role}] {content}")

    text = "\n".join(out_parts)
    if len(text) > max_chars:
        text = text[-max_chars:]
    return text


def _infer_from_artifact(artifact: Dict[str, Any]) -> Tuple[str, str, str, List[str]]:
    """
    Return (app, version, keyword, planning_keywords).

    Recon artifacts in this repository have multiple shapes over time. This
    function is intentionally defensive: it will accept both the older
    wrapper shape (artifact["final_ai_message_json"]["analysis"]) and the
    newer canonical shape (artifact["analysis"]).
    """
    app = ""
    version = ""
    keyword = ""
    planning_keywords: List[str] = []

    # 1) Pick the canonical analysis object
    analysis: Dict[str, Any] = {}
    if isinstance(artifact.get("analysis"), dict):
        analysis = artifact.get("analysis") or {}
    else:
        final = artifact.get("final_ai_message_json") or {}
        if isinstance(final, dict) and isinstance(final.get("analysis"), dict):
            analysis = final.get("analysis") or {}

    # 2) Prefer analysis.planning (this is the primary schema in utils/prompts/agent.py)
    pl = analysis.get("planning") if isinstance(analysis, dict) else None
    if isinstance(pl, dict):
        app = str(pl.get("app") or "").strip()
        version = str(pl.get("version") or "").strip()
        keyword = str(pl.get("keyword") or app or "").strip()

        pks = pl.get("planning_keywords")
        if isinstance(pks, list):
            planning_keywords = [str(x).strip() for x in pks if str(x).strip()]

        # If recon provided high-confidence CVE IDs, surface them as planning keywords
        cve_ids = pl.get("cve_ids")
        if isinstance(cve_ids, list):
            for cid in cve_ids:
                s = str(cid).strip()
                if s:
                    planning_keywords.insert(0, s)

    # 3) Fallback to a "products" list if present (older experiments)
    if (not app) and isinstance(analysis.get("products"), list):
        products = analysis.get("products") or []
        best = None
        for p in products:
            if not isinstance(p, dict):
                continue
            conf = p.get("confidence")
            if not isinstance(conf, (int, float)):
                conf = 0.0
            if best is None or float(conf) > float(best.get("confidence") or 0.0):
                best = p
        if isinstance(best, dict):
            app = str(best.get("name") or best.get("product") or "").strip()
            version = str(best.get("version_candidate") or best.get("version") or "").strip()
            if not keyword and app:
                keyword = app

    # 4) Prefer KB triage CVE candidates if available (artifact self-contained)
    triage = analysis.get("triage") if isinstance(analysis, dict) else None
    triage_terms: List[str] = []
    if isinstance(triage, dict):
        cc = triage.get("cve_candidates")
        if isinstance(cc, list):
            for item in cc:
                if isinstance(item, dict):
                    cid = item.get("cve_id") or item.get("keyword")
                    if cid:
                        triage_terms.append(str(cid).strip())

    if triage_terms:
        seen = set()
        merged: List[str] = []
        for x in triage_terms + planning_keywords:
            sx = str(x).strip()
            if not sx or sx in seen:
                continue
            seen.add(sx)
            merged.append(sx)
        planning_keywords = merged

    # 5) Final hygiene
    if not keyword:
        keyword = app
    planning_keywords = [x for x in _uniq_keep_order(planning_keywords) if x]

    return app, version, keyword, planning_keywords


def _infer_app_and_version_from_text(text: str) -> Tuple[str, str]:
    if not text:
        return "", ""

    if re.search(r"\bActiveMQ\b", text, re.IGNORECASE) or re.search(r"ActiveMQRealm", text, re.IGNORECASE):
        ver = ""
        m = re.search(r"ProviderVersion[^0-9]*([0-9]+\.[0-9]+\.[0-9]+)", text, re.IGNORECASE)
        if m:
            ver = m.group(1)
        return "ActiveMQ", ver

    if re.search(r"\bJenkins\b", text, re.IGNORECASE):
        ver = ""
        m = re.search(r"X\-Jenkins\s*:\s*([0-9][0-9\.]+)", text, re.IGNORECASE)
        if m:
            ver = m.group(1)
        return "Jenkins", ver

    return "", ""


def _build_vulnx_queries(app: str, keyword: str, product_name: str, planning_keywords: List[str]) -> List[str]:
    """
    Build a robust list of queries for vulnx:
      - explicit CVE IDs from planning_keywords (best)
      - keyword, app, product_name
      - raw planning_keywords (strings)
    """
    queries: List[str] = []

    # CVEs first
    cves = _extract_cves_from_keywords(planning_keywords)
    queries.extend(cves)

    # high-signal terms
    for q in (keyword, app, product_name):
        q = (q or "").strip()
        if q:
            queries.append(q)

    # raw planning keywords
    for pk in (planning_keywords or []):
        pk = (pk or "").strip()
        if pk:
            queries.append(pk)

    # de-dup, keep order
    return _uniq_keep_order(queries)


def main():
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        filename="planning_agent.log",
        level=logging.INFO
    )

    runtime = (config.get("runtime") or {})
    recon_cfg = (runtime.get("recon") or {})

    model_name = planning_config.get("model", "openai")
    _ = model_manager.get_model(model_name)
    logger.info("Using model: %s", model_name)

    topic = (recon_cfg.get("current_topic") or planning_config.get("current_topic") or "default_topic").strip()
    memory_dir = (recon_cfg.get("memory_dir") or "recon_memory")

    keyword = (planning_config.get("keyword") or "").strip()
    app = (planning_config.get("app") or "").strip()
    version = (planning_config.get("version") or "").strip()
    vuln_type = (planning_config.get("vuln_type") or "").strip()

    output_dir_cfg = planning_config.get("output_dir", "data/exp_info")
    output_dir = _safe_abs(PROJECT_ROOT, output_dir_cfg)

    safe_topic = re.sub(r"[^a-zA-Z0-9_.-]+", "-", topic) if topic else "default_topic"

    # 1) Prefer recon artifact
    planning_keywords: List[str] = []
    artifact = _load_recon_artifact(topic=topic, memory_dir=memory_dir)
    if artifact:
        a_app, a_ver, a_kw, a_pks = _infer_from_artifact(artifact)
        if a_pks:
            planning_keywords = a_pks
        if not app and a_app:
            app = a_app
        if not version and a_ver:
            version = a_ver
        if not keyword and a_kw:
            keyword = a_kw

    # 2) Fallback to recon memory text
    if planning_config.get("use_recon_memory", True) and (not app or not keyword) and topic:
        snap_text = _load_recon_memory_snapshot_text(topic=topic, memory_dir=memory_dir)
        if snap_text:
            t_app, t_ver = _infer_app_and_version_from_text(snap_text)
            if not app and t_app:
                app = t_app
            if not keyword and t_app:
                keyword = t_app
            if not version and t_ver:
                version = t_ver

    product_name = (app or keyword or "Unknown").strip()
    res_dir = os.path.join(output_dir, product_name, safe_topic)
    os.makedirs(res_dir, exist_ok=True)

    # Save recon snapshot files next to outputs (best effort)
    if planning_config.get("use_recon_memory", True) and topic:
        snap_text = _load_recon_memory_snapshot_text(topic=topic, memory_dir=memory_dir)
        if snap_text:
            snap_path = os.path.join(res_dir, "recon_memory_snapshot.txt")
            with open(snap_path, "w", encoding="utf-8") as f:
                f.write(f"# topic={topic} captured_at={datetime.now(timezone.utc).isoformat()}\n\n")
                f.write(snap_text)

    if artifact:
        art_path = os.path.join(res_dir, "recon_artifact.json")
        try:
            with open(art_path, "w", encoding="utf-8") as f:
                json.dump(artifact, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    logger.info("Planning input: product=%s keyword=%s version=%s topic=%s", product_name, keyword, version, topic)

    # -------------------------
    # CVE list (fixed logic)
    # -------------------------
    # (A) First: extract CVEs directly from planning_keywords (your recon already provides these in many cases)
    cve_lst: List[str] = _extract_cves_from_keywords(planning_keywords)

    # (B) If still empty: query vulnx with robust queries (no underscore mangling)
    cvemap_res: List[Dict[str, Any]] = []
    cvemap_res_dir = os.path.join(res_dir, "CVEMAP")

    if not cve_lst:
        queries = _build_vulnx_queries(app=app, keyword=keyword, product_name=product_name, planning_keywords=planning_keywords)

        # limit how many queries we try to avoid long runtime
        max_queries = int(cvemap_config.get("max_queries") or 6)
        if max_queries > 0:
            queries = queries[:max_queries]

        for q in queries:
            # If q is a CVE ID, that is ideal
            cvemap_res = cvemap_product(q, cvemap_res_dir, cvemap_config)
            if cvemap_res:
                logger.info("CVEMAP hit with query=%s entries=%d", q, len(cvemap_res))
                break

    # (C) If we got cvemap_res, build CVE list from it (respect version filter if version exists)
    if not cve_lst and cvemap_res:
        if version:
            print("Version constraint has been set, will use this to save tokens.\nThis MAY NOT ACCURATE, please double check!")
            limited_lst = get_affected_cve(cvemap_res, version) or []
            print(f"The following CVEs will be searched:\n{limited_lst}")
            cve_lst = [x.get("cve_id") for x in limited_lst if isinstance(x, dict) and x.get("cve_id")]

            # IMPORTANT FIX: if version-filter makes empty, fallback to unfiltered
            if not cve_lst and cvemap_res:
                logger.warning("Version-filter returned 0 CVEs; falling back to unfiltered CVEs from CVEMAP.")
                cve_lst = [x.get("cve_id") for x in cvemap_res if isinstance(x, dict) and x.get("cve_id")]
        else:
            cve_lst = [x.get("cve_id") for x in cvemap_res if isinstance(x, dict) and x.get("cve_id")]

        cve_lst = _uniq_keep_order(cve_lst)

    # (D) Optional hard fallback for Shellshock if recon strongly indicates it but no CVE extracted
    if not cve_lst and (keyword or "").strip().lower() == "shellshock":
        cve_lst = ["CVE-2014-6271"]
        logger.info("Injected fallback CVE for Shellshock: CVE-2014-6271")

    # If still empty: write empty plan and stop (unchanged behavior, but now rare)
    if not cve_lst:
        logger.warning("CVE list is empty. Will write empty plan.json and exit gracefully.")
        plan_filename = "plan_ec.json" if ECONOMIC_MODE else "plan.json"
        empty_plan_path = os.path.join(res_dir, plan_filename)
        with open(empty_plan_path, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2, ensure_ascii=False)

        thread_root = os.path.join(PROJECT_ROOT, "data", "threads")
        os.makedirs(thread_root, exist_ok=True)
        thread_dir = os.path.join(thread_root, safe_topic)
        os.makedirs(thread_dir, exist_ok=True)
        dst = os.path.join(thread_dir, "plan.json" if plan_filename == "plan.json" else "plan_ec.json")
        with open(empty_plan_path, "rb") as rf, open(dst, "wb") as wf:
            wf.write(rf.read())

        meta = {
            "topic": topic,
            "safe_topic": safe_topic,
            "product": product_name,
            "keyword": keyword,
            "app": app,
            "version": version,
            "vuln_type": vuln_type,
            "planning_keywords": planning_keywords,
            "extracted_cves": cve_lst,
            "source_plan_path": os.path.relpath(empty_plan_path, PROJECT_ROOT),
            "copied_to": os.path.relpath(dst, PROJECT_ROOT),
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "note": "Empty CVE list; wrote empty plan to avoid crash."
        }
        with open(os.path.join(thread_dir, "planning_meta.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, ensure_ascii=False)

        print("CVE to be searched not set! Wrote empty plan and stopped.")
        return

    # -------------------------
    # Run search/analysis
    # -------------------------
    times = get_exp_info(cve_lst, res_dir, app)

    if not times or not isinstance(times, (list, tuple)) or len(times) != 2:
        logger.warning("get_exp_info returned unexpected value: %r. Setting times to 0.", times)
        exploit_searching_time, exploit_analysis_time = 0.0, 0.0
    else:
        exploit_searching_time, exploit_analysis_time = times

    # Merge scores -> plan
    if ECONOMIC_MODE:
        plan_filename = "plan_ec.json"
        merge(res_dir, os.path.join(res_dir, plan_filename), True)
    else:
        plan_filename = "plan.json"
        merge(res_dir, os.path.join(res_dir, plan_filename), False)

    # Copy plan to per-thread deterministic location
    thread_root = os.path.join(PROJECT_ROOT, "data", "threads")
    os.makedirs(thread_root, exist_ok=True)
    thread_dir = os.path.join(thread_root, safe_topic)
    os.makedirs(thread_dir, exist_ok=True)

    src = os.path.join(res_dir, plan_filename)
    dst = os.path.join(thread_dir, "plan.json" if plan_filename == "plan.json" else "plan_ec.json")
    with open(src, "rb") as rf, open(dst, "wb") as wf:
        wf.write(rf.read())

    meta = {
        "topic": topic,
        "safe_topic": safe_topic,
        "product": product_name,
        "keyword": keyword,
        "app": app,
        "version": version,
        "vuln_type": vuln_type,
        "planning_keywords": planning_keywords,
        "final_cves": cve_lst,
        "source_plan_path": os.path.relpath(src, PROJECT_ROOT),
        "copied_to": os.path.relpath(dst, PROJECT_ROOT),
        "captured_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(os.path.join(thread_dir, "planning_meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

    # -------------------------------------------------
    # NEW: Build a multi-track DAG plan (plan_dag.json)
    # -------------------------------------------------
    try:
        # Load the merged plan entries we just wrote
        merged_plan: List[Dict[str, Any]] = []
        try:
            with open(src, "r", encoding="utf-8") as pf:
                obj = json.load(pf)
                if isinstance(obj, list):
                    merged_plan = obj
        except Exception:
            merged_plan = []

        # Load recon artifact (from recon_memory if enabled)
        recon_mem_dir = (config.get("runtime") or {}).get("recon", {}).get("memory_dir")
        artifact = load_recon_artifact(PROJECT_ROOT, topic, memory_dir=recon_mem_dir)
        analysis_obj: Dict[str, Any] = {}
        if isinstance(artifact.get("analysis"), dict):
            analysis_obj = artifact.get("analysis") or {}
        else:
            fa = artifact.get("final_ai_message_json")
            if isinstance(fa, dict) and isinstance(fa.get("analysis"), dict):
                analysis_obj = fa.get("analysis") or {}

        triage_obj = analysis_obj.get("triage") if isinstance(analysis_obj, dict) else None
        if not isinstance(triage_obj, dict):
            triage_obj = {"issues": [], "cve_candidates": []}

        dag = build_dag(topic=topic, analysis=analysis_obj, triage=triage_obj, plan_entries=merged_plan)

        dag_path = write_dag(PROJECT_ROOT, topic, dag, filename="plan_dag.json")

        # Also store a copy next to plan.json (res_dir) for convenience
        try:
            dag_copy = os.path.join(res_dir, "plan_dag.json")
            with open(dag_copy, "w", encoding="utf-8") as df:
                json.dump(dag, df, indent=2, ensure_ascii=False)
        except Exception:
            pass

        logger.info("Wrote plan DAG: %s", dag_path)
        print(f"[Planning] Wrote multi-track plan DAG to {dag_path}")
    except Exception as e:
        logger.warning("Failed to build plan_dag.json: %s", e)

    print(f"Successfully saved results to {src}")
    print(f"Exploit searching time is {exploit_searching_time:.6f} seconds")
    print(f"Exploit analysis time is {exploit_analysis_time:.6f} seconds")
    print(f"Total exploit time is {(exploit_searching_time + exploit_analysis_time):.6f} seconds")

if __name__ == "__main__":
    main()
