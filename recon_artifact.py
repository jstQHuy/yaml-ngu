# utils/recon_artifact.py
import os, json, re
from typing import Any, Dict, List
from datetime import datetime, timezone

def safe_topic_name(topic: str) -> str:
    topic = (topic or "default_topic").strip()
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", topic) or "default_topic"

def ensure_dir(p: str) -> None:
    os.makedirs(p, exist_ok=True)

def write_recon_artifact(
    project_root: str,
    topic: str,
    recon_summary: Dict[str, Any],
    ports_summary: Dict[str, Any] | None = None,
    candidates: List[Dict[str, Any]] | None = None,
) -> str:
    """
    Writes: <project_root>/data/threads/<safe_topic>/recon_artifact.json
    """
    safe_topic = safe_topic_name(topic)
    thread_dir = os.path.join(project_root, "data", "threads", safe_topic)
    ensure_dir(thread_dir)

    artifact = {
        "topic": topic,
        "safe_topic": safe_topic,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "summary": recon_summary or {},
        "ports": ports_summary or {},
        "candidates": candidates or [],
    }

    out_path = os.path.join(thread_dir, "recon_artifact.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2, ensure_ascii=False)

    return out_path
