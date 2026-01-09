import sys
import os
import json
import re
import logging
import subprocess
import time
import shlex
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple, Optional
from dotenv import load_dotenv
from pathlib import Path

# Load .env from repo root regardless of current working directory
load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

# Ensure project root is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils.config_loader import load_config, get_runtime_section
from utils.model_manager import get_model
from utils.attack_dag import safe_topic as _safe_topic_name
from utils.attack_dag import load_recon_artifact
from utils.deterministic_actions import run_web_hunt_creds, run_try_ssh

try:
    from langchain_core.messages import HumanMessage, AIMessage
    from langchain_core.chat_history import InMemoryChatMessageHistory
except Exception as e:
    raise RuntimeError(
        "Thiếu langchain_core. Hãy cài trong .venv:\n"
        "  source .venv/bin/activate\n"
        "  python -m pip install langchain-core langchain-community langchain\n"
        f"\nChi tiết lỗi: {e}"
    )

logger = logging.getLogger(__name__)
logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    filename="execution_agent.log",
    level=logging.INFO,
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG_PATH = os.path.join(PROJECT_ROOT, "configs", "config.yaml")


# -----------------------------
# Guard / Policy (no CommandPolicy)
# -----------------------------
@dataclass
class ExecGuard:
    enable_autorun: bool
    allowed_cmd_regex: List[str]
    denied_cmd_regex: List[str]
    timeout_sec: int
    max_output_chars: int

    # Safety toggles
    block_chaining: bool = True  # blocks && ; |
    allow_pipes: bool = False    # if True, '|' won't be blocked when block_chaining=True


def _compile_patterns(patterns: List[str]) -> List[re.Pattern]:
    out: List[re.Pattern] = []
    for p in patterns or []:
        try:
            out.append(re.compile(p))
        except re.error:
            logger.warning("Invalid regex pattern ignored: %s", p)
    return out


def _check_command(cmd: str, guard: ExecGuard, allowlist: List[re.Pattern], denylist: List[re.Pattern]) -> Tuple[bool, str]:
    if not guard.enable_autorun:
        return False, "Autorun is disabled (runtime.execution.enable_autorun=false)"

    c = (cmd or "").strip()
    if not c:
        return False, "Empty command"

    # Block chaining / piping unless you explicitly allow it
    if guard.block_chaining:
        if "&&" in c or ";" in c:
            return False, "Command chaining is not allowed (contains && or ;)"
        if ("|" in c) and (not guard.allow_pipes):
            return False, "Piping is not allowed (contains |)"

    for pat in denylist:
        if pat.search(c):
            return False, f"Matched denied_cmd_regex: {pat.pattern}"

    # If allowlist is configured, command must match at least one pattern
    if allowlist:
        for pat in allowlist:
            if pat.search(c):
                return True, "OK"
        return False, "Did not match any allowed_cmd_regex"

    return True, "OK"


def _safe_topic(topic: str) -> str:
    # Keep existing behavior but centralize sanitization for plan_dag.json paths
    return _safe_topic_name(topic)


def _load_plan_dag_for_topic(topic: str) -> Tuple[str, Dict[str, Any]]:
    """Load multi-track plan DAG for topic if available."""
    safe = _safe_topic(topic)
    base = os.path.join(PROJECT_ROOT, "data", "threads", safe)
    p = os.path.join(base, "plan_dag.json")
    if os.path.exists(p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                obj = json.load(f)
            if isinstance(obj, dict):
                return p, obj
        except Exception:
            pass
    return "", {}


# -----------------------------
# Stores (credentials / sessions / findings)
# -----------------------------


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _store_dedup_key(c: Dict[str, Any]) -> Tuple[str, str, str, str]:
    return (
        str(c.get("username") or ""),
        str(c.get("secret") or ""),
        str(c.get("type") or ""),
        str(c.get("source_url") or c.get("source") or ""),
    )


def _run_deterministic_action(
    *,
    action: Dict[str, Any],
    topic: str,
    target_ip: str,
    base_urls: List[str],
    cred_store: List[Dict[str, Any]],
    session_store: Dict[str, List[Dict[str, Any]]],
    findings: List[Dict[str, Any]],
    guard: ExecGuard,
    allowlist: List[re.Pattern],
    denylist: List[re.Pattern],
    history: InMemoryChatMessageHistory,
    deterministic_allow: set,
) -> bool:
    """Execute a subset of actions deterministically (no LLM).

    Returns True if the action type is handled (success or failure).
    """

    if not isinstance(action, dict):
        return False
    a_type = str(action.get("type") or "").strip().upper()
    if not a_type or a_type not in deterministic_allow:
        return False

    def runner(cmd: str, cwd: Optional[str]) -> Tuple[str, Optional[str]]:
        out, new_cwd = _run_shell(guard, allowlist, denylist, cmd, cwd=cwd)
        history.add_message(HumanMessage(content=f"[DET] Command: {cmd}\nOutput:\n{out}"))
        return out, new_cwd

    if a_type == "WEB_HUNT_CREDS":
        creds, fnds = run_web_hunt_creds(runner=runner, base_urls=base_urls)
        # Store updates
        existing = {_store_dedup_key(x) for x in cred_store}
        for c in creds:
            c = dict(c)
            c.setdefault("at", _now_iso())
            k = _store_dedup_key(c)
            if k in existing:
                continue
            existing.add(k)
            cred_store.append(c)
        for fnd in fnds:
            if isinstance(fnd, dict):
                fnd = dict(fnd)
                fnd.setdefault("at", _now_iso())
                fnd.setdefault("action_id", action.get("id"))
                fnd.setdefault("action_type", a_type)
                findings.append(fnd)
        return True

    if a_type == "TRY_SSH":
        ok, fnds = run_try_ssh(runner=runner, target_ip=target_ip, credentials=cred_store)
        for fnd in fnds:
            if isinstance(fnd, dict):
                fnd = dict(fnd)
                fnd.setdefault("at", _now_iso())
                fnd.setdefault("action_id", action.get("id"))
                fnd.setdefault("action_type", a_type)
                findings.append(fnd)
        if ok:
            session_store.setdefault("ssh", []).append({"at": _now_iso(), "detail": "ssh_login_success", "source": "deterministic"})
        return True

    return False


def _extract_credentials_from_text(text: str) -> List[Dict[str, Any]]:
    """Heuristic credential extraction.

    This is intentionally conservative to avoid polluting the store.
    It targets common patterns in writeups and tool outputs:
      - user:pass
      - username=... password=...

    It will *not* treat hashes as passwords unless explicitly labeled.
    """
    if not text:
        return []

    found: List[Dict[str, Any]] = []

    # 1) user:pass (avoid URLs and timestamps)
    for m in re.finditer(r"\b([a-zA-Z0-9_.-]{1,32})\s*:\s*([^\s'\"<>]{4,80})\b", text):
        user = m.group(1)
        pwd = m.group(2)
        if user.lower() in {"http", "https"}:
            continue
        if "/" in pwd or "://" in pwd:
            continue
        found.append({"username": user, "secret": pwd, "type": "password", "source": "stdout"})

    # 2) username=... password=...
    for m in re.finditer(
        r"(?i)\b(user(?:name)?|login)\s*[=:]\s*([a-zA-Z0-9_.-]{1,32}).{0,40}?\b(pass(?:word)?|pwd)\s*[=:]\s*([^\s'\"<>]{4,80})",
        text,
    ):
        user = m.group(2)
        pwd = m.group(4)
        found.append({"username": user, "secret": pwd, "type": "password", "source": "stdout"})

    # De-dup
    uniq = []
    seen = set()
    for c in found:
        k = (c.get("username"), c.get("secret"), c.get("type"))
        if k in seen:
            continue
        seen.add(k)
        uniq.append(c)
    return uniq[:25]


def _looks_like_ssh_success(output: str) -> bool:
    if not output:
        return False
    o = output.lower()
    return ("last login" in o) or ("welcome" in o and "permission denied" not in o)


def _req_satisfied(req: str, evidence: set, cred_store: List[Dict[str, Any]], sessions: Dict[str, List[Dict[str, Any]]]) -> bool:
    r = (req or "").strip()
    if not r:
        return True
    if r.startswith("evidence:"):
        key = r.split(":", 1)[1]
        return key in evidence
    if r.startswith("store:credentials:any"):
        return len(cred_store) > 0
    if r.startswith("store:sessions:"):
        kind = r.split(":", 2)[2]
        if kind == "any":
            return any(v for v in sessions.values())
        return len(sessions.get(kind, [])) > 0
    # Unknown requirement => treat as unmet
    return False


def _select_next_action(dag: Dict[str, Any], done_ids: set, evidence: set, cred_store: List[Dict[str, Any]], sessions: Dict[str, List[Dict[str, Any]]]) -> Optional[Dict[str, Any]]:
    actions = dag.get("actions") if isinstance(dag, dict) else None
    if not isinstance(actions, list):
        return None

    candidates: List[Dict[str, Any]] = []
    for a in actions:
        if not isinstance(a, dict):
            continue
        aid = str(a.get("id") or "")
        if not aid or aid in done_ids:
            continue
        reqs = a.get("requires")
        if reqs is None:
            reqs = []
        if not isinstance(reqs, list):
            reqs = [str(reqs)]
        if all(_req_satisfied(str(r), evidence, cred_store, sessions) for r in reqs):
            candidates.append(a)

    if not candidates:
        return None

    def pr(a: Dict[str, Any]) -> float:
        p = a.get("priority")
        return float(p) if isinstance(p, (int, float)) else 0.0

    candidates.sort(key=pr, reverse=True)
    return candidates[0]


def _load_plan_for_topic(topic: str) -> Tuple[str, List[Dict[str, Any]]]:
    safe = _safe_topic(topic)
    base = os.path.join(PROJECT_ROOT, "data", "threads", safe)

    for name in ("plan_ec.json", "plan.json"):
        p = os.path.join(base, name)
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    obj = json.load(f)
                if isinstance(obj, list):
                    return p, obj
            except Exception:
                continue

    return "", []


def _pick_best_entry(plan: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not plan:
        return None

    def score_of(x: Dict[str, Any]) -> float:
        s = x.get("score")
        if isinstance(s, (int, float)):
            return float(s)
        return 0.0

    return sorted(plan, key=score_of, reverse=True)[0]


def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    # Allow fenced ```json
    m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        text = m.group(1)
    # Or any {...}
    m2 = re.search(r"(\{.*\})", text, re.DOTALL)
    if m2:
        text = m2.group(1)
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        return None
    return None


def _normalize_executable(executable: Any) -> List[str]:
    """
    Accept:
      - "None" / None -> []
      - string -> [string]
      - list[str] -> list[str]
    Anything else -> []
    """
    if executable is None:
        return []
    if isinstance(executable, str):
        exe = executable.strip()
        if not exe or exe.lower() == "none":
            return []
        return [exe]
    if isinstance(executable, list):
        cmds: List[str] = []
        for x in executable:
            if isinstance(x, str) and x.strip():
                if x.strip().lower() != "none":
                    cmds.append(x.strip())
        return cmds
    return []


def _slug(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s or "poc"


def _tokenize(cmd: str) -> List[str]:
    # Best-effort tokenize for analysis (not for execution)
    try:
        return shlex.split(cmd)
    except Exception:
        return (cmd or "").split()


def _find_go_file_dir(cmd: str, cwd: Optional[str]) -> Optional[str]:
    """
    If cmd references a .go file (absolute or resolvable relative), return its directory.
    """
    tokens = _tokenize(cmd)
    base = cwd or os.getcwd()
    for t in tokens:
        if not isinstance(t, str):
            continue
        if t.endswith(".go"):
            if os.path.isabs(t) and os.path.isfile(t):
                return os.path.dirname(t)
            candidate = os.path.abspath(os.path.join(base, t))
            if os.path.isfile(candidate):
                return os.path.dirname(candidate)
    return None


def _is_go_cmd(cmd: str) -> bool:
    c = (cmd or "").strip()
    return c.startswith("go " ) or c == "go"


def _module_path_for_dir(dirpath: str) -> str:
    # You can customize this prefix if you want
    name = _slug(os.path.basename(dirpath))
    return f"example.com/{name}"


def _ensure_go_module(
    guard: ExecGuard,
    allowlist: List[re.Pattern],
    denylist: List[re.Pattern],
    cwd: str,
    history: InMemoryChatMessageHistory,
) -> List[Tuple[str, str]]:
    """
    Ensure go.mod exists in cwd.
    Returns list of (cmd, output) executed.
    """
    executed: List[Tuple[str, str]] = []
    gomod = os.path.join(cwd, "go.mod")
    if os.path.isfile(gomod):
        return executed

    module_path = _module_path_for_dir(cwd)
    cmds = [f"go mod init {module_path}", "go mod tidy"]

    for cmd in cmds:
        out, _ = _run_shell(
            guard=guard,
            allowlist=allowlist,
            denylist=denylist,
            cmd=cmd,
            cwd=cwd,
        )
        executed.append((cmd, out))
        # Save to history for LLM awareness
        history.add_message(HumanMessage(content=f"[AUTO] Command: {cmd}\nOutput:\n{out}"))

        # If blocked, stop early; user needs to adjust allowlist
        if out.startswith("[BLOCKED]"):
            break

    return executed


def _rewrite_go_mod_init_if_missing_path(cmd: str, cwd: Optional[str]) -> str:
    """
    If cmd is exactly `go mod init` (no args), rewrite with module path based on cwd.
    """
    if re.match(r"^\s*go\s+mod\s+init\s*$", cmd or ""):
        base = cwd or os.getcwd()
        return f"go mod init {_module_path_for_dir(base)}"
    return cmd


def _run_shell(
    guard: ExecGuard,
    allowlist: List[re.Pattern],
    denylist: List[re.Pattern],
    cmd: str,
    cwd: Optional[str] = None,
) -> Tuple[str, Optional[str]]:
    """
    Run a shell command with guardrails.
    Returns (output, new_cwd_if_cd_else_None).

    NOTE:
    - 'cd <dir>' is handled internally by updating cwd, because 'cd' won't persist across subprocess calls.
    """
    cmd = (cmd or "").strip()
    if not cmd:
        return "[SKIP] Empty command", None

    # Handle 'cd' explicitly (do not send to subprocess)
    m = re.match(r"^\s*cd\s+(.+?)\s*$", cmd)
    if m:
        target = m.group(1).strip().strip('"').strip("'")
        base = cwd or os.getcwd()
        new_dir = target if os.path.isabs(target) else os.path.abspath(os.path.join(base, target))
        if os.path.isdir(new_dir):
            return f"[OK] Changed directory to: {new_dir}", new_dir
        return f"[ERROR] cd failed: directory not found: {new_dir}", None

    # Make python/pip executions deterministic: always use the interpreter that is
    # currently running ExecutionAgent (typically the active virtualenv).
    cmd = _rewrite_python_and_pip(cmd)

    ok, reason = _check_command(cmd, guard, allowlist, denylist)
    if not ok:
        return f"[BLOCKED] {reason}. Command: {cmd}", None

    try:
        r = subprocess.run(
            cmd,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=guard.timeout_sec,
            cwd=cwd,
        )
        out = (r.stdout or "") + (("\n" + r.stderr) if r.stderr else "")
        out = out[: guard.max_output_chars]
        return out, None
    except subprocess.CalledProcessError as e:
        out = (e.stdout or "") + (("\n" + e.stderr) if e.stderr else "")
        out = out[: guard.max_output_chars]
        return out or f"Command failed with returncode={getattr(e, 'returncode', '?')}", None
    except subprocess.TimeoutExpired:
        return f"Command timed out after {guard.timeout_sec} seconds", None


def _rewrite_python_and_pip(cmd: str) -> str:
    """Ensure pip installs and python runs happen in the same environment.

    Why this exists:
    - LLMs often emit '/usr/bin/python3 ...' even when the agent is executed inside a venv.
    - That leads to: pip installs into venv, but script runs with system python (ImportError).

    Strategy:
    - Rewrite leading 'python3' or '/usr/bin/python3' (and common variants) to sys.executable.
    - Rewrite leading 'pip' / 'pip3' to: '<sys.executable> -m pip'.
    """

    c = (cmd or "").strip()
    if not c:
        return cmd

    py = shlex.quote(sys.executable)

    # If the user/LLM already uses `python -m pip`, do not rewrite.
    if re.match(r"^\s*python(\d+(\.\d+)*)?\s+-m\s+pip(\s+|$)", c):
        return cmd

    # Rewrite pip invocations.
    m = re.match(r"^\s*(?P<pip>(?:/usr/bin/)?pip3?|(?:\./)?pip3?)(?P<rest>\s+.*|$)", c)
    if m:
        rest = (m.group("rest") or "").lstrip()
        return f"{py} -m pip {rest}".rstrip()

    # Rewrite python invocations.
    m = re.match(r"^\s*(?P<py>(?:/usr/bin/)?python3|python3|python)(?P<rest>\s+.*|$)", c)
    if m:
        rest = (m.group("rest") or "").lstrip()
        return f"{py} {rest}".rstrip()

    return cmd


def main():
    config = load_config(CONFIG_PATH, expand_env=False)

    recon_cfg = get_runtime_section(config, "recon") or {}
    exec_cfg = get_runtime_section(config, "execution") or {}

    target_ip = (recon_cfg.get("target_ip") or exec_cfg.get("target_ip") or "").strip()

    topic = (recon_cfg.get("current_topic") or exec_cfg.get("current_topic") or "default_topic").strip()

    # Prefer multi-track DAG plan if present
    dag_path, dag = _load_plan_dag_for_topic(topic)

    plan_path, plan = _load_plan_for_topic(topic)
    if (not dag) and (not plan):
        print(f"[Execution] No plan found for topic={topic}. Looked under data/threads/<topic>/plan*.json")
        return

    model_name = exec_cfg.get("model", "openai")
    llm = get_model(model_name)
    if llm is None:
        raise RuntimeError(
            f"Model init failed (got None). Check runtime.execution.model='{model_name}' "
            f"and your .env (OPENAI_API_KEY or other provider credentials)."
        )

    guard = ExecGuard(
        enable_autorun=bool(exec_cfg.get("enable_autorun", False)),
        allowed_cmd_regex=list(exec_cfg.get("allowed_cmd_regex", []) or []),
        denied_cmd_regex=list(exec_cfg.get("denied_cmd_regex", []) or []),
        timeout_sec=int(exec_cfg.get("command_timeout_sec", 60)),
        max_output_chars=int(exec_cfg.get("max_output_chars", 20000)),
        block_chaining=True,
        allow_pipes=bool(exec_cfg.get("allow_pipes", False)),
    )

    allowlist = _compile_patterns(guard.allowed_cmd_regex)
    denylist = _compile_patterns(guard.denied_cmd_regex)

    history = InMemoryChatMessageHistory()

    # Strengthen guidance so LLM produces better multi-step lists
    guidance = {
        "rules": [
            "Return ONLY valid JSON (no markdown).",
            "Field 'executable' MUST be either a string command or a list of string commands.",
            "Do NOT use '&&' or ';' to chain commands. If you need multiple steps, use a list.",
            "Prefer using local paths already present in the plan entry, if any.",
            "If you need to clone, use a repo URL that appears in the plan entry. If none exists, set executable to 'None' and explain.",
            "When running python or installing Python deps, prefer: python ... and python -m pip ... (do NOT hardcode /usr/bin/python3).",
            "If executing Go commands, cd into the directory containing the .go file first, and ensure a go.mod exists (go mod init <module> + go mod tidy).",
        ]
    }

    # -----------------------------
    # DAG mode (multi-track) OR legacy mode (top1)
    # -----------------------------

    if isinstance(dag, dict) and isinstance(dag.get("actions"), list) and dag.get("actions"):
        print(f"[Execution] Using DAG plan: {dag_path}")

        # Seed evidence set from recon artifact (if available)
        recon_mem_dir = (get_runtime_section(config, "recon") or {}).get("memory_dir")
        art = load_recon_artifact(PROJECT_ROOT, topic, memory_dir=recon_mem_dir)
        analysis = art.get("analysis") if isinstance(art, dict) else None
        if not isinstance(analysis, dict):
            fa = art.get("final_ai_message_json") if isinstance(art, dict) else None
            if isinstance(fa, dict) and isinstance(fa.get("analysis"), dict):
                analysis = fa.get("analysis")
        analysis = analysis if isinstance(analysis, dict) else {}

        evidence = set()
        meta = analysis.get("meta") if isinstance(analysis, dict) else None
        if isinstance(meta, dict) and isinstance(meta.get("evidence_keys"), list):
            evidence = set(str(x) for x in meta.get("evidence_keys") if str(x))
        # Derive common evidence keys
        if analysis.get("ports"):
            evidence.add("net.services")
        if (analysis.get("web") or {}).get("base_urls"):
            evidence.add("web.base_urls")

        cred_store: List[Dict[str, Any]] = []
        session_store: Dict[str, List[Dict[str, Any]]] = {}
        findings: List[Dict[str, Any]] = []
        done_ids: set = set()

        # -----------------------------
        # Deterministic (non-LLM) actions
        # -----------------------------
        det_enabled = bool(exec_cfg.get("deterministic_enable", True))
        det_actions = exec_cfg.get("deterministic_actions")
        if not isinstance(det_actions, list):
            det_actions = ["WEB_HUNT_CREDS", "TRY_SSH"]
        det_actions_set = {str(x).strip().upper() for x in det_actions if str(x).strip()}
        if not det_enabled:
            det_actions_set = set()

        web_obj = analysis.get("web") if isinstance(analysis, dict) else None
        base_urls: List[str] = []
        if isinstance(web_obj, dict) and isinstance(web_obj.get("base_urls"), list):
            base_urls = [str(x).strip() for x in web_obj.get("base_urls") if str(x).strip()]

        cwd: Optional[str] = None
        max_actions = int(exec_cfg.get("max_actions", 12) or 12)
        action_retries = int(exec_cfg.get("action_retries", 1) or 1)

        for _ in range(max_actions):
            action = _select_next_action(dag, done_ids, evidence, cred_store, session_store)
            if not action:
                break

            # If the action is supported deterministically, run it and skip LLM.
            handled = _run_deterministic_action(
                action=action,
                topic=topic,
                target_ip=target_ip,
                base_urls=base_urls,
                cred_store=cred_store,
                session_store=session_store,
                findings=findings,
                guard=guard,
                allowlist=allowlist,
                denylist=denylist,
                history=history,
                deterministic_allow=det_actions_set,
            )
            if handled:
                done_ids.add(str(action.get("id")))
                time.sleep(0.15)
                continue

            # Prompt the LLM to propose commands for this action, with awareness of stores
            history.add_message(
                HumanMessage(
                    content=(
                        "You are an execution agent running a multi-track attack DAG.\n"
                        "You MUST ground actions in real command outputs.\n"
                        "Return ONLY valid JSON (no markdown).\n\n"
                        "Current stores:\n"
                        f"credentials={json.dumps(cred_store, ensure_ascii=False)[:3000]}\n"
                        f"sessions={json.dumps(session_store, ensure_ascii=False)[:3000]}\n\n"
                        "Current action (JSON):\n"
                        f"{json.dumps(action, indent=2, ensure_ascii=False)}\n\n"
                        "Guidance:\n"
                        f"{json.dumps(guidance, indent=2)}\n\n"
                        "Return JSON with fields:\n"
                        "  analysis: string\n"
                        "  next_step: string\n"
                        "  executable: string | list[string] | 'None'\n"
                        "  expected: {credentials?: list, sessions?: list, findings?: list} (optional)\n"
                    )
                )
            )

            last_obj: Optional[Dict[str, Any]] = None
            for attempt in range(max(1, action_retries) + 1):
                resp = llm.invoke(history.messages, timeout=30)
                text = getattr(resp, "content", str(resp))
                obj = _extract_json(text)
                if not obj:
                    history.add_message(AIMessage(content=text))
                    history.add_message(HumanMessage(content="Your previous response is not valid JSON. Return ONLY valid JSON now."))
                    continue

                last_obj = obj
                print(json.dumps(obj, indent=2, ensure_ascii=False))
                history.add_message(AIMessage(content=json.dumps(obj, ensure_ascii=False)))

                cmds = _normalize_executable(obj.get("executable"))
                if not cmds:
                    break

                # Execute proposed commands
                combined_out = ""
                for raw_cmd in cmds:
                    cmd = raw_cmd

                    if _is_go_cmd(cmd):
                        go_dir = _find_go_file_dir(cmd, cwd)
                        if go_dir and os.path.isdir(go_dir):
                            cwd = go_dir
                        cmd = _rewrite_go_mod_init_if_missing_path(cmd, cwd)
                        if cwd and os.path.isdir(cwd):
                            _ensure_go_module(guard, allowlist, denylist, cwd, history)

                    out, new_cwd = _run_shell(guard, allowlist, denylist, cmd, cwd=cwd)
                    print("[Command]\n", cmd)
                    print("[Command Output]\n", out)
                    combined_out += "\n" + out

                    if new_cwd:
                        cwd = new_cwd

                    history.add_message(HumanMessage(content=f"Command: {cmd}\nOutput:\n{out}"))

                    # Minimal session inference for SSH attempts
                    if action.get("type") == "TRY_SSH" and _looks_like_ssh_success(out):
                        session_store.setdefault("ssh", []).append({"at": _now_iso(), "detail": "ssh_login_success"})

                # Extract credentials opportunistically from command output
                new_creds = _extract_credentials_from_text(combined_out)
                if new_creds:
                    for c in new_creds:
                        c["at"] = _now_iso()
                    # de-dup against store
                    existing = {(x.get("username"), x.get("secret"), x.get("type")) for x in cred_store}
                    for c in new_creds:
                        k = (c.get("username"), c.get("secret"), c.get("type"))
                        if k not in existing:
                            cred_store.append(c)
                            existing.add(k)

                # Accept LLM-provided expected updates as *hints* (no blind trust)
                exp = obj.get("expected") if isinstance(obj, dict) else None
                if isinstance(exp, dict):
                    # Optional: allow LLM to propose *structured* store updates,
                    # but keep it bounded and defensive.
                    if isinstance(exp.get("credentials"), list):
                        for c in exp.get("credentials")[:10]:
                            if not isinstance(c, dict):
                                continue
                            u = str(c.get("username") or "").strip()
                            s = str(c.get("secret") or "").strip()
                            if not u or not s:
                                continue
                            cand = {"username": u, "secret": s, "type": str(c.get("type") or "password"), "source": "llm_expected", "at": _now_iso()}
                            k = (cand.get("username"), cand.get("secret"), cand.get("type"))
                            existing = {(x.get("username"), x.get("secret"), x.get("type")) for x in cred_store}
                            if k not in existing:
                                cred_store.append(cand)

                    if isinstance(exp.get("sessions"), list):
                        for s in exp.get("sessions")[:10]:
                            if not isinstance(s, dict):
                                continue
                            kind = str(s.get("kind") or "").strip().lower()
                            if not kind:
                                continue
                            rec = dict(s)
                            rec.setdefault("at", _now_iso())
                            session_store.setdefault(kind, []).append(rec)

                    if isinstance(exp.get("findings"), list):
                        for fnd in exp.get("findings"):
                            if isinstance(fnd, dict):
                                fnd.setdefault("at", _now_iso())
                                findings.append(fnd)

                # Mark action done after one execution cycle
                done_ids.add(str(action.get("id")))
                break

            time.sleep(0.25)

        # Persist execution state for debugging / thesis artifacts
        try:
            safe = _safe_topic(topic)
            out_dir = os.path.join(PROJECT_ROOT, "data", "threads", safe)
            os.makedirs(out_dir, exist_ok=True)
            state_path = os.path.join(out_dir, "execution_state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "topic": topic,
                        "captured_at": _now_iso(),
                        "done_actions": sorted(list(done_ids)),
                        "credentials": cred_store,
                        "sessions": session_store,
                        "findings": findings,
                    },
                    f,
                    indent=2,
                    ensure_ascii=False,
                )
            print(f"[Execution] Wrote execution_state.json to {state_path}")
        except Exception as e:
            logger.warning("Failed to write execution_state.json: %s", e)

        return

    # -----------------------------
    # Legacy mode: pick top1 plan entry
    # -----------------------------

    best = _pick_best_entry(plan)
    if not best:
        print(f"[Execution] Plan is empty or malformed: {plan_path}")
        return

    history.add_message(
        HumanMessage(
            content=(
                "You are an execution agent.\n"
                "Here is the selected exploit plan entry (JSON):\n"
                f"{json.dumps(best, indent=2, ensure_ascii=False)}\n\n"
                "Guidance:\n"
                f"{json.dumps(guidance, indent=2)}\n\n"
                "Now generate the next action.\n"
                "Return JSON with fields: analysis (string), next_step (string), executable (string or list of strings or 'None')."
            )
        )
    )

    max_steps = int(exec_cfg.get("max_steps", 8) or 8)
    cwd: Optional[str] = None

    for _ in range(max_steps):
        resp = llm.invoke(history.messages, timeout=30)
        text = getattr(resp, "content", str(resp))

        obj = _extract_json(text)
        if not obj:
            history.add_message(AIMessage(content=text))
            history.add_message(HumanMessage(content="Your previous response is not valid JSON. Return ONLY valid JSON now."))
            print("[WARN] LLM returned non-JSON. Retrying.")
            continue

        print(json.dumps(obj, indent=2, ensure_ascii=False))
        history.add_message(AIMessage(content=json.dumps(obj, ensure_ascii=False)))

        cmds = _normalize_executable(obj.get("executable"))
        if not cmds:
            break

        for raw_cmd in cmds:
            cmd = raw_cmd

            # (B1) If command is Go-related and references a .go file, auto-adjust cwd to that file's directory
            if _is_go_cmd(cmd):
                go_dir = _find_go_file_dir(cmd, cwd)
                if go_dir and os.path.isdir(go_dir):
                    cwd = go_dir

            # (B2) If LLM outputs "go mod init" without module path, rewrite it
            if _is_go_cmd(cmd):
                cmd = _rewrite_go_mod_init_if_missing_path(cmd, cwd)

            # (B3) Proactive: if Go command and cwd has no go.mod, auto create it before running
            if _is_go_cmd(cmd) and cwd and os.path.isdir(cwd):
                _ensure_go_module(guard, allowlist, denylist, cwd, history)

            out, new_cwd = _run_shell(
                guard=guard,
                allowlist=allowlist,
                denylist=denylist,
                cmd=cmd,
                cwd=cwd,
            )

            print("[Command]\n", cmd)
            print("[Command Output]\n", out)

            if new_cwd:
                cwd = new_cwd

            history.add_message(HumanMessage(content=f"Command: {cmd}\nOutput:\n{out}"))

            # (B4) Reactive recovery: if Go build fails due to module issue, auto-init module + retry once
            if _is_go_cmd(cmd) and ("cannot find main module" in out or "go: cannot find main module" in out):
                if cwd and os.path.isdir(cwd):
                    _ensure_go_module(guard, allowlist, denylist, cwd, history)
                    retry_out, _ = _run_shell(
                        guard=guard,
                        allowlist=allowlist,
                        denylist=denylist,
                        cmd=cmd,
                        cwd=cwd,
                    )
                    print("[AUTO-RETRY]\n", cmd)
                    print("[AUTO-RETRY OUTPUT]\n", retry_out)
                    history.add_message(HumanMessage(content=f"[AUTO-RETRY] Command: {cmd}\nOutput:\n{retry_out}"))

        time.sleep(0.5)


if __name__ == "__main__":
    main()


