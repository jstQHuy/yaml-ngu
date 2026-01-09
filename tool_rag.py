"""Tool-RAG helper (docs -> retrieval -> prompt augmentation).

This module is intentionally lightweight and *optional*.

It is meant to support Recon by grounding LLM suggestions in local tool
documentation (PDF/TXT/MD cheat-sheets) so the agent proposes correct flags and
enumeration sequences.

Important: This is **not** a generic "execute whatever the LLM says" feature.
The Recon agent must still validate commands using its allow/deny policy.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class ToolRAGConfig:
    enable: bool = False
    docs_dir: str = ""
    max_chars: int = 9000
    top_k: int = 6
    # PDF parsing is often fragile in lab environments (corrupted PDFs, missing deps, noisy warnings).
    # Default is OFF to keep Recon startup fast and predictable.
    allow_pdf: bool = False
    max_pdf_pages: int = 20
    # Limit how many files are read per retrieval (prevents "index the whole library" stalls).
    max_files: int = 60
    # Only these file types are considered.
    include_exts: tuple = (".txt", ".md", ".rst", ".csv", ".yaml", ".yml", ".json")


class ToolRAG:
    """Best-effort retrieval over local docs.

    We use a conservative keyword-based retrieval over local text.

    Rationale: vector indexes (LlamaIndex + embeddings) are valuable but introduce
    failure modes (missing deps, large startup time, PDF parsing edge cases). For a
    thesis demo, stability matters more than perfect retrieval.

    If you later want vector retrieval, implement it as an *offline* build step.
    """

    def __init__(self, cfg: ToolRAGConfig) -> None:
        self.cfg = cfg
        self._docs_dir = Path(cfg.docs_dir).expanduser() if cfg.docs_dir else None
        self._text_cache: Optional[List[tuple[str, str]]] = None
        # NOTE: we intentionally avoid building vector indexes at runtime.
        # This keeps Recon deterministic and prevents "load a mountain of PDFs" delays.
        if not cfg.enable or not self._docs_dir or not self._docs_dir.exists():
            return

    def _load_text_cache(self) -> List[tuple[str, str]]:
        if self._text_cache is not None:
            return self._text_cache
        out: List[tuple[str, str]] = []
        if not self._docs_dir or not self._docs_dir.exists():
            self._text_cache = out
            return out

        # Keep extraction conservative and bounded.
        # We intentionally avoid reading an entire "library" (hundreds of PDFs) at runtime.
        include_exts = set(str(x).lower() for x in (self.cfg.include_exts or ()))
        max_files = max(1, int(self.cfg.max_files or 60))

        # Collect candidate paths first, then read only a bounded subset.
        paths: List[Path] = []
        for p in self._docs_dir.rglob("*"):
            if not p.is_file():
                continue
            suf = p.suffix.lower()
            if suf in include_exts:
                paths.append(p)
            elif suf == ".pdf" and bool(self.cfg.allow_pdf):
                paths.append(p)

        # Prefer small, text-first files.
        def _rank_path(x: Path) -> tuple:
            suf = x.suffix.lower()
            is_pdf = 1 if suf == ".pdf" else 0
            try:
                sz = x.stat().st_size
            except Exception:
                sz = 10**9
            return (is_pdf, sz, str(x))

        paths.sort(key=_rank_path)
        paths = paths[:max_files]

        for p in paths:
            suf = p.suffix.lower()
            if suf in include_exts:
                try:
                    out.append((str(p), p.read_text(encoding="utf-8", errors="ignore")))
                except Exception:
                    continue
            elif suf == ".pdf" and bool(self.cfg.allow_pdf):
                # Optional: PDF extraction is best-effort and commonly fails on malformed PDFs.
                try:
                    import PyPDF2  # type: ignore

                    with p.open("rb") as f:
                        reader = PyPDF2.PdfReader(f, strict=False)
                        chunks = []
                        for page in reader.pages[: max(1, int(self.cfg.max_pdf_pages))]:
                            try:
                                t = page.extract_text() or ""
                            except Exception:
                                t = ""
                            if t:
                                chunks.append(t)
                        if chunks:
                            out.append((str(p), "\n".join(chunks)))
                except Exception:
                    continue

        self._text_cache = out
        return out

    def retrieve(self, query: str) -> str:
        """Return a compact context string relevant to `query`."""
        if not self.cfg.enable:
            return ""
        q = (query or "").strip()
        if not q:
            return ""

        # Keyword fallback
        docs = self._load_text_cache()
        if not docs:
            return ""

        tokens = [t for t in re.split(r"\W+", q.lower()) if len(t) >= 3][:12]
        if not tokens:
            return ""

        scored: List[tuple[int, str, str]] = []
        for path, text in docs:
            low = text.lower()
            score = sum(low.count(tok) for tok in tokens)
            if score <= 0:
                continue
            scored.append((score, path, text))
        scored.sort(reverse=True, key=lambda x: x[0])

        parts: List[str] = []
        for _, path, text in scored[: max(1, int(self.cfg.top_k))]:
            # Take the first ~1200 chars plus the most relevant lines if possible.
            snippet = text[:2000]
            parts.append(f"[DOC] {os.path.basename(path)}\n{snippet}")
        return "\n\n".join(parts)[: self.cfg.max_chars]

