"""
Assignment 11 — Correlated, redacted audit log.

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Correlate an input with its eventual decision; redact logged content."""
        from guardrails.output_guardrails import content_filter
        key = request_id or user_id
        if key in self._open:
            raise ValueError("An unfinished audit request already uses this ID.")
        self._open[key] = {
            "request_id": key, "user_id": user_id,
            "input": content_filter(text)["redacted"],
            "started_at": utc_now_iso(), "_timer": time.monotonic(),
        }

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
        redacted: bool = False,
    ):
        """Complete exactly the matching request, including blocked requests."""
        from guardrails.output_guardrails import content_filter
        key = request_id or user_id
        if key not in self._open or self._open[key]["user_id"] != user_id:
            raise ValueError("No matching input for this audit output.")
        row = self._open.pop(key)
        timer = row.pop("_timer")
        row.update(output=content_filter(text)["redacted"], blocked=bool(blocked), redacted=bool(redacted),
                   layer=layer, finished_at=utc_now_iso(),
                   latency_ms=round((time.monotonic() - timer) * 1000, 3))
        self.logs.append(row)

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8")
        return path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
