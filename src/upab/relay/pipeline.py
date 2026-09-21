from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..executor import ToolExecutor
from ..security import redact
from .ledger import RelayLedger
from .schema import RESULT_SCHEMA, RelayValidationError, task_sha256, validate_task


class ExactRelayPipeline:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.relay_cfg = cfg["exact_relay"]
        self.ledger = RelayLedger(cfg["state"]["directory"])

    def current_nonce(self) -> str:
        return self.ledger.current_nonce()

    def _base_result(self, task_id: str | None, digest: str | None) -> dict[str, Any]:
        return {
            "schema": RESULT_SCHEMA,
            "task_id": task_id,
            "task_sha256": digest,
            "status": "BLOCKED",
            "started_at_utc": datetime.now(timezone.utc).isoformat(),
            "finished_at_utc": None,
            "repository": {
                "root": self.cfg["repository"]["root"],
                "head_before": None,
                "head_after": None,
            },
            "operations": [],
            "rollback": None,
            "evidence_log": None,
            "next_relay_nonce": self.ledger.current_nonce(),
            "message": None,
        }

    def execute_task(self, raw_task: dict[str, Any]) -> dict[str, Any]:
        digest = task_sha256(raw_task)
        task_id = raw_task.get("task_id") if isinstance(raw_task, dict) else None
        result = self._base_result(task_id, digest)

        try:
            task = validate_task(raw_task, self.cfg, self.ledger.current_nonce())
        except RelayValidationError as exc:
            result["message"] = f"VALIDATION_BLOCKED: {exc}"
            result["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
            return result

        if task["task_id"] in self.ledger.seen_task_ids():
            result["message"] = f"REPLAY_BLOCKED: task_id already consumed: {task['task_id']}"
            result["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
            return result

        try:
            executor = ToolExecutor(self.cfg)
        except Exception as exc:
            result["message"] = f"EXECUTOR_INIT_BLOCKED: {type(exc).__name__}: {exc}"
            result["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
            return result

        result["evidence_log"] = str(executor.evidence.log_path)
        if executor.git.is_git:
            result["repository"]["head_before"] = executor.git.current_head()

        supplied_head = task["repository"].get("expected_head")
        if supplied_head and executor.git.is_git and executor.git.current_head().lower() != supplied_head.lower():
            result["message"] = (
                "BASELINE_BLOCKED: task expected HEAD " + supplied_head +
                " but live HEAD is " + executor.git.current_head()
            )
            result["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
            return result

        if task["mode"] == "mutation":
            ok, reason = executor.gate.mutation_authority_status()
            if not ok:
                result["message"] = "MUTATION_BLOCKED: " + reason
                result["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
                return result

        try:
            next_nonce = self.ledger.consume(task["task_id"], digest, task["relay_nonce"])
        except ValueError as exc:
            result["message"] = f"CONSUME_BLOCKED: {exc}"
            result["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
            return result
        result["next_relay_nonce"] = next_nonce

        executor.evidence.append({
            "event": "exact_relay_task_accepted",
            "task_id": task["task_id"],
            "task_sha256": digest,
            "mode": task["mode"],
            "operation_count": len(task["operations"]),
        })

        failure = False
        fatal_failure = False
        for item in task["operations"]:
            op_id = item["operation_id"]
            op = item["op"]
            args = item["args"]
            tool_result = executor.execute(op, args)
            result["operations"].append({
                "operation_id": op_id,
                "op": op,
                "ok": tool_result.ok,
                "fatal": tool_result.fatal,
                "output": redact(tool_result.output, int(self.cfg["governance"]["max_output_chars"])),
                "metadata": tool_result.metadata,
            })
            if not tool_result.ok:
                failure = True
                fatal_failure = fatal_failure or tool_result.fatal
                if task["stop_on_failure"] or tool_result.fatal:
                    break

        if failure and task["rollback_on_failure"] and executor.write_history:
            rollback = executor.rollback_all_session_writes()
            result["rollback"] = rollback.as_dict()
            if not rollback.ok:
                fatal_failure = True
        elif failure:
            result["rollback"] = {"ok": True, "output": "ROLLBACK_NOT_REQUESTED_OR_NO_WRITES", "metadata": {}, "fatal": False}

        try:
            executor.git.assert_head_unchanged()
            executor.git.assert_no_unexpected_changes()
        except Exception as exc:
            failure = True
            fatal_failure = True
            result["message"] = f"FINAL_GUARD_FAIL: {type(exc).__name__}: {exc}"

        if executor.git.is_git:
            result["repository"]["head_after"] = executor.git.current_head()

        if not failure:
            result["status"] = "PASS"
            result["message"] = "Exact Relay task completed successfully"
        elif fatal_failure:
            result["status"] = "FAIL_CLOSED"
            if not result["message"]:
                result["message"] = "Task stopped on a fatal fail-closed condition"
        else:
            result["status"] = "FAIL"
            if not result["message"]:
                result["message"] = "Task completed with one or more failed operations"

        result["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        executor.evidence.append({
            "event": "exact_relay_task_finished",
            "task_id": task["task_id"],
            "status": result["status"],
            "message": result["message"],
            "next_nonce": next_nonce,
        })
        self._save_result(task["task_id"], result)
        return result

    def _save_result(self, task_id: str, result: dict[str, Any]) -> Path:
        root = Path(self.cfg["state"]["directory"]).expanduser().resolve() / "relay" / "results"
        root.mkdir(parents=True, exist_ok=True)
        safe_id = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in task_id)
        path = root / f"{safe_id}.result.json"
        path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        return path
