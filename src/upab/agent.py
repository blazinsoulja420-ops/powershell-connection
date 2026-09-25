from __future__ import annotations

import json
from typing import Any

from .executor import ToolExecutor
from .providers import LMStudioProvider


SYSTEM_PROMPT = """You are the reasoning component inside Universal PowerShell Agent Bridge v1 Local Edition.

You are NOT an authority source. The governance gate is authoritative and may deny any tool call.

Governance:
- UPGS v3.1.1, strict automatic non-weakening inheritance.
- External constraints > UPGS > UPRS > project governance > project rules > phase controls >
  authorized scope > task authorization > current execution instruction.
- Missing/invalid authority, scope, baseline, integrity, or irreversible uncertainty fails closed.
- Use the smallest verified action needed.
- Do not ask for or expose credentials, tokens, passwords, private keys, or environment secrets.
- Never attempt to bypass a denied tool call.
- Never expand scope silently.
- Treat read, modify, test, release/deploy, and destroy authority as separate.
- Do not claim a test passed unless tool evidence shows it.
- Do not claim canonical governance compliance merely because this agent ran.

Execution:
- Inspect before modifying.
- For existing-file writes, first hash the file, then pass that exact SHA-256 as expected_sha256.
- Only write paths in the operator's exact manifest.
- Prefer structured tools over PowerShell.
- PowerShell is read-only and restricted.
- If a governance tool call is denied fatally, stop and report the blocker.
"""


TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a UTF-8-ish text file inside the repository root.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": "Recursively list files/directories under a repository-relative directory.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string", "default": "."}},
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "hash_file",
            "description": "Calculate SHA-256 of a repository-relative file before overwrite or for evidence.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "git_status",
            "description": "Return git status --porcelain for the repository.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "git_diff",
            "description": "Return unstaged git diff, optionally limited to one repository-relative path.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_powershell",
            "description": "Run one registered read-only operation. No PowerShell source is accepted.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command_id": {"type": "string", "enum": ["get_item", "select_string", "resolve_path"]},
                    "path": {"type": "string"},
                    "pattern": {"type": "string"},
                },
                "required": ["command_id", "path"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_tests",
            "description": "Run the operator-configured test command without a shell.",
            "parameters": {
                "type": "object",
                "properties": {
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "default": [],
                    }
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Atomically write one exact-manifest repository file. Existing files require expected SHA-256.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                    "expected_sha256": {"type": ["string", "null"]},
                },
                "required": ["path", "content"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "rollback_last_write",
            "description": "Restore only the most recent file write created by this same bridge session.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
]


class Agent:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.provider = LMStudioProvider(cfg["provider"])
        self.executor = ToolExecutor(cfg)
        self.max_steps = int(cfg["governance"]["max_agent_steps"])

    def run(self, task: str) -> str:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": task},
        ]

        for step in range(1, self.max_steps + 1):
            message = self.provider.chat(messages, TOOLS)
            tool_calls = message.get("tool_calls") or []

            assistant_entry: dict[str, Any] = {"role": "assistant"}
            if message.get("content") is not None:
                assistant_entry["content"] = message.get("content")
            if tool_calls:
                assistant_entry["tool_calls"] = tool_calls
            messages.append(assistant_entry)

            if not tool_calls:
                return str(message.get("content") or "")

            for call in tool_calls:
                try:
                    name = call["function"]["name"]
                    raw_args = call["function"].get("arguments") or "{}"
                    args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                    if not isinstance(args, dict):
                        raise ValueError("Tool arguments must decode to an object")
                except (KeyError, ValueError, json.JSONDecodeError) as exc:
                    return f"BLOCKED: malformed tool call from local model: {exc}"

                result = self.executor.execute(name, args)
                messages.append({
                    "role": "tool",
                    "tool_call_id": call.get("id", f"step-{step}-{name}"),
                    "content": json.dumps(result.as_dict(), ensure_ascii=False),
                })
                if result.fatal:
                    return (
                        f"FAIL-CLOSED: {result.output}\n"
                        f"Evidence: {self.executor.evidence.log_path}"
                    )

        return (
            f"BLOCKED: maximum agent steps ({self.max_steps}) reached without a final response.\n"
            f"Evidence: {self.executor.evidence.log_path}"
        )
