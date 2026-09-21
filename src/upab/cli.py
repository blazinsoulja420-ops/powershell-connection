from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agent import Agent
from .config import ConfigError, load_config
from .executor import ToolExecutor
from .providers import LMStudioProvider
from .relay.clipboard import WindowsClipboard
from .relay.pipeline import ExactRelayPipeline
from .relay.schema import format_result_block, parse_task_block, RelayValidationError
from .relay.watcher import ClipboardRelayWatcher


def _load(path: str):
    try:
        return load_config(path)
    except (OSError, json.JSONDecodeError, ConfigError) as exc:
        print(f"CONFIG_FAIL: {exc}", file=sys.stderr)
        raise SystemExit(2)


def cmd_doctor(args) -> int:
    cfg = _load(args.config)
    print("UPAB_DOCTOR")
    print(f"repo={cfg['repository']['root']}")
    print(f"provider={cfg['provider']['base_url']}")
    print(f"model={cfg['provider']['model']}")
    try:
        executor = ToolExecutor(cfg)
    except Exception as exc:
        print(f"repository_gate=FAIL {type(exc).__name__}: {exc}")
        return 3

    print(f"git={'YES' if executor.git.is_git else 'NO'}")
    if executor.git.is_git:
        print(f"head={executor.git.baseline_head}")
        status = executor.git.status_text().strip()
        print("worktree=" + ("CLEAN" if not status else "DIRTY"))
        if status:
            print(status)

    ok, reason = executor.gate.canonical_binding_status()
    print(f"canonical_upgs={'PASS' if ok else 'BLOCKED'} {reason}")
    mut_ok, mut_reason = executor.gate.mutation_authority_status()
    print(f"mutation_authority={'PASS' if mut_ok else 'BLOCKED'} {mut_reason}")

    provider = LMStudioProvider(cfg["provider"])
    try:
        models = provider.list_models()
        print("lmstudio=PASS")
        print("models=" + (", ".join(models) if models else "[none reported]"))
        if cfg["provider"]["model"] not in models:
            print("configured_model=BLOCKED model id not found in LM Studio /v1/models")
            return 4
        print("configured_model=PASS")
    except Exception as exc:
        print(f"lmstudio=BLOCKED {type(exc).__name__}: {exc}")
        return 4

    return 0


def cmd_status(args) -> int:
    cfg = _load(args.config)
    try:
        executor = ToolExecutor(cfg)
    except Exception as exc:
        print(f"STATUS_FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
    print(executor.git.status_text())
    print(f"EVIDENCE={executor.evidence.log_path}")
    return 0


def cmd_verify_governance(args) -> int:
    cfg = _load(args.config)
    executor = ToolExecutor(cfg)
    ok, reason = executor.gate.canonical_binding_status()
    print(("PASS" if ok else "BLOCKED") + ": " + reason)
    return 0 if ok else 5


def cmd_run(args) -> int:
    cfg = _load(args.config)
    task = args.task
    if args.task_file:
        task = Path(args.task_file).read_text(encoding="utf-8-sig")
    if not task:
        print("RUN_FAIL: provide --task or --task-file", file=sys.stderr)
        return 2
    try:
        agent = Agent(cfg)
        print(f"SESSION={agent.executor.evidence.session_id}")
        print(f"EVIDENCE={agent.executor.evidence.log_path}")
        print(agent.run(task))
        return 0
    except KeyboardInterrupt:
        print("INTERRUPTED", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"RUN_FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 6



def cmd_relay_nonce(args) -> int:
    cfg = _load(args.config)
    pipeline = ExactRelayPipeline(cfg)
    print("UPAB_EXACT_RELAY_NONCE")
    print(f"CHANNEL={cfg['exact_relay']['channel_id']}")
    print(f"NONCE={pipeline.current_nonce()}")
    print(f"REPOSITORY={cfg['repository']['root']}")
    return 0


def cmd_relay_run(args) -> int:
    cfg = _load(args.config)
    pipeline = ExactRelayPipeline(cfg)
    if args.task_file:
        text = Path(args.task_file).read_text(encoding="utf-8-sig")
    else:
        try:
            text = WindowsClipboard().get_text()
        except Exception as exc:
            print(f"CLIPBOARD_FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 7
    try:
        task = parse_task_block(text)
    except RelayValidationError as exc:
        print(f"TASK_BLOCK_FAIL: {exc}", file=sys.stderr)
        return 8
    if task is None:
        print("TASK_BLOCK_FAIL: clipboard/file does not contain an exact relay task block", file=sys.stderr)
        return 8
    result = pipeline.execute_task(task)
    block = format_result_block(result)
    print(block)
    if args.copy_result:
        try:
            WindowsClipboard().set_text(block)
            print("RESULT_COPIED_TO_CLIPBOARD", file=sys.stderr)
        except Exception as exc:
            print(f"RESULT_COPY_FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 9
    return 0 if result["status"] == "PASS" else 10


def cmd_relay_watch(args) -> int:
    cfg = _load(args.config)
    try:
        clipboard = WindowsClipboard()
    except Exception as exc:
        print(f"CLIPBOARD_FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 7
    watcher = ClipboardRelayWatcher(cfg, clipboard)
    try:
        return watcher.watch(once=args.once)
    except KeyboardInterrupt:
        print("RELAY_STOPPED")
        return 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="upab",
        description="Universal PowerShell Agent Bridge v1.1 — Exact Relay Autopilot",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="Verify repository, governance binding, and LM Studio")
    doctor.add_argument("--config", required=True)
    doctor.set_defaults(func=cmd_doctor)

    status = sub.add_parser("status", help="Show target repository Git status")
    status.add_argument("--config", required=True)
    status.set_defaults(func=cmd_status)

    verify = sub.add_parser("verify-governance", help="Verify canonical UPGS package hash")
    verify.add_argument("--config", required=True)
    verify.set_defaults(func=cmd_verify_governance)

    run = sub.add_parser("run", help="Run a governed local-agent task")
    run.add_argument("--config", required=True)
    group = run.add_mutually_exclusive_group(required=True)
    group.add_argument("--task")
    group.add_argument("--task-file")
    run.set_defaults(func=cmd_run)

    nonce = sub.add_parser("relay-nonce", help="Show the current one-time Exact Relay nonce")
    nonce.add_argument("--config", required=True)
    nonce.set_defaults(func=cmd_relay_nonce)

    relay_run = sub.add_parser("relay-run", help="Execute one Exact Relay task from file or clipboard")
    relay_run.add_argument("--config", required=True)
    source = relay_run.add_mutually_exclusive_group(required=True)
    source.add_argument("--task-file")
    source.add_argument("--clipboard", action="store_true")
    relay_run.add_argument("--copy-result", action="store_true")
    relay_run.set_defaults(func=cmd_relay_run)

    watch = sub.add_parser("relay-watch", help="Watch Windows clipboard for exact relay task blocks")
    watch.add_argument("--config", required=True)
    watch.add_argument("--once", action="store_true")
    watch.set_defaults(func=cmd_relay_watch)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
