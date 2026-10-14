"""Stage 18 isolated legacy-watcher migration/rollback REHEARSAL only.

Creates FIXED PUBLIC, fictional v1 tasks in an empty disposable OS-temp lab,
copies only those synthetic state files into a separately isolated candidate,
imports into the existing v2 ledger, checks nonce rotation/replay refusal,
then restores the untouched backup into yet another disposable directory.

NEVER accepts a real state directory, repository, arbitrary task or command;
does not stop a process, install software, start the watcher, or activate a
real v2 marker. Markers exist ONLY within the disposable synthetic lab.
Passing this rehearsal is NOT migration approval or proof of v1 quiescence.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import secrets
import shutil
import stat
import tempfile

from .ledger import RelayLedger
from .ledger_v2 import RelayLedgerV2
from .v3_migration_risk_audit import audit_migration_risks
from .v3_policy import PolicyBlocked

FILES = ("nonce.txt", "seen_tasks.jsonl")
TASKS = (("stage18-public-a", "A"*64), ("stage18-public-b", "B"*64))
INJECTIONS = frozenset({"none", "after_backup", "after_v2_import", "after_marker"})


def _ordinary(path: Path, *, directory: bool = False) -> bool:
    try:
        m = path.lstat()
    except FileNotFoundError:
        return False
    if (stat.S_ISLNK(m.st_mode) or getattr(m, "st_file_attributes", 0) & 0x400):
        raise PolicyBlocked("synthetic rehearsal path redirected")
    if directory and not stat.S_ISDIR(m.st_mode):
        raise PolicyBlocked("synthetic rehearsal directory type invalid")
    if not directory and not stat.S_ISREG(m.st_mode):
        raise PolicyBlocked("synthetic rehearsal file type invalid")
    return True


def _root(root: str | Path) -> Path:
    supplied = Path(root).expanduser()
    if not supplied.name.startswith("upab-v3-lab-"):
        raise PolicyBlocked("rehearsal requires disposable lab naming")
    if not _ordinary(supplied, directory=True):
        raise PolicyBlocked("rehearsal requires existing ordinary lab directory")
    canonical = supplied.resolve(strict=True)
    if (canonical.name != supplied.name or
            canonical.parent != Path(tempfile.gettempdir()).resolve()):
        raise PolicyBlocked("rehearsal must use direct child of OS temp")
    if any(canonical.iterdir()):
        raise PolicyBlocked("rehearsal refuses to modify nonempty test root")
    return canonical


def _sha256(path: Path) -> str:
    if not _ordinary(path) or path.stat().st_size > 8 * 1024 * 1024:
        raise PolicyBlocked("unexpected synthetic fixture state file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _copy_whitelist(src: Path, dst: Path) -> dict[str, str]:
    if dst.exists():
        raise PolicyBlocked("rehearsal destination already exists")
    if not _ordinary(src, directory=True):
        raise PolicyBlocked("synthetic source is not ordinary")
    dst.mkdir(parents=True, exist_ok=False)
    hashes: dict[str, str] = {}
    for name in FILES:
        path = src / name
        digest = _sha256(path)
        shutil.copyfile(path, dst / name)
        if _sha256(dst / name) != digest:
            raise PolicyBlocked("synthetic backup integrity failed")
        hashes[name] = digest
    return hashes


def _report(phase: str, *, backups_verified: bool, replay_checked: bool,
            restored_verified: bool, simulated_interruption: bool) -> dict[str, object]:
    return {
        "schema": "upab.watcher-v3.disposable-migration-rehearsal.v1",
        "status": phase,
        "fixture_only": True,
        "synthetic_fixture_task_count": len(TASKS),
        "backup_checksums_match": backups_verified,
        "candidate_v2_import_replay_checked": replay_checked,
        "separate_restored_copy_verified": restored_verified,
        "injected_interruption": simulated_interruption,
        "actual_v1_stopped_and_verified": False,
        "migration_authorized": False,
        "real_activation_marker_written": False,
        "real_files_changed": False,
        "actual_repositories_accessed": False,
        "real_task_execution_allowed": False,
        "real_rollback_performed": False,
    }


def rehearse_disposable_migration(
    root: str | Path, *, inject_at: str = "none"
) -> dict[str, object]:
    """One-off disposable fixture. No repair or resumption of interrupted runs."""
    if type(inject_at) is not str or inject_at not in INJECTIONS:
        raise PolicyBlocked("invalid synthetic migration interruption selector")
    lab = _root(root)
    original = lab / "source"
    original.mkdir()
    v1 = RelayLedger(original)
    for tid, digest in TASKS:
        v1.consume(tid, digest, v1.current_nonce())
    v1_nonce = v1.current_nonce()
    source_relay = original / "relay"
    before = {name: _sha256(source_relay / name) for name in FILES}
    source_audit = audit_migration_risks(original)
    if (source_audit["legacy_record_count"] != len(TASKS)
            or source_audit["migration_allowed"]):
        raise PolicyBlocked("synthetic source audit mismatch")
    backup_relay = lab / "backup" / "relay"
    backup_relay.parent.mkdir()
    backup = _copy_whitelist(source_relay, backup_relay)
    if backup != before:
        raise PolicyBlocked("backup snapshot mismatch")
    if inject_at == "after_backup":
        return _report("SIMULATED_INTERRUPTED_AFTER_BACKUP",
                       backups_verified=True, replay_checked=False,
                       restored_verified=False, simulated_interruption=True)

    candidate_relay = lab / "candidate" / "relay"
    candidate_relay.parent.mkdir()
    candidate_files = _copy_whitelist(backup_relay, candidate_relay)
    if candidate_files != backup:
        raise PolicyBlocked("candidate snapshot differs from backup")
    new_ledger = RelayLedgerV2(candidate_relay.parent)
    nonce_v2 = new_ledger.current_nonce()
    if not nonce_v2 or nonce_v2 == v1_nonce:
        raise PolicyBlocked("synthetic migration failed to rotate nonce")
    for tid, digest in TASKS:
        if not new_ledger.has_seen(tid):
            raise PolicyBlocked("legacy replay record not imported")
        try:
            new_ledger.consume(tid, digest, nonce_v2)
        except ValueError:
            pass
        else:
            raise PolicyBlocked("replay unexpectedly accepted by v2 candidate")
    candidate_audit = audit_migration_risks(candidate_relay.parent)
    if (candidate_audit["missing_legacy_records_in_v2"] != 0
            or candidate_audit["migration_allowed"]):
        raise PolicyBlocked("candidate audit did not deny migration")
    if inject_at == "after_v2_import":
        return _report("SIMULATED_INTERRUPTED_AFTER_V2_IMPORT",
                       backups_verified=True, replay_checked=True,
                       restored_verified=False, simulated_interruption=True)

    # Marker tests ONLY the copied candidate state, never the original.
    (candidate_relay / "v2_active.marker").write_text(
        "DISPOSABLE-FIXTURE-ONLY\n", encoding="ascii"
    )
    try:
        RelayLedger(candidate_relay.parent)
    except RuntimeError as exc:
        if "legacy relay v1 disabled" not in str(exc):
            raise
    else:
        raise PolicyBlocked("candidate v1 did not respect synthetic marker")
    if inject_at == "after_marker":
        return _report("SIMULATED_INTERRUPTED_AFTER_MARKER",
                       backups_verified=True, replay_checked=True,
                       restored_verified=False, simulated_interruption=True)

    restored_relay = lab / "restored" / "relay"
    restored_relay.parent.mkdir()
    restored = _copy_whitelist(backup_relay, restored_relay)
    restored_ledger = RelayLedger(restored_relay.parent)
    if (restored != before or restored_ledger.current_nonce() != v1_nonce
            or restored_ledger.seen_task_ids() != {tid for tid, _ in TASKS}):
        raise PolicyBlocked("synthetic rollback did not reproduce backup state")
    if {name: _sha256(source_relay / name) for name in FILES} != before:
        raise PolicyBlocked("original synthetic fixture was modified")
    if {name: _sha256(backup_relay / name) for name in FILES} != before:
        raise PolicyBlocked("synthetic source backup was modified")
    return _report("DISPOSABLE_REHEARSAL_COMPLETE_NO_ACTIVATION",
                   backups_verified=True, replay_checked=True,
                   restored_verified=True, simulated_interruption=False)
