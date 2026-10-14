"""Stage 38: disposable, SYNTHETIC health replay ledger; NO operational authority.

The witness is a shared in-memory TEST DOUBLE, not a TPM, protected counter,
owner-approved registry, cross-process lock, or independent provenance root.
Do not run this as a service, monitor, enrollment API or production defense.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import threading
import uuid

from .v3_policy import PolicyBlocked
from .v3_portfolio_health_rollup import MAX_EPOCH, MAX_OBSERVATIONS
from .v3_portfolio_review import PROJECTS, POINDEXTER_MODULES
from .v3_signed_health_evidence_review import HEX64, review_signed_health_batch

SCHEMA = "upab.watcher-v3.synthetic-health-ledger.v1"
RECEIPT = "upab.watcher-v3.synthetic-health-ledger-receipt.v1"
_VALID_ID = re.compile(r"[A-Za-z0-9._:-]{1,64}\Z")


class SimulatedInterruption(RuntimeError):
    """Test-only interruption of a known durability boundary."""


class FakeMonotonicWitness:
    """Process-local fake anchor. NEVER treat as rollback-resistant."""

    def __init__(self):
        self._lock = threading.Lock()
        self._identity = None
        self._epoch = 0
        self.fail_next_advance = False

    def snapshot(self):
        with self._lock:
            return self._identity, self._epoch

    def bind_new_fixture(self, identity):
        with self._lock:
            if self._identity is not None or self._epoch:
                raise PolicyBlocked("synthetic witness already bound")
            self._identity = identity

    def advance(self, *, identity, expected_epoch):
        with self._lock:
            if self.fail_next_advance:
                self.fail_next_advance = False
                raise PolicyBlocked("synthetic witness advance failed")
            if self._identity != identity or self._epoch != expected_epoch:
                raise PolicyBlocked("synthetic witness mismatch")
            self._epoch += 1
            return self._epoch


def _valid_epoch(value):
    return type(value) is int and 0 <= value <= MAX_EPOCH


def _scope(repo, module):
    if type(repo) is not str or repo not in PROJECTS:
        raise PolicyBlocked("unselected collector scope")
    if module is not None and (
        repo != "UP-UHAIB-001-Poindexter" or type(module) is not str
        or module not in {m for m, _ in POINDEXTER_MODULES}
    ):
        raise PolicyBlocked("invalid nested collector scope")
    return repo + ":" + ("-" if module is None else module)


def _check(path, *, directory=False):
    try:
        st = path.lstat()
    except FileNotFoundError:
        return
    if (stat.S_ISLNK(st.st_mode)
            or getattr(st, "st_file_attributes", 0) & 0x400
            or not (stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode))):
        raise PolicyBlocked("synthetic storage path is unsafe")


def _receipt(status, *, accepted=0, quarantined=0, interrupted=0):
    return {
        "schema": RECEIPT, "status": status, "accepted_count": accepted,
        "quarantined_count": quarantined, "interrupted_count": interrupted,
        "trusted_collector_authenticated": False,
        "rollback_resistance_verified": False,
        "hardware_monotonic_store_verified": False,
        "operational_health_verified": False, "owner_authenticated": False,
        "real_monitoring_enabled": False, "task_execution_authorized": False,
        "project_roster_modified": False,
    }


class SyntheticHealthLedger:
    """Never accepts external DB roots outside existing disposable temp labs."""

    def __init__(self, root, *, witness):
        if not isinstance(witness, FakeMonotonicWitness):
            raise PolicyBlocked("synthetic witness required")
        base = Path(root).expanduser()
        if (not base.name.startswith("upab-v3-lab-")
                or base.is_symlink() or not base.is_dir()):
            raise PolicyBlocked("existing disposable lab root required")
        self.root = base.resolve(strict=True)
        if self.root.parent != Path(tempfile.gettempdir()).resolve():
            raise PolicyBlocked("synthetic root is outside OS temp")
        _check(self.root, directory=True)
        self.path = self.root / "v3_synthetic_health_ledger.sqlite3"
        self.witness = witness
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("CREATE TABLE IF NOT EXISTS meta ("
                           "id INTEGER PRIMARY KEY CHECK(id=1),"
                           "ledger_id TEXT NOT NULL,epoch INTEGER NOT NULL CHECK(epoch>=0),"
                           "phase TEXT NOT NULL CHECK(phase IN ('READY','PENDING','QUARANTINED')))")
                db.execute("CREATE TABLE IF NOT EXISTS collectors ("
                           "scope TEXT PRIMARY KEY,enrollment_id TEXT UNIQUE NOT NULL,"
                           "fingerprint TEXT NOT NULL,source_kind TEXT NOT NULL,"
                           "state TEXT NOT NULL CHECK(state IN ('ENROLLED','REVOKED','EXPIRED')),"
                           "valid_from INTEGER NOT NULL,valid_until INTEGER NOT NULL)")
                db.execute("CREATE TABLE IF NOT EXISTS sequences ("
                           "scope TEXT PRIMARY KEY REFERENCES collectors(scope),"
                           "last_sequence INTEGER NOT NULL CHECK(last_sequence>=1),"
                           "last_when INTEGER NOT NULL,commit_epoch INTEGER NOT NULL,"
                           "digest TEXT NOT NULL)")
                db.execute("CREATE TABLE IF NOT EXISTS pending ("
                           "id INTEGER PRIMARY KEY CHECK(id=1),scope TEXT NOT NULL,"
                           "previous_digest TEXT NOT NULL,new_digest TEXT NOT NULL,"
                           "new_sequence INTEGER NOT NULL,new_when INTEGER NOT NULL,"
                           "next_epoch INTEGER NOT NULL)")
                row = db.execute("SELECT ledger_id,epoch,phase FROM meta WHERE id=1").fetchone()
                if row is None:
                    if self.witness.snapshot() != (None, 0):
                        raise PolicyBlocked("ledger missing but fake witness already bound")
                    identity = uuid.uuid4().hex
                    db.execute("INSERT INTO meta VALUES(1,?,0,'READY')", (identity,))
                    self.witness.bind_new_fixture(identity)
                    row = (identity, 0, "READY")
                db.execute("COMMIT")
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
        if self.witness.snapshot()[0] != row[0]:
            raise PolicyBlocked("ledger identity differs from synthetic witness")

    def _db(self):
        _check(self.root, directory=True)
        for suffix in ("", "-wal", "-shm", "-journal"):
            _check(Path(str(self.path) + suffix))
        try:
            db = sqlite3.connect(self.path, timeout=1, isolation_level=None)
            mode = db.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA busy_timeout=1000")
            if mode.lower() != "wal" or db.execute("PRAGMA synchronous").fetchone()[0] != 2:
                raise PolicyBlocked("storage durability downgraded")
            if db.execute("PRAGMA integrity_check(1)").fetchone()[0] != "ok":
                raise PolicyBlocked("synthetic ledger corrupt")
            return db
        except (sqlite3.Error, OSError) as exc:
            raise PolicyBlocked("synthetic storage unavailable") from exc

    @staticmethod
    def _meta(db):
        row = db.execute("SELECT ledger_id,epoch,phase FROM meta WHERE id=1").fetchone()
        if row is None:
            raise PolicyBlocked("ledger metadata missing")
        return row

    def _ready(self, db):
        identity, epoch, phase = self._meta(db)
        if (self.witness.snapshot() != (identity, epoch) or phase != "READY"
                or db.execute("SELECT count(*) FROM pending").fetchone()[0] != 0):
            raise PolicyBlocked("ledger needs recovery or is quarantined")
        return identity, epoch

    @staticmethod
    def _digest(scope, sequence, when, epoch):
        record = {"domain": SCHEMA, "scope": scope,
                  "sequence": sequence, "when": when, "epoch": epoch}
        payload = json.dumps(record, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")
        return hashlib.sha256(payload).hexdigest()

    def seed_fixture(self, *, enrollment_id, fingerprint, repository, module_id,
                     source_kind, initial_sequence, initial_when, valid_from, valid_until):
        """Fixture initialization only, NOT owner-approved collector enrollment."""
        scope = _scope(repository, module_id)
        if (type(enrollment_id) is not str or not _VALID_ID.fullmatch(enrollment_id)
                or type(fingerprint) is not str or not HEX64.fullmatch(fingerprint)
                or source_kind not in ("LOCAL_WATCHER", "GITHUB_CI")
                or (module_id is not None and source_kind != "LOCAL_WATCHER")
                or not _valid_epoch(initial_sequence) or initial_sequence < 1
                or not all(_valid_epoch(v) for v in (initial_when, valid_from, valid_until))
                or not valid_from <= initial_when < valid_until):
            raise PolicyBlocked("synthetic fixture invalid")
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                _, epoch = self._ready(db)
                if (epoch != 0 or db.execute("SELECT count(*) FROM collectors").fetchone()[0]
                        >= MAX_OBSERVATIONS):
                    raise PolicyBlocked("cannot seed synthetic fixture after activity")
                db.execute("INSERT INTO collectors VALUES (?,?,?,?,?,?,?)",
                           (scope, enrollment_id, fingerprint, source_kind,
                            "ENROLLED", valid_from, valid_until))
                db.execute("INSERT INTO sequences VALUES (?,?,?,?,?)",
                           (scope, initial_sequence, initial_when, 0,
                            self._digest(scope, initial_sequence, initial_when, 0)))
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        return _receipt("SYNTHETIC_FIXTURE_ONLY_NOT_OWNER_ENROLLED")

    def revoke_fixture(self, *, repository, module_id):
        scope = _scope(repository, module_id)
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                self._ready(db)
                if db.execute("UPDATE collectors SET state='REVOKED' WHERE scope=?",
                              (scope,)).rowcount != 1:
                    raise PolicyBlocked("synthetic scope absent")
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        return _receipt("SYNTHETIC_REVOCATION_ONLY")

    def accept_fixture(self, *, portfolio, envelope, now_epoch_s,
                       max_age_s=300, interrupt_at=None):
        """Verify existing Stage 36 signature, then simulate durable continuity."""
        if interrupt_at not in (None, "before_prepare", "after_prepare",
                                "after_anchor", "after_finalize"):
            raise PolicyBlocked("unknown synthetic fault injection")
        review_signed_health_batch(portfolio=portfolio, envelopes=[envelope],
                                   now_epoch_s=now_epoch_s, max_age_s=max_age_s)
        claim = envelope["claim"]
        when, seq = claim["observed_at_epoch_s"], claim["sequence"]
        if when > now_epoch_s or now_epoch_s - when > max_age_s:
            raise PolicyBlocked("stale or future observation")
        scope = _scope(claim["repository"], claim["module_id"])
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                identity, epoch = self._ready(db)
                collector = db.execute(
                    "SELECT fingerprint,source_kind,state,valid_from,valid_until "
                    "FROM collectors WHERE scope=?", (scope,)).fetchone()
                prior = db.execute(
                    "SELECT last_sequence,last_when,commit_epoch,digest "
                    "FROM sequences WHERE scope=?", (scope,)).fetchone()
                if collector is None or prior is None:
                    raise PolicyBlocked("fixture history or scope missing")
                fingerprint, source, state, start, end = collector
                if (fingerprint != envelope["public_key_sha256"]
                        or source != claim["source_kind"] or state != "ENROLLED"
                        or not start <= when < end or not start <= now_epoch_s < end):
                    raise PolicyBlocked("synthetic signer is not in valid fixture scope")
                old_seq, old_when, old_epoch, old_digest = prior
                if (old_epoch > epoch or
                        old_digest != self._digest(scope, old_seq, old_when, old_epoch)):
                    raise PolicyBlocked("synthetic history digest invalid")
                if seq <= old_seq or when < old_when:
                    raise PolicyBlocked("sequence replay or observation-clock regression")
                if seq != old_seq + 1:
                    db.execute("UPDATE meta SET phase='QUARANTINED' WHERE id=1")
                    db.execute("COMMIT")
                    return _receipt("QUARANTINED_SEQUENCE_GAP", quarantined=1)
                new_digest = self._digest(scope, seq, when, epoch + 1)
                db.execute("INSERT INTO pending VALUES(1,?,?,?,?,?,?)",
                           (scope, old_digest, new_digest, seq, when, epoch + 1))
                db.execute("UPDATE meta SET phase='PENDING' WHERE id=1")
                if interrupt_at == "before_prepare":
                    raise SimulatedInterruption("before durable prepare")
                db.execute("COMMIT")
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
        if interrupt_at == "after_prepare":
            raise SimulatedInterruption("after durable prepare")
        self.witness.advance(identity=identity, expected_epoch=epoch)
        if interrupt_at == "after_anchor":
            raise SimulatedInterruption("after fake witness advanced")
        self._finalize_pending()
        if interrupt_at == "after_finalize":
            raise SimulatedInterruption("after committed finalization")
        return _receipt("SYNTHETIC_CONTINUITY_ACCEPTED_NO_TRUST", accepted=1)

    def _finalize_pending(self):
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                identity, epoch, phase = self._meta(db)
                rows = db.execute(
                    "SELECT scope,previous_digest,new_digest,new_sequence,new_when,"
                    "next_epoch FROM pending").fetchall()
                if phase != "PENDING" or len(rows) != 1:
                    raise PolicyBlocked("ambiguous pending synthetic update")
                scope, old_digest, new_digest, seq, when, next_epoch = rows[0]
                prior = db.execute(
                    "SELECT last_sequence,last_when,commit_epoch,digest "
                    "FROM sequences WHERE scope=?", (scope,)).fetchone()
                if (prior is None or prior[3] != old_digest
                        or old_digest != self._digest(scope, prior[0], prior[1], prior[2])
                        or seq != prior[0] + 1 or when < prior[1]
                        or next_epoch != epoch + 1
                        or new_digest != self._digest(scope, seq, when, next_epoch)
                        or self.witness.snapshot() != (identity, next_epoch)):
                    raise PolicyBlocked("insufficient synthetic finalize proof")
                if db.execute("UPDATE sequences SET last_sequence=?,last_when=?,"
                              "commit_epoch=?,digest=? WHERE scope=?",
                              (seq, when, next_epoch, new_digest, scope)).rowcount != 1:
                    raise PolicyBlocked("synthetic sequence record vanished")
                db.execute("UPDATE meta SET epoch=?,phase='READY' WHERE id=1",
                           (next_epoch,))
                db.execute("DELETE FROM pending WHERE id=1")
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def recover_fixture(self):
        """Quarantine uncertainty; recover only exact post-anchor prepared state."""
        try:
            with closing(self._db()) as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    identity, epoch, phase = self._meta(db)
                    anchor_id, anchor_epoch = self.witness.snapshot()
                    pending = db.execute("SELECT count(*) FROM pending").fetchone()[0]
                    if (phase == "READY" and pending == 0 and
                            (identity, epoch) == (anchor_id, anchor_epoch)):
                        db.execute("COMMIT")
                        return _receipt("SYNTHETIC_LEDGER_READY_NOT_AUTHENTICATED")
                    if (phase == "PENDING" and pending == 1 and identity == anchor_id
                            and anchor_epoch == epoch + 1):
                        db.execute("COMMIT")
                        self._finalize_pending()
                        return _receipt("SYNTHETIC_INTERRUPTED_COMMIT_RECOVERED",
                                        interrupted=1)
                    db.execute("UPDATE meta SET phase='QUARANTINED' WHERE id=1")
                    db.execute("COMMIT")
                    return _receipt("QUARANTINED_UNCERTAIN_SYNTHETIC_RECOVERY",
                                    quarantined=1)
                except BaseException:
                    if db.in_transaction:
                        db.execute("ROLLBACK")
                    raise
        except (sqlite3.Error, OSError) as exc:
            raise PolicyBlocked("synthetic recovery storage unavailable") from exc
