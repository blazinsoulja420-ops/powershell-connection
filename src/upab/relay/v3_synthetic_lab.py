"""Synthetic integration harness for the Watcher v3 review control plane.

ONLY fixed fictional fixture metadata. No command/task executor, no real task
data, no clipboard, no network access, no Git and no approval issuance.
Its state root MUST be an explicit disposable upab-v3-lab-* directory.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from .review_queue_v2 import BoundedReviewQueue, QueueBlocked
from .single_flight_v2 import SingleFlightLock
from .v3_checkpoint import CheckpointStore
from .v3_policy import PolicyBlocked

FIXTURE_ID = "synthetic-review-lab-v1"
FIXTURE_DIGEST = hashlib.sha256(b"UPAB WATCHER V3 SYNTHETIC REVIEW FIXTURE").hexdigest().upper()


class SyntheticReviewLab:
    def __init__(self, root: str | Path):
        raw = Path(root).expanduser()
        if (not raw.name.startswith("upab-v3-lab-") or raw.is_symlink()
                or not raw.is_dir()):
            raise PolicyBlocked("requires an existing disposable upab-v3-lab- directory")
        self.root = raw.resolve(strict=True)
        # No other project folder or production watcher state is inspected.
        if not self.root.name.startswith("upab-v3-lab-"):
            raise PolicyBlocked("disposable test root changed during canonicalization")

    def begin(self) -> dict[str, object]:
        with SingleFlightLock(self.root):
            review = BoundedReviewQueue(self.root, capacity=1)
            checkpoints = CheckpointStore(self.root, max_records=2)
            review.submit(FIXTURE_ID, FIXTURE_DIGEST)
            checkpoints.propose(FIXTURE_ID, FIXTURE_DIGEST)
            record = review.claim_for_review()
            if record is None or record["task_id"] != FIXTURE_ID:
                raise PolicyBlocked("synthetic review cannot be uniquely claimed")
            checkpoints.transition(
                FIXTURE_ID, expected_digest=FIXTURE_DIGEST,
                next_phase="REVIEW_STARTED",
            )
            return {
                "status": "SYNTHETIC_REVIEW_STARTED",
                "task_id": FIXTURE_ID,
                "execution_authorized": False,
                "task_executed": False,
            }

    def finish(self) -> dict[str, object]:
        with SingleFlightLock(self.root):
            review = BoundedReviewQueue(self.root, capacity=1)
            checkpoints = CheckpointStore(self.root, max_records=2)
            record = checkpoints.status(FIXTURE_ID)
            if record is None or record["phase"] != "REVIEW_STARTED":
                raise PolicyBlocked("synthetic review not in expected phase")
            # A review receipt is NEVER authorization to execute tasks.
            checkpoints.transition(
                FIXTURE_ID, expected_digest=FIXTURE_DIGEST,
                next_phase="REVIEW_COMPLETED",
            )
            review.dismiss(FIXTURE_ID)
            return {
                "status": "SYNTHETIC_REVIEW_FINISHED",
                "task_id": FIXTURE_ID,
                "execution_authorized": False,
                "task_executed": False,
            }

    def reconcile(self) -> dict[str, object]:
        """Interrupted review is quarantined, not automatically replayed."""
        with SingleFlightLock(self.root):
            queue = BoundedReviewQueue(self.root, capacity=1)
            checkpoints = CheckpointStore(self.root, max_records=2)
            pending = queue.reconcile_after_exclusive_restart()
            review_phases = checkpoints.reconcile_interrupted()
            return {
                "status": "SYNTHETIC_REVIEW_RECONCILED",
                "interrupted_queue_claims": pending,
                "interrupted_checkpoints": review_phases,
                "needs_manual_review": bool(pending or review_phases),
                "execution_authorized": False,
                "task_executed": False,
            }
