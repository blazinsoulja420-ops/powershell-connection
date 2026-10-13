"""Watcher v3 deterministic control policies. Candidate; no task execution.

All outputs are observations, scheduling suggestions, or denials. No function
in this module executes tasks, grants approvals, opens network listeners,
modifies Git repositories, or starts processes.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import re
import time
from typing import Iterable

_TASK_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_ALLOWED_PRIORITIES = frozenset({0, 1, 2, 3})
_SAFE_RETRY_CLASSES = frozenset({"clipboard_read_busy", "read_only_status_unavailable"})
_ALLOWED_METRICS = frozenset({
    "notification", "duplicate", "oversize", "read_error",
    "review_admitted", "review_blocked", "review_interrupted",
    "watchdog_alert", "retry_deferred",
})


class PolicyBlocked(ValueError):
    pass


@dataclass(frozen=True)
class ReviewJob:
    task_id: str
    digest: str
    priority: int = 1
    dependencies: tuple[str, ...] = ()
    sequence: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or not _TASK_ID.fullmatch(self.task_id):
            raise PolicyBlocked("invalid task identifier")
        if not isinstance(self.digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", self.digest):
            raise PolicyBlocked("invalid task digest")
        if type(self.priority) is not int or self.priority not in _ALLOWED_PRIORITIES:
            raise PolicyBlocked("priority must be an integer from 0 to 3")
        if type(self.sequence) is not int or self.sequence < 0:
            raise PolicyBlocked("sequence must be nonnegative")
        if not isinstance(self.dependencies, tuple) or len(self.dependencies) > 16:
            raise PolicyBlocked("dependencies must be a tuple of up to 16 IDs")
        if len(set(self.dependencies)) != len(self.dependencies):
            raise PolicyBlocked("repeated dependency")
        for item in self.dependencies:
            if not isinstance(item, str) or not _TASK_ID.fullmatch(item) or item == self.task_id:
                raise PolicyBlocked("invalid dependency")


class ReviewScheduler:
    """No run() API: only chooses which metadata proposal to REVIEW next."""

    def __init__(self, *, capacity: int = 8, aging_interval: int = 4):
        if type(capacity) is not int or not 1 <= capacity <= 32:
            raise PolicyBlocked("capacity must be 1..32")
        if type(aging_interval) is not int or not 1 <= aging_interval <= 100:
            raise PolicyBlocked("aging_interval must be 1..100")
        self.capacity = capacity
        self.aging_interval = aging_interval
        self._items: dict[str, ReviewJob] = {}
        self._reviewed: set[str] = set()
        self._claimed: str | None = None
        self._sequence = 0

    @property
    def active(self) -> int:
        return len(self._items)

    def add(self, job: ReviewJob) -> None:
        if len(self._items) >= self.capacity:
            raise PolicyBlocked("bounded review queue is full")
        if job.task_id in self._items or job.task_id in self._reviewed:
            raise PolicyBlocked("duplicate review identifier")
        if any(dep not in self._items and dep not in self._reviewed for dep in job.dependencies):
            raise PolicyBlocked("dependency missing from this queue")
        self._sequence += 1
        self._items[job.task_id] = ReviewJob(
            task_id=job.task_id, digest=job.digest, priority=job.priority,
            dependencies=job.dependencies, sequence=self._sequence,
        )

    def choose_for_review(self) -> str | None:
        if self._claimed is not None:
            return None
        ready = [
            item for item in self._items.values()
            if all(dep in self._reviewed for dep in item.dependencies)
        ]
        if not ready:
            return None
        # Priority and aging are combined, but a review never implies
        # authorization to execute the item or dependency.
        ready.sort(
            key=lambda j: (
                -(j.priority + min(3, (self._sequence - j.sequence) // self.aging_interval)),
                j.sequence, j.task_id,
            )
        )
        self._claimed = ready[0].task_id
        return self._claimed

    def finish_review(self, task_id: str) -> None:
        if self._claimed != task_id:
            raise PolicyBlocked("only the claimed review can be completed")
        del self._items[task_id]
        self._reviewed.add(task_id)
        self._claimed = None

    def interrupted(self) -> str | None:
        """Fail closed: leaves any claimed item blocked; no requeue or rerun."""
        return self._claimed

    def snapshot(self) -> dict[str, object]:
        return {
            "queued": len(self._items),
            "claimed_for_review": self._claimed,
            "reviewed": len(self._reviewed),
            "capacity": self.capacity,
            "execution_authorized": False,
        }


@dataclass(frozen=True)
class ResourceSample:
    cpu_percent: float
    available_memory_mb: int

    def __post_init__(self) -> None:
        if type(self.cpu_percent) not in (int, float) or not math.isfinite(self.cpu_percent):
            raise PolicyBlocked("CPU sample unavailable")
        if not 0 <= self.cpu_percent <= 100:
            raise PolicyBlocked("CPU sample out of range")
        if type(self.available_memory_mb) is not int or self.available_memory_mb < 0:
            raise PolicyBlocked("RAM sample unavailable")


def review_admission_allowed(
    sample: ResourceSample | None, *, cpu_ceiling: float = 85.0, min_free_mb: int = 768
) -> bool:
    """Resource-aware recommendation only. Unknown measurements deny admission."""
    if sample is None:
        return False
    if not 1 <= cpu_ceiling <= 100 or not 0 <= min_free_mb <= 65536:
        raise PolicyBlocked("invalid resource threshold")
    return sample.cpu_percent < cpu_ceiling and sample.available_memory_mb >= min_free_mb


def retry_delay_seconds(
    failure_class: str, attempt: int, *, max_attempts: int = 3
) -> float | None:
    """Bounded backoff only for explicitly named read-only transient conditions."""
    if type(attempt) is not int or type(max_attempts) is not int or not 1 <= max_attempts <= 5:
        raise PolicyBlocked("invalid retry bounds")
    if attempt < 1:
        raise PolicyBlocked("attempt must be positive")
    if failure_class not in _SAFE_RETRY_CLASSES or attempt >= max_attempts:
        return None
    return min(2.0, 0.1 * (2 ** (attempt - 1)))


@dataclass
class HeartbeatWatchdog:
    """Detect stalled processing; never kill, restart, or repeat a task."""

    max_silence_seconds: float = 30.0
    last_beat: float | None = None

    def __post_init__(self) -> None:
        if not math.isfinite(self.max_silence_seconds) or not 1 <= self.max_silence_seconds <= 3600:
            raise PolicyBlocked("invalid watchdog timeout")

    def beat(self, *, now: float | None = None) -> None:
        value = time.monotonic() if now is None else now
        if not math.isfinite(value) or value < 0:
            raise PolicyBlocked("invalid monotonic timestamp")
        if self.last_beat is not None and value < self.last_beat:
            raise PolicyBlocked("monotonic clock moved backward")
        self.last_beat = value

    def status(self, *, now: float | None = None) -> str:
        value = time.monotonic() if now is None else now
        if not math.isfinite(value) or value < 0:
            raise PolicyBlocked("invalid monotonic timestamp")
        if self.last_beat is None:
            return "NOT_STARTED"
        if value < self.last_beat:
            return "CLOCK_INVALID"
        return "STALE_NEEDS_REVIEW" if value - self.last_beat > self.max_silence_seconds else "HEALTHY"


class SanitizedMetrics:
    """Bounded allowlisted telemetry; refuses arbitrary labels and payloads."""

    def __init__(self):
        self._counts = {label: 0 for label in sorted(_ALLOWED_METRICS)}

    def record(self, event: str) -> None:
        if not isinstance(event, str) or event not in _ALLOWED_METRICS:
            raise PolicyBlocked("event not allowlisted for metrics")
        self._counts[event] = min(2**63 - 1, self._counts[event] + 1)

    def snapshot(self) -> dict[str, object]:
        return {"counters": dict(self._counts), "contains_task_content": False}


def validate_inbox_preview(data: object) -> dict[str, object]:
    """Local inbox schema check; NOT authentication, no HTTP server/listener."""
    if not isinstance(data, dict) or set(data) != {"schema", "task_id", "digest"}:
        raise PolicyBlocked("unknown or missing inbox preview fields")
    if data["schema"] != "upab.inbox.preview.v1":
        raise PolicyBlocked("unsupported inbox preview schema")
    task_id, digest = data["task_id"], data["digest"]
    # No authorization, sender identity, or task payload accepted here.
    job = ReviewJob(task_id=task_id, digest=digest)
    return {
        "task_id": job.task_id,
        "digest": job.digest.upper(),
        "status": "PREVIEW_ONLY",
        "authenticated": False,
        "authorized": False,
        "execution_allowed": False,
    }
