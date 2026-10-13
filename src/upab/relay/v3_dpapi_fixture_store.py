"""Disposable DPAPI credential custody test; NOT a production approval key store.

The only protected bytes are a randomly generated TEST SEED, held under an
existing upab-v3-lab-* direct child of the OS temporary directory.
Creation is single-use; no overwrite, user-controlled paths, secret export,
signing, approval issuance, or task execution. The owner can still decrypt
with the same OS account: DPAPI is not user-presence authentication.
"""
from __future__ import annotations

import os
from pathlib import Path
import secrets
import stat
import sys
import tempfile

from .v3_policy import PolicyBlocked
from .v3_windows_dpapi import (
    protect_for_current_user, unprotect_for_current_user,
)

_FILENAME = "synthetic_dpapi_seed.bin"
_MAX_CIPHERTEXT = 4096


def _safe_root(root: str | Path) -> Path:
    if sys.platform != "win32":
        raise PolicyBlocked("Windows test vault requires Windows")
    supplied = Path(root).expanduser()
    if not supplied.name.startswith("upab-v3-lab-"):
        raise PolicyBlocked("vault may only use a synthetic test root")
    if supplied.is_symlink() or not supplied.is_dir():
        raise PolicyBlocked("synthetic test directory must already exist")
    canonical = supplied.resolve(strict=True)
    if (canonical.name != supplied.name or
            canonical.parent != Path(tempfile.gettempdir()).resolve()):
        raise PolicyBlocked("test vault outside OS temporary directory")
    attrs = canonical.lstat()
    if (not stat.S_ISDIR(attrs.st_mode) or
            getattr(attrs, "st_file_attributes", 0) & 0x400):
        raise PolicyBlocked("test vault directory is redirected")
    return canonical


def _file(root: str | Path) -> Path:
    path = _safe_root(root) / _FILENAME
    try:
        attrs = path.lstat()
    except FileNotFoundError:
        return path
    if (not stat.S_ISREG(attrs.st_mode) or stat.S_ISLNK(attrs.st_mode)
            or getattr(attrs, "st_file_attributes", 0) & 0x400):
        raise PolicyBlocked("test vault file is redirected")
    return path


def create_synthetic_seed(root: str | Path) -> dict[str, object]:
    """Create just one encrypted non-production seed; never return its bytes."""
    path = _file(root)
    if path.exists():
        raise PolicyBlocked("test vault already exists")
    seed = secrets.token_bytes(32)
    encrypted = protect_for_current_user(seed)
    if not 1 <= len(encrypted) <= _MAX_CIPHERTEXT:
        raise PolicyBlocked("unexpected encrypted seed size")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(str(path), flags, 0o600)
    except FileExistsError as exc:
        raise PolicyBlocked("test vault already exists") from exc
    try:
        with os.fdopen(fd, "wb", closefd=True) as file:
            file.write(encrypted)
            file.flush()
            os.fsync(file.fileno())
    except BaseException:
        # A partial vault is treated as corrupt and cannot be overwritten.
        raise
    return {
        "schema": "upab.watcher-v3.dpapi-vault-lab.v1",
        "synthetic_seed_created": True,
        "plaintext_written": False,
        "seed_exported": False,
        "owner_authenticated": False,
        "execution_authorized": False,
    }


def verify_synthetic_seed(root: str | Path) -> dict[str, object]:
    """Integrity/DPAPI round-trip only; never return decrypted bytes."""
    path = _file(root)
    if not path.is_file():
        raise PolicyBlocked("synthetic test vault missing")
    size = path.stat().st_size
    if not 1 <= size <= _MAX_CIPHERTEXT:
        raise PolicyBlocked("test vault size invalid")
    encrypted = path.read_bytes()
    decoded = unprotect_for_current_user(encrypted)
    if len(decoded) != 32:
        raise PolicyBlocked("test vault seed size mismatch")
    return {
        "schema": "upab.watcher-v3.dpapi-vault-lab.v1",
        "seed_verified_under_current_user": True,
        "seed_exported": False,
        "owner_authenticated": False,
        "execution_authorized": False,
    }
