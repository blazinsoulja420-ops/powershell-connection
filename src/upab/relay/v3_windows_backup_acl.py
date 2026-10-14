"""Stage 20: read-only native Windows ACL sampling on EXISTING backup files.

Native GetNamedSecurityInfoW / GetAce read an NTFS DACL; no ACL changes.
Broad write-capable ALLOW ACEs are flagged conservatively, even if a DENY
ACE might override them. No raw SIDs, path, ACEs or state bytes are returned.
DACL observation does not prove protected backup, custody, authenticity,
immutability, handle-race safety, enrollment or migration authority.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import Path
import stat
import sys

from .v3_policy import PolicyBlocked

SE_FILE_OBJECT = 1
OWNER_SECURITY_INFORMATION = 1
DACL_SECURITY_INFORMATION = 4
SE_DACL_PROTECTED = 0x1000
ACL_SIZE_INFORMATION_CLASS = 2
ACCESS_ALLOWED_ACE_TYPE = 0
ACCESS_DENIED_ACE_TYPE = 1
_WRITE_MASK = (
    0x40000000 |  # GENERIC_WRITE
    0x10000000 |  # GENERIC_ALL
    0x00000002 |  # FILE_WRITE_DATA
    0x00000004 |  # FILE_APPEND_DATA
    0x00000010 |  # FILE_WRITE_EA
    0x00000100 |  # FILE_WRITE_ATTRIBUTES
    0x00010000 |  # DELETE
    0x00040000 |  # WRITE_DAC
    0x00080000    # WRITE_OWNER
)
_BROAD_SIDS = frozenset({"S-1-1-0", "S-1-5-11", "S-1-5-32-545",
                        "S-1-5-7", "S-1-5-32-546"})
_MAX_ACES = 512


class ACL_SIZE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("AceCount", wintypes.DWORD),
        ("AclBytesInUse", wintypes.DWORD),
        ("AclBytesFree", wintypes.DWORD),
    ]


def _regular_existing_file(path: str | Path) -> Path:
    source = Path(path).expanduser()
    if not source.is_absolute():
        raise PolicyBlocked("backup ACL scan requires an absolute file path")
    # Check every existing component, not just final resolved path.
    pieces = [source] + list(source.parents)
    for component in pieces:
        try:
            info = component.lstat()
        except OSError as exc:
            raise PolicyBlocked("backup ACL scan path missing") from exc
        if stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise PolicyBlocked("backup ACL scan path redirected")
    if not stat.S_ISREG(source.lstat().st_mode):
        raise PolicyBlocked("backup ACL scan requires regular file")
    if source.stat().st_size > 8*1024*1024:
        raise PolicyBlocked("backup ACL scan file exceeds bound")
    return source


def inspect_backup_file_acl(file: str | Path) -> dict[str, object]:
    """Sample a file security descriptor, always deny live authorization."""
    if sys.platform != "win32":
        raise PolicyBlocked("Windows ACL inspection requires Windows")
    path = _regular_existing_file(file)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    ptr = ctypes.c_void_p
    adv.GetNamedSecurityInfoW.argtypes = [
        ctypes.c_wchar_p, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(ptr), ctypes.POINTER(ptr),
        ctypes.POINTER(ptr), ctypes.POINTER(ptr), ctypes.POINTER(ptr),
    ]
    adv.GetNamedSecurityInfoW.restype = wintypes.DWORD
    adv.GetSecurityDescriptorControl.argtypes = [
        ptr, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD)
    ]
    adv.GetSecurityDescriptorControl.restype = wintypes.BOOL
    adv.GetSecurityDescriptorDacl.argtypes = [
        ptr, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ptr),
        ctypes.POINTER(wintypes.BOOL)
    ]
    adv.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    adv.GetAclInformation.argtypes = [
        ptr, ptr, wintypes.DWORD, wintypes.DWORD
    ]
    adv.GetAclInformation.restype = wintypes.BOOL
    adv.GetAce.argtypes = [ptr, wintypes.DWORD, ctypes.POINTER(ptr)]
    adv.GetAce.restype = wintypes.BOOL
    adv.ConvertSidToStringSidW.argtypes = [ptr, ctypes.POINTER(ctypes.c_wchar_p)]
    adv.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ptr]
    kernel.LocalFree.restype = ptr

    owner = ptr()
    dacl = ptr()
    sd = ptr()
    status = adv.GetNamedSecurityInfoW(
        str(path), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(sd)
    )
    if status != 0 or not sd.value:
        if sd.value:
            kernel.LocalFree(sd)
        raise PolicyBlocked("Windows could not read backup security descriptor")
    try:
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not adv.GetSecurityDescriptorControl(
            sd, ctypes.byref(control), ctypes.byref(revision)
        ):
            raise PolicyBlocked("Windows security descriptor control unreadable")
        present = wintypes.BOOL()
        defaulted = wintypes.BOOL()
        effective_dacl = ptr()
        if not adv.GetSecurityDescriptorDacl(
            sd, ctypes.byref(present), ctypes.byref(effective_dacl),
            ctypes.byref(defaulted)
        ):
            raise PolicyBlocked("Windows security descriptor DACL unreadable")
        broad = False
        allowed = 0
        unknown = 0
        ace_count = 0
        null_dacl = not bool(present.value) or not bool(effective_dacl.value)
        if not null_dacl:
            sizes = ACL_SIZE_INFORMATION()
            if not adv.GetAclInformation(
                effective_dacl, ctypes.byref(sizes),
                ctypes.sizeof(sizes), ACL_SIZE_INFORMATION_CLASS
            ):
                raise PolicyBlocked("Windows ACL size unreadable")
            ace_count = int(sizes.AceCount)
            if ace_count > _MAX_ACES:
                raise PolicyBlocked("backup DACL has too many entries")
            for i in range(ace_count):
                ace = ptr()
                if not adv.GetAce(effective_dacl, i, ctypes.byref(ace)):
                    raise PolicyBlocked("Windows ACE enumeration failed")
                hdr = ctypes.string_at(ace.value, 8)
                kind = hdr[0]
                size = int.from_bytes(hdr[2:4], "little")
                if size < 8:
                    raise PolicyBlocked("Windows ACE size malformed")
                if kind not in (ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE):
                    unknown += 1
                    continue
                if size < 12:
                    raise PolicyBlocked("Windows access ACE size malformed")
                if kind == ACCESS_DENIED_ACE_TYPE:
                    continue
                allowed += 1
                mask = int.from_bytes(hdr[4:8], "little")
                if not (mask & _WRITE_MASK):
                    continue
                string_sid = ctypes.c_wchar_p()
                sid_addr = ptr(ace.value + 8)
                if not adv.ConvertSidToStringSidW(
                    sid_addr, ctypes.byref(string_sid)
                ):
                    raise PolicyBlocked("Windows ACE SID conversion failed")
                try:
                    if string_sid.value in _BROAD_SIDS:
                        broad = True
                finally:
                    kernel.LocalFree(ctypes.cast(string_sid, ptr))
        return {
            "schema": "upab.watcher-v3.backup-acl-observation.v1",
            "security_descriptor_observed": True,
            "dacl_present": bool(present.value),
            "null_or_missing_dacl": null_dacl,
            "dacl_inheritance_protected": bool(control.value & SE_DACL_PROTECTED),
            "ace_count": ace_count,
            "allow_ace_count": allowed,
            "uninterpreted_ace_count": unknown,
            "broad_write_allow_ace_observed": broad or null_dacl,
            "path_and_acl_race_free": False,
            "all_file_acl_components_audited": False,
            "backup_access_isolation_proven": False,
            "backup_authenticity_proven": False,
            "backup_immutability_proven": False,
            "owner_authenticated": False,
            "migration_authorized": False,
            "changes_performed": False,
        }
    finally:
        kernel.LocalFree(sd)
