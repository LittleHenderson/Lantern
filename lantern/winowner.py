"""Who owns a folder on Windows, and whose folders count as the current user's own, asked of Windows itself.

`lantern.gitfacts` follows a git folder that lies outside the folder a person asked about only when it is that
person's own, which is git's rule (2026-11-10: on a shared computer another user can make `C:\\.git`, and every
project beneath it that has no git folder of its own was reported with that user's commit and address). On Windows
"whose is it" is the owner in the folder's security descriptor, written as a SID (`S-1-5-21-…-1001`), and the answer
is the one git for Windows gives (`is_path_owned_by_current_sid` in its `compat/mingw.c`):

* the owner is the user of this process; or
* the owner is the Administrators group and the user is one of them. What an administrator makes in an elevated
  window belongs to that group, not to the person. The everyday, not elevated, sign-in of an administrator carries
  the group switched off, so the sign-in linked to it is asked as well, as git does.

Left out on purpose, and so stricter than git for Windows in one place: git also takes the person's home folder for
theirs whoever owns it. Never asked: a network name (`\\\\server\\share\\…`), which git does not ask either, so that
no server is sent a sign-in. Anything Windows does not tell (an error, a disk that keeps no owners) is "not known",
and a folder whose owner is not known is nobody's.

Every call's result is read, and what a call hands out (a handle, memory) is given back on every path. Only
documented calls of advapi32 and kernel32 are used. `api` stands for those libraries, so the tests can hand in a
stand-in on any system (tests/test_gitfacts.py); the real ones are loaded only on Windows.
"""

from __future__ import annotations

import ctypes

FILE_OBJECT = 1                         # SE_FILE_OBJECT
OWNER = 0x00000001                      # OWNER_SECURITY_INFORMATION
TOKEN_QUERY = 0x0008
USER, ELEVATION_TYPE, LINKED_TOKEN = 1, 18, 19     # TOKEN_INFORMATION_CLASS: TokenUser, TokenElevationType, TokenLinkedToken
LIMITED = 3                             # TokenElevationTypeLimited: an administrator's sign-in that is not elevated
ADMINISTRATORS = "S-1-5-32-544"         # the group BUILTIN\Administrators: the same SID on every Windows
MOST = 1024                             # a TOKEN_USER is under 100 bytes; more than this is not an answer

_DWORD = ctypes.c_uint32                # c_ulong is four bytes on Windows only; the tests read these on any system
_BOOL = ctypes.c_int
_HANDLE = ctypes.c_void_p
_PTR = ctypes.c_void_p
_OUT = ctypes.POINTER(ctypes.c_void_p)


class _Api:
    """The functions as this module calls them, each with its argument and result types declared (without them
    ctypes passes a handle or an address as a 32-bit number, which cuts a 64-bit one short)."""

    CALLS = {
        "advapi32": (
            ("GetNamedSecurityInfoW", _DWORD, [ctypes.c_wchar_p, ctypes.c_int, _DWORD, _OUT, _OUT, _OUT, _OUT, _OUT]),
            ("ConvertSidToStringSidW", _BOOL, [_PTR, _OUT]),
            ("ConvertStringSidToSidW", _BOOL, [ctypes.c_wchar_p, _OUT]),
            ("OpenProcessToken", _BOOL, [_HANDLE, _DWORD, _OUT]),
            ("GetTokenInformation", _BOOL, [_HANDLE, ctypes.c_int, _PTR, _DWORD, ctypes.POINTER(_DWORD)]),
            ("CheckTokenMembership", _BOOL, [_HANDLE, _PTR, ctypes.POINTER(_BOOL)]),
        ),
        "kernel32": (
            ("GetCurrentProcess", _HANDLE, []),
            ("CloseHandle", _BOOL, [_HANDLE]),
            ("LocalFree", _PTR, [_PTR]),
        ),
    }

    def __init__(self):
        for library, calls in self.CALLS.items():
            dll = ctypes.WinDLL(library, use_last_error=True)       # Windows only: this class is made nowhere else
            for name, result, arguments in calls:
                fn = getattr(dll, name)
                fn.restype, fn.argtypes = result, arguments
                setattr(self, name, fn)


_real: _Api | None = None


def _api() -> _Api:
    global _real
    if _real is None:
        _real = _Api()
    return _real


def _sid_text(api, sid: int) -> str | None:
    """A SID as Windows writes it (`S-1-5-…`). The text is Windows' own memory, given back here."""
    text = ctypes.c_void_p()
    if not api.ConvertSidToStringSidW(sid, ctypes.byref(text)) or not text.value:
        return None
    try:
        return ctypes.wstring_at(text.value)
    finally:
        api.LocalFree(text.value)


def local(path: str) -> bool:
    """Whether `path` names a place on this computer's own disks (`C:\\…`, also in the long form `\\\\?\\C:\\…`), and
    not a network name or a device."""
    p = path.replace("/", "\\")
    p = p[4:] if p.startswith("\\\\?\\") else p
    return not p.startswith("\\\\") and not p[:4].upper() == "UNC\\"


def owner(path: str, api=None) -> str | None:
    """The owner Windows records for `path`, as a SID. None when Windows does not say, and for a network name."""
    if not local(path):
        return None
    try:
        api = api if api is not None else _api()
        sid, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
        failed = api.GetNamedSecurityInfoW(path, FILE_OBJECT, OWNER, ctypes.byref(sid), None, None, None,
                                           ctypes.byref(descriptor))
        try:
            return _sid_text(api, sid.value) if not failed and sid.value else None
        finally:
            if descriptor.value:                    # the owner's SID lies inside it, so it is given back last
                api.LocalFree(descriptor.value)
    except (OSError, ValueError, ctypes.ArgumentError):
        return None


def _administrator(api, token: int) -> bool:
    """Whether the user of this process is one of the Administrators: with this sign-in, or with the elevated one
    linked to it."""
    group = ctypes.c_void_p()
    if not api.ConvertStringSidToSidW(ADMINISTRATORS, ctypes.byref(group)) or not group.value:
        return False
    try:
        member = _BOOL(0)
        if api.CheckTokenMembership(None, group.value, ctypes.byref(member)) and member.value:
            return True
        kind, size = _DWORD(0), _DWORD(0)
        if not api.GetTokenInformation(token, ELEVATION_TYPE, ctypes.byref(kind), ctypes.sizeof(kind),
                                       ctypes.byref(size)) or kind.value != LIMITED:
            return False
        linked = ctypes.c_void_p()
        if not api.GetTokenInformation(token, LINKED_TOKEN, ctypes.byref(linked), ctypes.sizeof(linked),
                                       ctypes.byref(size)) or not linked.value:
            return False
        try:
            member = _BOOL(0)
            return bool(api.CheckTokenMembership(linked.value, group.value, ctypes.byref(member)) and member.value)
        finally:
            api.CloseHandle(linked.value)
    finally:
        api.LocalFree(group.value)


def myself(api=None) -> frozenset[str]:
    """The owners whose folders are the current user's own: the user's SID, and the Administrators group when the
    user is one of them. Empty when Windows does not say, and then no folder counts as the user's."""
    try:
        api = api if api is not None else _api()
        token = ctypes.c_void_p()
        if not api.OpenProcessToken(api.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)) or not token.value:
            return frozenset()
        mine: set[str] = set()
        try:
            size = _DWORD(0)
            api.GetTokenInformation(token.value, USER, None, 0, ctypes.byref(size))    # answers with the room it needs
            if 0 < size.value <= MOST:
                room = ctypes.create_string_buffer(size.value)
                if api.GetTokenInformation(token.value, USER, room, size.value, ctypes.byref(size)):
                    sid = ctypes.cast(room, _OUT)[0]        # a TOKEN_USER begins with the address of the user's SID
                    user = _sid_text(api, sid) if sid else None
                    if user:
                        mine.add(user)
            if _administrator(api, token.value):
                mine.add(ADMINISTRATORS)
        finally:
            api.CloseHandle(token.value)
        return frozenset(mine)
    except (OSError, ValueError, ctypes.ArgumentError):
        return frozenset()
