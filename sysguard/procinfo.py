"""Helpers for reading process and socket information from /proc.

Everything here is read-only. We never write to /proc, never attach to
or trace other processes, and never kill anything. The scanner only
*observes*.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

_SOCKET_RE = re.compile(r"socket:\[(\d+)\]")


@dataclass
class Process:
    pid: int
    cmdline: str = ""
    comm: str = ""
    exe: str = ""
    exe_deleted: bool = False
    uid: int = -1
    open_paths: list[str] = field(default_factory=list)
    socket_inodes: list[int] = field(default_factory=list)


def _read(path: str) -> str:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except (OSError, PermissionError):
        return ""


def iter_pids() -> list[int]:
    pids = []
    try:
        for name in os.listdir("/proc"):
            if name.isdigit():
                pids.append(int(name))
    except OSError:
        pass
    return pids


def read_process(pid: int, *, with_fds: bool = True) -> Process | None:
    """Collect what we can about one PID. Returns None if it vanished."""
    base = f"/proc/{pid}"
    if not os.path.isdir(base):
        return None

    proc = Process(pid=pid)

    raw_cmd = _read(f"{base}/cmdline")
    proc.cmdline = raw_cmd.replace("\x00", " ").strip()
    proc.comm = _read(f"{base}/comm").strip()

    try:
        target = os.readlink(f"{base}/exe")
        if target.endswith(" (deleted)"):
            proc.exe_deleted = True
            target = target[: -len(" (deleted)")]
        proc.exe = target
    except OSError:
        # Kernel threads and processes we can't inspect have no readable exe.
        proc.exe = ""

    try:
        proc.uid = os.stat(base).st_uid
    except OSError:
        proc.uid = -1

    if with_fds:
        fd_dir = f"{base}/fd"
        try:
            for fd in os.listdir(fd_dir):
                try:
                    link = os.readlink(f"{fd_dir}/{fd}")
                except OSError:
                    continue
                match = _SOCKET_RE.fullmatch(link)
                if match:
                    proc.socket_inodes.append(int(match.group(1)))
                else:
                    proc.open_paths.append(link)
        except (OSError, PermissionError):
            # Reading another user's fds needs root; that's expected and fine.
            pass

    return proc


def read_environ(pid: int) -> dict[str, str]:
    """Return a process's environment as a dict.

    ``/proc/<pid>/environ`` is NUL-separated ``KEY=VALUE`` entries. Reading
    another user's environ requires root; without it we simply get an empty
    dict for those processes, which callers handle gracefully.
    """
    raw = _read(f"/proc/{pid}/environ")
    env: dict[str, str] = {}
    if not raw:
        return env
    for item in raw.split("\x00"):
        if not item or "=" not in item:
            continue
        key, _, value = item.partition("=")
        env[key] = value
    return env


def all_processes(*, with_fds: bool = True) -> list[Process]:
    out = []
    for pid in iter_pids():
        proc = read_process(pid, with_fds=with_fds)
        if proc is not None:
            out.append(proc)
    return out


def socket_inode_to_pid() -> dict[int, int]:
    """Map a socket inode -> the first PID we find holding it open.

    Used to attribute a network connection to a process. Requires root to
    see sockets owned by other users; without it we still see our own.
    """
    mapping: dict[int, int] = {}
    for proc in all_processes(with_fds=True):
        for inode in proc.socket_inodes:
            mapping.setdefault(inode, proc.pid)
    return mapping


def running_as_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:  # pragma: no cover - non-POSIX
        return False


_IS_WSL: bool | None = None


def is_wsl() -> bool:
    """True if we're running under Windows Subsystem for Linux.

    Matters because Windows drives mounted under WSL (DrvFs/9p, e.g.
    ``/mnt/c``) report mode 0777 for everything — they carry no real Unix
    permissions — so permission-based checks there are meaningless noise.
    """
    global _IS_WSL
    if _IS_WSL is None:
        try:
            with open("/proc/version", "r") as fh:
                _IS_WSL = "microsoft" in fh.read().lower()
        except OSError:
            _IS_WSL = False
    return _IS_WSL


def on_windows_mount(path: str) -> bool:
    """True for a path on a Windows drive mounted under WSL (/mnt/<letter>)."""
    if not is_wsl():
        return False
    parts = path.split("/")
    # /mnt/c/... -> ['', 'mnt', 'c', ...]
    return len(parts) >= 3 and parts[1] == "mnt" and len(parts[2]) == 1
