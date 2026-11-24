"""The individual detection checks.

Design notes
------------
* Every detector is a plain function ``() -> list[Finding]``.
* Detectors are *conservative*: they describe what they observed and let a
  human judge. Many findings are expected on a healthy system (a display
  server legitimately reads input devices, for example). We say so.
* Each detector is wrapped so one failing check never aborts the scan.
* Nothing here modifies the system. It is a read-only scanner.
"""

from __future__ import annotations

import glob
import os
import re
import stat
import subprocess

from . import netinfo, procinfo
from .findings import Finding, Severity

# ---------------------------------------------------------------------------
# 1. Input-device monitors  (the classic software keylogger technique)
# ---------------------------------------------------------------------------

# Processes that legitimately open /dev/input on a typical desktop.
_KNOWN_INPUT_READERS = {
    "Xorg", "Xwayland", "gnome-shell", "kwin_x11", "kwin_wayland",
    "sway", "weston", "mutter", "systemd-logind", "libinput",
    "ibus-daemon", "fcitx", "fcitx5",
}


def detect_input_monitors() -> list[Finding]:
    """Flag processes reading raw keyboard/mouse events from /dev/input.

    A software keylogger on Linux typically opens ``/dev/input/eventN`` (or
    ``/dev/input/by-path/*-kbd``) and reads the raw event stream. So do a
    handful of legitimate system components, which we recognise and
    down-rank. Anything *unrecognised* reading the keyboard deserves a look.
    """
    findings: list[Finding] = []
    for proc in procinfo.all_processes(with_fds=True):
        input_paths = [p for p in proc.open_paths if p.startswith("/dev/input/")]
        # Only keyboard-ish devices are interesting for keylogging.
        kbd_paths = [
            p for p in input_paths
            if "event" in p or "kbd" in p.lower() or p.endswith("/mice")
        ]
        if not kbd_paths:
            continue

        name = proc.comm or os.path.basename(proc.exe)
        known = name in _KNOWN_INPUT_READERS
        suspicious_location = any(
            proc.exe.startswith(p) for p in ("/tmp", "/dev/shm", "/var/tmp", "/home")
        )

        if known and not suspicious_location:
            severity = Severity.INFO
            detail = (
                f"Process '{name}' (PID {proc.pid}) is reading input devices. "
                "This is a recognised system component and is normally benign."
            )
        else:
            severity = Severity.HIGH if suspicious_location else Severity.MEDIUM
            detail = (
                f"Process '{name}' (PID {proc.pid}) is reading raw input events "
                f"from {', '.join(kbd_paths)}. This is the behaviour a software "
                "keylogger uses to capture keystrokes. Confirm you recognise "
                "this program and expect it to read the keyboard."
            )
        findings.append(
            Finding(
                category="input-monitor",
                title=f"Input-device reader: {name}",
                severity=severity,
                detail=detail,
                evidence={
                    "pid": proc.pid,
                    "exe": proc.exe or "(unknown)",
                    "cmdline": proc.cmdline,
                    "devices": kbd_paths,
                },
                remediation=(
                    "Identify the program. If you did not install it, note the "
                    "executable path, then investigate it offline. Do not simply "
                    "kill it before preserving the evidence (path, cmdline, hashes)."
                ),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# 2. Suspicious processes (running from temp dirs or with a deleted binary)
# ---------------------------------------------------------------------------

_SUSPECT_EXEC_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/")


def detect_suspicious_processes() -> list[Finding]:
    findings: list[Finding] = []
    for proc in procinfo.all_processes(with_fds=False):
        reasons = []
        if proc.exe_deleted and proc.exe:
            reasons.append("its executable has been deleted from disk while still running")
        if proc.exe and any(proc.exe.startswith(d) for d in _SUSPECT_EXEC_DIRS):
            reasons.append(f"it runs from a temporary/world-writable location ({proc.exe})")
        if not reasons:
            continue
        name = proc.comm or os.path.basename(proc.exe) or f"pid{proc.pid}"
        findings.append(
            Finding(
                category="suspicious-process",
                title=f"Suspicious process: {name}",
                severity=Severity.HIGH,
                detail=(
                    f"Process '{name}' (PID {proc.pid}) is suspicious because "
                    + "; ".join(reasons)
                    + ". Malware commonly runs from temp directories or deletes "
                    "its own binary to hinder analysis."
                ),
                evidence={
                    "pid": proc.pid,
                    "exe": proc.exe or "(unknown)",
                    "cmdline": proc.cmdline,
                    "exe_deleted": proc.exe_deleted,
                },
                remediation=(
                    "Preserve evidence first: record the cmdline, and if the binary "
                    "still exists copy it for analysis. Investigate before terminating."
                ),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# 3. Network listeners and outbound connections (exfiltration / backdoors)
# ---------------------------------------------------------------------------

def detect_network() -> list[Finding]:
    findings: list[Finding] = []
    inode_pid = procinfo.socket_inode_to_pid()

    def describe_proc(inode: int) -> str:
        pid = inode_pid.get(inode)
        if pid is None:
            return "owning process not visible (run as root to attribute it)"
        proc = procinfo.read_process(pid, with_fds=False)
        if proc is None:
            return f"PID {pid}"
        return f"{proc.comm or proc.exe or 'unknown'} (PID {pid})"

    for conn in netinfo.all_connections():
        if conn.state == "LISTEN":
            # Listening on all interfaces is more exposed than loopback-only.
            exposed = not netinfo.is_loopback(conn.local_ip)
            findings.append(
                Finding(
                    category="network",
                    title=f"Listening port {conn.local_port}/{conn.proto}",
                    severity=Severity.LOW if exposed else Severity.INFO,
                    detail=(
                        f"{conn.proto} is listening on {conn.local_ip}:{conn.local_port}"
                        + (" (reachable from the network)" if exposed else " (loopback only)")
                        + f". Owner: {describe_proc(conn.inode)}."
                    ),
                    evidence={
                        "proto": conn.proto,
                        "local": f"{conn.local_ip}:{conn.local_port}",
                        "owner": describe_proc(conn.inode),
                    },
                    remediation=(
                        "Confirm you expect a service on this port. Unexpected "
                        "listeners can be backdoors. Close the service or firewall "
                        "the port if it should not be exposed."
                    ),
                )
            )
        elif conn.state == "ESTABLISHED" and not netinfo.is_loopback(conn.remote_ip):
            findings.append(
                Finding(
                    category="network",
                    title=f"Outbound connection to {conn.remote_ip}:{conn.remote_port}",
                    severity=Severity.INFO,
                    detail=(
                        f"Established {conn.proto} connection "
                        f"{conn.local_ip}:{conn.local_port} -> "
                        f"{conn.remote_ip}:{conn.remote_port}. "
                        f"Owner: {describe_proc(conn.inode)}. "
                        "Keyloggers and spyware exfiltrate captured data over such "
                        "connections; review any you do not recognise."
                    ),
                    evidence={
                        "proto": conn.proto,
                        "remote": f"{conn.remote_ip}:{conn.remote_port}",
                        "owner": describe_proc(conn.inode),
                    },
                    remediation=(
                        "Cross-check the remote address and owning process. "
                        "Investigate connections to unfamiliar hosts."
                    ),
                )
            )
    return findings


# ---------------------------------------------------------------------------
# 4. Persistence mechanisms (how malware survives a reboot)
# ---------------------------------------------------------------------------

_SUSPICIOUS_LINE_RE = re.compile(
    r"(curl|wget)\s+[^|]*\|\s*(ba)?sh"          # pipe-to-shell installers
    r"|base64\s+-d"                              # decode-and-run
    r"|\bnc\b\s+-\w*[el]"                        # netcat listeners/reverse
    r"|/dev/tcp/"                                # bash reverse shells
    r"|python[0-9.]*\s+-c\s+['\"]?import\s+socket",
    re.IGNORECASE,
)


def _scan_text_for_suspicious(text: str) -> list[str]:
    hits = []
    for line in text.splitlines():
        if _SUSPICIOUS_LINE_RE.search(line):
            hits.append(line.strip()[:200])
    return hits


def detect_persistence() -> list[Finding]:
    findings: list[Finding] = []
    home = os.path.expanduser("~")

    # 4a. User crontab.
    try:
        out = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True, timeout=5
        )
        if out.returncode == 0 and out.stdout.strip():
            hits = _scan_text_for_suspicious(out.stdout)
            findings.append(
                Finding(
                    category="persistence",
                    title="User crontab present",
                    severity=Severity.MEDIUM if hits else Severity.INFO,
                    detail=(
                        "Your user crontab contains scheduled jobs."
                        + (f" Suspicious lines: {hits}" if hits else
                           " Review them to confirm you created each one.")
                    ),
                    evidence={"suspicious_lines": hits},
                    remediation="Run 'crontab -l' and remove any job you did not add.",
                )
            )
    except (OSError, subprocess.SubprocessError):
        pass

    # 4b. XDG autostart entries.
    autostart = os.path.join(home, ".config", "autostart")
    if os.path.isdir(autostart):
        for entry in sorted(os.listdir(autostart)):
            if not entry.endswith(".desktop"):
                continue
            path = os.path.join(autostart, entry)
            try:
                with open(path, "r", errors="replace") as fh:
                    content = fh.read()
            except OSError:
                continue
            exec_line = next(
                (ln for ln in content.splitlines() if ln.lower().startswith("exec=")),
                "",
            )
            hits = _scan_text_for_suspicious(content)
            findings.append(
                Finding(
                    category="persistence",
                    title=f"Autostart entry: {entry}",
                    severity=Severity.MEDIUM if hits else Severity.INFO,
                    detail=(
                        f"A desktop autostart entry will run at login. {exec_line}"
                        + (f" Suspicious content: {hits}" if hits else "")
                    ),
                    evidence={"path": path, "exec": exec_line, "suspicious": hits},
                    remediation="Delete the .desktop file if you did not create it.",
                )
            )

    # 4c. systemd user services.
    sysd_user = os.path.join(home, ".config", "systemd", "user")
    if os.path.isdir(sysd_user):
        for entry in sorted(os.listdir(sysd_user)):
            if entry.endswith(".service"):
                findings.append(
                    Finding(
                        category="persistence",
                        title=f"systemd user service: {entry}",
                        severity=Severity.LOW,
                        detail=(
                            f"A user-level systemd service '{entry}' is installed and "
                            "may start automatically. Confirm it is one you created."
                        ),
                        evidence={"path": os.path.join(sysd_user, entry)},
                        remediation="Inspect with 'systemctl --user cat' and disable if unknown.",
                    )
                )

    # 4d. Shell startup files.
    for rc in (".bashrc", ".bash_profile", ".profile", ".zshrc"):
        path = os.path.join(home, rc)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue
        hits = _scan_text_for_suspicious(content)
        if hits:
            findings.append(
                Finding(
                    category="persistence",
                    title=f"Suspicious lines in {rc}",
                    severity=Severity.HIGH,
                    detail=(
                        f"Your {rc} contains lines that match known malicious "
                        f"patterns (download-and-run, reverse shells, etc.): {hits}"
                    ),
                    evidence={"path": path, "lines": hits},
                    remediation=f"Open {path} and remove any line you did not add.",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# 5. SUID/SGID root binaries in unexpected places
# ---------------------------------------------------------------------------

# A non-exhaustive allowlist of binaries commonly SUID-root on Linux.
_COMMON_SUID = {
    "sudo", "su", "passwd", "chsh", "chfn", "newgrp", "gpasswd", "mount",
    "umount", "ping", "ping6", "fusermount", "fusermount3", "pkexec",
    "sudoedit", "ssh-keysign", "unix_chkpwd", "dbus-daemon-launch-helper",
    "polkit-agent-helper-1", "crontab", "at", "chrome-sandbox",
}

_SUID_SEARCH_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin")


def detect_suid() -> list[Finding]:
    findings: list[Finding] = []
    seen = set()
    for d in _SUID_SEARCH_DIRS:
        if not os.path.isdir(d):
            continue
        try:
            entries = os.listdir(d)
        except OSError:
            continue
        for name in entries:
            path = os.path.join(d, name)
            real = os.path.realpath(path)
            if real in seen:
                continue
            seen.add(real)
            try:
                st = os.lstat(path)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if st.st_mode & stat.S_ISUID and st.st_uid == 0:
                if name not in _COMMON_SUID:
                    findings.append(
                        Finding(
                            category="privilege",
                            title=f"Unusual SUID-root binary: {name}",
                            severity=Severity.MEDIUM,
                            detail=(
                                f"{path} is SUID and owned by root, so it runs with "
                                "root privileges for any user. It is not on the list "
                                "of binaries commonly SUID on Linux. A planted SUID "
                                "binary is a classic privilege-escalation backdoor."
                            ),
                            evidence={"path": path, "mode": oct(st.st_mode)},
                            remediation=(
                                "Verify the package that owns it (dpkg -S / rpm -qf). "
                                "If nothing owns it, treat it as highly suspicious."
                            ),
                        )
                    )
    return findings


# ---------------------------------------------------------------------------
# 6. Weak permissions on PATH directories
# ---------------------------------------------------------------------------

def detect_writable_path() -> list[Finding]:
    findings: list[Finding] = []
    seen = set()
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if not d or d in seen:
            continue
        seen.add(d)
        if not os.path.isdir(d):
            continue
        try:
            st = os.stat(d)
        except OSError:
            continue
        # World-writable directory on PATH = anyone can plant a trojan binary.
        if st.st_mode & stat.S_IWOTH and not (st.st_mode & stat.S_ISVTX):
            # Windows drives under WSL always report 0777; that's a filesystem
            # artifact, not a real exposure, so down-rank and explain it.
            win_mount = procinfo.on_windows_mount(d)
            if win_mount:
                severity = Severity.INFO
                detail = (
                    f"{d} appears world-writable, but it is a Windows drive mounted "
                    "under WSL. DrvFs reports mode 0777 for every file regardless of "
                    "the real Windows ACLs, so this is a known false positive rather "
                    "than a Linux permission weakness."
                )
                remediation = (
                    "No action needed for the WSL mount itself. If you care about the "
                    "underlying Windows permissions, manage them from Windows."
                )
            else:
                severity = Severity.HIGH
                detail = (
                    f"{d} is on your PATH and is writable by any user, with no "
                    "sticky bit. Anyone could drop a malicious executable there "
                    "that you would run by name."
                )
                remediation = f"Tighten permissions: chmod o-w {d}  (or remove it from PATH)."
            findings.append(
                Finding(
                    category="privilege",
                    title=f"World-writable PATH directory: {d}",
                    severity=severity,
                    detail=detail,
                    evidence={"dir": d, "mode": oct(st.st_mode), "wsl_windows_mount": win_mount},
                    remediation=remediation,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# 7. LD_PRELOAD / LD_AUDIT library injection (dynamic-linker hijacking)
# ---------------------------------------------------------------------------

# Dynamic-linker variables an attacker uses to force their own code into
# other programs. This is the basis of many userland rootkits and of
# library-based keyloggers that hook libc functions (read/getpass/XNextEvent)
# to capture input across every process they are injected into.
_LD_INJECT_VARS = ("LD_PRELOAD", "LD_AUDIT")

# Directories a legitimately installed shared library should essentially
# never live in. A preload pointing here is a strong malware signal.
_SUSPECT_LIB_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/", "/home/")

_LD_PERSIST_RE = re.compile(
    r"(?:^|[\s;])(?:export\s+)?(LD_PRELOAD|LD_AUDIT)\s*=",
    re.IGNORECASE,
)


def _lib_is_suspect(lib: str) -> tuple[bool, str]:
    """Return (suspect?, reason) for a single preloaded library path."""
    lib = lib.strip()
    if not lib:
        return False, ""
    if any(lib.startswith(d) for d in _SUSPECT_LIB_DIRS):
        return True, "it lives in a temporary / user-writable directory"
    if not lib.startswith("/"):
        # Resolved against each victim process's CWD — a known hijack trick.
        return True, "it is a relative path (resolved per-process, easily hijacked)"
    if not os.path.exists(lib):
        return True, "the library file does not exist on disk"
    return False, ""


def _split_preload(value: str) -> list[str]:
    """LD_PRELOAD entries are separated by spaces and/or colons."""
    return [p for chunk in value.split(":") for p in chunk.split() if p]


def detect_ld_preload() -> list[Finding]:
    findings: list[Finding] = []

    # 7a. /etc/ld.so.preload — a global preload applied to EVERY program.
    preload_file = "/etc/ld.so.preload"
    try:
        if os.path.isfile(preload_file):
            with open(preload_file, "r", errors="replace") as fh:
                content = fh.read()
            libs = _split_preload(content)
            if not libs:
                findings.append(
                    Finding(
                        category="ld-preload",
                        title="/etc/ld.so.preload exists but is empty",
                        severity=Severity.LOW,
                        detail=(
                            "/etc/ld.so.preload is present but empty. Most systems do "
                            "not have this file at all; confirm you expect it to exist."
                        ),
                        evidence={"path": preload_file},
                        remediation="If you did not create it, remove it.",
                    )
                )
            for lib in libs:
                suspect, reason = _lib_is_suspect(lib)
                sev = Severity.HIGH if suspect else Severity.MEDIUM
                detail = (
                    f"'{lib}' is force-loaded into every dynamically linked program on "
                    "the system via /etc/ld.so.preload. Userland rootkits and "
                    "library-based keyloggers use exactly this to hook libc functions "
                    "across all processes at once."
                )
                if suspect:
                    detail += f" It is especially suspicious because {reason}."
                findings.append(
                    Finding(
                        category="ld-preload",
                        title=f"Global library injection via ld.so.preload: {lib}",
                        severity=sev,
                        detail=detail,
                        evidence={"path": preload_file, "library": lib, "suspect": suspect},
                        remediation=(
                            "Verify the library and the package that owns it "
                            "(dpkg -S / rpm -qf). If unrecognised, treat it as a likely "
                            "rootkit: preserve a copy for analysis, then remove the "
                            "entry from /etc/ld.so.preload."
                        ),
                    )
                )
    except OSError:
        pass

    # 7b. LD_PRELOAD / LD_AUDIT set in live process environments.
    # Aggregate by (var, value): one preload inherited by many children should
    # be a single finding, not dozens.
    seen: dict[tuple[str, str], list[int]] = {}
    for proc in procinfo.all_processes(with_fds=False):
        env = procinfo.read_environ(proc.pid)
        for var in _LD_INJECT_VARS:
            value = env.get(var, "").strip()
            if value:
                seen.setdefault((var, value), []).append(proc.pid)

    for (var, value), pids in seen.items():
        reasons = []
        suspect_any = False
        for lib in _split_preload(value):
            is_suspect, reason = _lib_is_suspect(lib)
            if is_suspect:
                suspect_any = True
                reasons.append(f"{lib}: {reason}")
        sev = Severity.HIGH if suspect_any else Severity.MEDIUM
        sample = ", ".join(str(p) for p in pids[:5])
        more = "" if len(pids) <= 5 else f" (+{len(pids) - 5} more)"
        detail = (
            f"{var}={value} is set in the environment of {len(pids)} running "
            f"process(es) [PIDs: {sample}{more}]. {var} forces extra shared libraries "
            "into those programs and can transparently hook their library calls — used "
            "by both legitimate debugging/sanitiser tools and by malware/keyloggers."
        )
        if suspect_any:
            detail += " Suspicious entries — " + "; ".join(reasons) + "."
        findings.append(
            Finding(
                category="ld-preload",
                title=f"{var} set in running process(es)",
                severity=sev,
                detail=detail,
                evidence={"variable": var, "value": value, "pids": pids[:50]},
                remediation=(
                    "Work out why these processes have it set (some sanitisers and "
                    "wrappers use it legitimately). If you did not set it and the "
                    "library is unfamiliar, analyse the library before touching anything."
                ),
            )
        )

    # 7c. LD_PRELOAD / LD_AUDIT persisted in environment / profile files.
    persist_files = ["/etc/environment", "/etc/profile"]
    persist_files += sorted(glob.glob("/etc/profile.d/*.sh"))
    home = os.path.expanduser("~")
    persist_files += [
        os.path.join(home, rc)
        for rc in (".bashrc", ".bash_profile", ".profile", ".zshrc")
    ]
    for path in persist_files:
        try:
            if not os.path.isfile(path):
                continue
            with open(path, "r", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            continue
        found_vars = set()
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue  # ignore comments to avoid false positives
            match = _LD_PERSIST_RE.search(stripped)
            if match:
                found_vars.add(match.group(1).upper())
        for var in sorted(found_vars):
            findings.append(
                Finding(
                    category="ld-preload",
                    title=f"{var} persisted in {path}",
                    severity=Severity.HIGH,
                    detail=(
                        f"{path} sets {var}. This makes a library preload persistent "
                        "across logins/reboots for affected shells (or the whole "
                        "system), a stealthy way to keep injected code — such as a "
                        "keylogging hook — loaded."
                    ),
                    evidence={"path": path, "variable": var},
                    remediation=(
                        f"Open {path} and confirm you added this for a known tool. "
                        "Remove the line if you did not."
                    ),
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

ALL_DETECTORS = {
    "input-monitor": detect_input_monitors,
    "suspicious-process": detect_suspicious_processes,
    "network": detect_network,
    "persistence": detect_persistence,
    "privilege-suid": detect_suid,
    "privilege-path": detect_writable_path,
    "ld-preload": detect_ld_preload,
}
