# sysguard

> A small, **read-only** local threat scanner for Linux — it looks for the
> behaviour a software **keylogger** (and other local threats) leaves behind,
> explains what it found, and tells you what to do about it.
>
> CLI **and** a Tkinter GUI. Pure Python standard library — no third-party
> dependencies.

`sysguard` is a **defensive** security tool. It does **not** capture keystrokes,
spy on anyone, or change your system. It only *observes* and *reports*. Think of
it as a flashlight you shine into the corners where local malware likes to hide.

---

## ⚠️ Read this first — dangers, ethics & the law

Security tools cut both ways, and even a purely defensive one can cause harm if
you misuse it. Please take this section as seriously as the code.

### What sysguard will and will not do

| | |
|---|---|
| ✅ **Reads** `/proc`, `/proc/net`, your crontab, autostart & shell files, and file permissions | ❌ **Never** records keystrokes or any user input |
| ✅ **Reports** suspicious *behaviour* for a human to judge | ❌ **Never** modifies, kills, quarantines or deletes anything |
| ✅ Runs entirely locally; sends **no data anywhere** | ❌ **Never** phones home or uploads your results |
| ✅ Tells you *why* something is flagged and what to check | ❌ Does **not** prove a machine is clean or infected |

### Only scan computers you are allowed to scan

Run `sysguard` **only** on:

- a computer you **own**, or
- a computer you have **explicit, documented authorisation** to inspect
  (e.g. a lab machine your course provides, or a client system under a signed
  engagement).

Scanning a machine you don't control — even "just looking" — can violate
computer-misuse law (e.g. the US CFAA, the UK Computer Misuse Act, Poland's
*Kodeks karny* art. 267) and your institution's acceptable-use policy. **When in
doubt, get written permission first.**

### A detector is not a cure

- `sysguard` is a **teaching / triage** tool, **not** an antivirus or EDR. It
  runs a fixed set of heuristic checks. Malware that is sophisticated, brand-new,
  kernel-level, or simply outside these checks **will not be caught.**
- A **clean result means "these specific checks found nothing"** — nothing more.
- A flagged item is a **lead, not a verdict.** Several checks intentionally report
  benign-but-noteworthy things (a display server reading input devices is normal).
  Investigate before you act.

### Handle findings responsibly

- If you suspect a real compromise: **preserve evidence first** (note the process
  path, command line, hashes, network peers) *before* killing processes or
  deleting files. Destroying evidence can turn a recoverable incident into an
  unsolvable one.
- Treat anything you discover about other users on a shared system as
  **confidential.**

### About the keylogger connection

This project was written for a **university cybersecurity course** to study how
software keyloggers work **so they can be detected**. It contains **no keylogging
code** and is **not** derived from any keylogger project — it is the *defensive
counterpart*: the tool that finds the behaviour a keylogger exhibits (reading raw
`/dev/input` events, persisting across reboots, exfiltrating over the network).
If you want to understand the offensive side, study it **in the abstract and in a
lab you control** — don't deploy keystroke capture on anyone else's machine.

---

## What it checks

| Detector | Looks for | Why it matters |
|---|---|---|
| `input-monitor` | Processes reading raw events from `/dev/input/*` | This is exactly how a software **keylogger** captures keystrokes. Known components (Xorg, the compositor, IME) are recognised and down-ranked. |
| `suspicious-process` | Processes running from `/tmp`, `/dev/shm`, `/var/tmp`, or whose binary was **deleted** while running | Classic malware tradecraft to hide and resist analysis. |
| `network` | Listening ports and established outbound connections, attributed to a process | Backdoors listen; spyware **exfiltrates** captured data outward. |
| `persistence` | User crontab, XDG autostart, systemd **user** services, and suspicious lines in shell startup files | How malware **survives a reboot**. Shell files are scanned for download-and-run and reverse-shell patterns. |
| `privilege-suid` | Unusual **SUID-root** binaries outside a known-common allowlist | A planted SUID binary is a textbook **privilege-escalation** backdoor. |
| `privilege-path` | **World-writable** directories on your `PATH` | Anyone could drop a trojan binary you'd then run by name. (WSL Windows mounts are detected and down-ranked — see below.) |
| `ld-preload` | `/etc/ld.so.preload`, and `LD_PRELOAD`/`LD_AUDIT` in process environments or persisted in profile files | Dynamic-linker hijacking: force-loads attacker code into other programs. Used by userland rootkits and by **library-based keyloggers** that hook libc input functions. Libraries in temp dirs, relative paths, or missing files are escalated to HIGH. |

Each finding carries a **severity** (`INFO` / `LOW` / `MEDIUM` / `HIGH`), a
plain-language explanation, supporting **evidence**, and a **remediation** hint.

---

## Requirements

- **Linux** (reads the Linux `/proc` filesystem). Also runs under **WSL2**, which
  it detects and adjusts for.
- **Python 3.9+**
- **Tkinter** for the GUI (CPython ships with it; on Debian/Ubuntu install with
  `sudo apt install python3-tk`). The **CLI needs nothing extra.**

No `pip install` of third-party packages is required.

---

## Install / run

Clone and run straight from the source tree — no build step needed:

```bash
git clone https://github.com/fdragowski480677/sysguard.git
cd sysguard

# CLI scan
python3 -m sysguard

# GUI
python3 -m sysguard --gui
```

Or install it as a package (gives you the `sysguard` and `sysguard-gui` commands):

```bash
pip install .
sysguard            # CLI
sysguard-gui        # GUI
```

### Run as root for full coverage

Without root, processes, sockets and files owned by **other users are invisible**
to the scanner, and network connections can't always be attributed to a process.
For a complete scan on a multi-user system:

```bash
sudo python3 -m sysguard
```

`sysguard` tells you (in both CLI and GUI) when it's running without root.

---

## CLI usage

```
python3 -m sysguard [options]

  -d, --detector NAME   Run only this detector (repeatable). Default: all.
      --min-severity S  Hide findings below S (INFO|LOW|MEDIUM|HIGH).
      --json            Machine-readable JSON (good for reports / CI).
      --no-color        Disable ANSI colours.
      --list            List available detectors and exit.
```

Examples:

```bash
# Only the keylogger-style and persistence checks, medium severity and up
python3 -m sysguard -d input-monitor -d persistence --min-severity MEDIUM

# JSON report you can attach to your write-up
python3 -m sysguard --json > sysguard-report.json
```

**Exit codes:** `0` = no actionable findings · `2` = at least one `MEDIUM`+
finding to review. (Handy for scripts and CI.)

---

## GUI usage

`python3 -m sysguard --gui` opens a window where you can:

- run a scan on a background thread (the UI stays responsive),
- filter by minimum severity,
- click any finding to see its full detail, evidence and remediation,
- export the whole report to JSON.

The scan is read-only; the GUI changes nothing on your system.

---

## A note on WSL2

Windows drives mounted under WSL (e.g. `/mnt/c`) use DrvFs/9p, which reports mode
`0777` for **every** file regardless of the real Windows permissions. A naive
check would scream that half your `PATH` is world-writable. `sysguard` detects WSL
and **down-ranks those `/mnt/<letter>` findings to `INFO`** with an explanation,
so the signal isn't drowned in false positives.

---

## Development

Tests use only the standard library (`unittest`):

```bash
python3 -m unittest discover -s sysguard/tests -v
```

Project layout:

```
sysguard/
├── findings.py     # Finding dataclass + Severity enum
├── procinfo.py     # read-only /proc + process helpers (incl. WSL awareness)
├── netinfo.py      # parse /proc/net/tcp{,6},udp{,6} with no external tools
├── detectors.py    # the individual checks
├── engine.py       # runs detectors safely, aggregates results
├── cli.py          # command-line interface
├── gui.py          # Tkinter GUI
├── __main__.py     # `python -m sysguard`
└── tests/          # unittest suite
```

**Ideas for extending it** (good next steps for a course project):

- hash flagged binaries and check them against a local allowlist / VirusTotal
  (offline hash only — don't upload files),
- ~~detect LD_PRELOAD / `/etc/ld.so.preload` hijacks~~ ✅ **done** (the
  `ld-preload` detector),
- watch for changes between scans (a lightweight baseline/diff mode),
- add a packaged `.desktop` launcher,
- a kernel-module listing check for simple rootkits.

---

## Limitations (be honest in your report)

- **Userland, read-only, heuristic.** It cannot see kernel rootkits, hardware
  keyloggers, or anything that actively hides from `/proc`.
- **Linux-specific.** The checks rely on Linux `/proc` semantics.
- **Not a replacement** for maintained anti-malware/EDR or for good hygiene
  (updates, least privilege, not running untrusted code).

---

## License

[MIT](LICENSE) © 2026 Franciszek Drągowski
