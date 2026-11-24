"""Unit tests for sysguard (stdlib unittest, no external deps).

Run with:  python -m unittest discover -s sysguard/tests
"""

from __future__ import annotations

import os
import socket
import struct
import tempfile
import unittest
from unittest import mock

from sysguard import detectors, engine, netinfo, procinfo
from sysguard.findings import Finding, Severity


class FindingTests(unittest.TestCase):
    def test_to_dict_serialises_severity_as_label(self):
        f = Finding("cat", "title", Severity.HIGH, "detail")
        d = f.to_dict()
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["category"], "cat")

    def test_severity_ordering(self):
        self.assertGreater(Severity.HIGH, Severity.LOW)
        self.assertLess(Severity.INFO, Severity.MEDIUM)


class NetInfoTests(unittest.TestCase):
    def test_decode_ipv4_addr(self):
        # 127.0.0.1:8080 -> little-endian hex of the address + hex port.
        packed = socket.inet_aton("127.0.0.1")
        little = struct.pack("<I", struct.unpack(">I", packed)[0])
        token = f"{little.hex().upper()}:{8080:04X}"
        ip, port = netinfo._decode_addr(token, ipv6=False)
        self.assertEqual(ip, "127.0.0.1")
        self.assertEqual(port, 8080)

    def test_is_loopback(self):
        self.assertTrue(netinfo.is_loopback("127.0.0.1"))
        self.assertTrue(netinfo.is_loopback("::1"))
        self.assertFalse(netinfo.is_loopback("8.8.8.8"))

    def test_parse_file_handles_missing(self):
        self.assertEqual(netinfo._parse_file("/nonexistent/path", "tcp", False), [])


class DetectorContractTests(unittest.TestCase):
    """Every detector must return a list of Findings and never raise."""

    def test_all_detectors_return_findings(self):
        for name, fn in detectors.ALL_DETECTORS.items():
            with self.subTest(detector=name):
                result = fn()
                self.assertIsInstance(result, list)
                for item in result:
                    self.assertIsInstance(item, Finding)


class SuidDetectorTests(unittest.TestCase):
    def test_flags_unknown_suid_binary(self):
        with tempfile.TemporaryDirectory() as d:
            fake = os.path.join(d, "totally-not-normal-suid")
            with open(fake, "w") as fh:
                fh.write("#!/bin/sh\n")
            os.chmod(fake, 0o4755)  # SUID bit set
            # Pretend the file is owned by root so the check fires.
            real_lstat = os.lstat

            def fake_lstat(path, *a, **k):
                st = real_lstat(path, *a, **k)
                if path == fake:
                    return os.stat_result(
                        (st.st_mode, st.st_ino, st.st_dev, st.st_nlink,
                         0, st.st_gid, st.st_size, st.st_atime,
                         st.st_mtime, st.st_ctime)
                    )
                return st

            with mock.patch.object(detectors, "_SUID_SEARCH_DIRS", (d,)), \
                 mock.patch("os.lstat", side_effect=fake_lstat):
                findings = detectors.detect_suid()
            titles = [f.title for f in findings]
            self.assertTrue(any("totally-not-normal-suid" in t for t in titles))


class WritablePathTests(unittest.TestCase):
    def test_flags_world_writable_path_dir(self):
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d, 0o777)  # world-writable, no sticky bit
            with mock.patch.dict(os.environ, {"PATH": d}), \
                 mock.patch("sysguard.procinfo.on_windows_mount", return_value=False):
                findings = detectors.detect_writable_path()
            match = [f for f in findings if d in f.evidence.get("dir", "")]
            self.assertTrue(match)
            self.assertEqual(match[0].severity, Severity.HIGH)

    def test_wsl_windows_mount_is_downranked(self):
        # A WSL Windows drive reports 0777; that must not be a HIGH finding.
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d, 0o777)
            with mock.patch.dict(os.environ, {"PATH": d}), \
                 mock.patch("sysguard.procinfo.on_windows_mount", return_value=True):
                findings = detectors.detect_writable_path()
            match = [f for f in findings if d in f.evidence.get("dir", "")]
            self.assertTrue(match)
            self.assertEqual(match[0].severity, Severity.INFO)
            self.assertTrue(match[0].evidence["wsl_windows_mount"])


class WslHelperTests(unittest.TestCase):
    def test_on_windows_mount_matches_drive_letters_only(self):
        from sysguard import procinfo
        with mock.patch.object(procinfo, "is_wsl", return_value=True):
            self.assertTrue(procinfo.on_windows_mount("/mnt/c/Users/x"))
            self.assertFalse(procinfo.on_windows_mount("/mnt/data/x"))  # not a letter
            self.assertFalse(procinfo.on_windows_mount("/usr/bin"))
        with mock.patch.object(procinfo, "is_wsl", return_value=False):
            self.assertFalse(procinfo.on_windows_mount("/mnt/c/Users/x"))


class LdPreloadTests(unittest.TestCase):
    def test_lib_is_suspect(self):
        self.assertTrue(detectors._lib_is_suspect("/tmp/evil.so")[0])        # temp dir
        self.assertTrue(detectors._lib_is_suspect("relative.so")[0])         # relative
        self.assertTrue(detectors._lib_is_suspect("/no/such/lib_xyz.so")[0]) # missing
        # An existing, absolute path outside the suspect dirs is NOT flagged.
        # (/tmp and /home are themselves suspect, so we use a system path.)
        safe = "/bin/sh"
        if os.path.exists(safe):
            self.assertFalse(detectors._lib_is_suspect(safe)[0])

    def test_split_preload_spaces_and_colons(self):
        self.assertEqual(
            detectors._split_preload("a.so:b.so c.so"), ["a.so", "b.so", "c.so"]
        )

    def test_process_env_preload_is_aggregated_and_high(self):
        fake_procs = [procinfo.Process(pid=10), procinfo.Process(pid=11)]
        with mock.patch.object(procinfo, "all_processes", return_value=fake_procs), \
             mock.patch.object(procinfo, "read_environ",
                               return_value={"LD_PRELOAD": "/tmp/evil.so"}), \
             mock.patch("os.path.isfile", return_value=False), \
             mock.patch("glob.glob", return_value=[]), \
             mock.patch("os.path.expanduser", return_value="/no/such/home"):
            findings = detectors.detect_ld_preload()
        preload = [f for f in findings if f.evidence.get("variable") == "LD_PRELOAD"]
        self.assertEqual(len(preload), 1, "two PIDs with same value -> one finding")
        self.assertEqual(preload[0].severity, Severity.HIGH)  # library is in /tmp
        self.assertEqual(sorted(preload[0].evidence["pids"]), [10, 11])

    def test_persisted_in_rc_file_but_comment_ignored(self):
        with tempfile.TemporaryDirectory() as home:
            with open(os.path.join(home, ".bashrc"), "w") as fh:
                fh.write("# LD_PRELOAD=should_be_ignored\n")
                fh.write("export LD_PRELOAD=/tmp/evil.so\n")
            with open(os.path.join(home, ".profile"), "w") as fh:
                fh.write("# just a comment mentioning LD_PRELOAD=foo\n")
            only_rc = lambda p: p.endswith((".bashrc", ".profile"))  # noqa: E731
            with mock.patch.object(procinfo, "all_processes", return_value=[]), \
                 mock.patch("os.path.isfile", side_effect=only_rc), \
                 mock.patch("glob.glob", return_value=[]), \
                 mock.patch("os.path.expanduser", return_value=home):
                findings = detectors.detect_ld_preload()
            persisted_paths = {f.evidence["path"] for f in findings if "persisted" in f.title}
            self.assertIn(os.path.join(home, ".bashrc"), persisted_paths)
            self.assertNotIn(os.path.join(home, ".profile"), persisted_paths)


class EngineTests(unittest.TestCase):
    def test_run_scan_aggregates_and_times(self):
        result = engine.run_scan()
        self.assertGreaterEqual(result.duration, 0.0)
        self.assertIsInstance(result.counts(), dict)
        self.assertIsInstance(result.to_dict(), dict)

    def test_one_bad_detector_does_not_abort(self):
        boom = {"boom": lambda: (_ for _ in ()).throw(RuntimeError("boom"))}
        with mock.patch.object(engine, "ALL_DETECTORS", boom):
            result = engine.run_scan(["boom"])
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(result.findings, [])

    def test_selected_subset(self):
        result = engine.run_scan(["network"])
        # Should not raise and should produce a well-formed result.
        self.assertIsInstance(result.sorted_findings(), list)


if __name__ == "__main__":
    unittest.main()
