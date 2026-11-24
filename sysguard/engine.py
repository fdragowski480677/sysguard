"""Run detectors safely and aggregate their findings."""

from __future__ import annotations

import time
import traceback
from collections.abc import Callable, Iterable

from . import procinfo
from .detectors import ALL_DETECTORS
from .findings import Finding, Severity


class ScanResult:
    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.errors: list[tuple[str, str]] = []
        self.started_at: float = 0.0
        self.finished_at: float = 0.0
        self.ran_as_root: bool = False

    @property
    def duration(self) -> float:
        return self.finished_at - self.started_at

    def counts(self) -> dict[str, int]:
        out = {s.label: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-int(f.severity), f.category, f.title))

    def to_dict(self) -> dict:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.duration, 3),
            "ran_as_root": self.ran_as_root,
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "errors": [{"detector": d, "error": e} for d, e in self.errors],
        }


def run_scan(
    selected: Iterable[str] | None = None,
    *,
    progress: Callable[[str, int, int], None] | None = None,
) -> ScanResult:
    """Run the chosen detectors (all by default).

    ``progress`` is an optional callback ``(detector_name, index, total)``
    invoked before each detector, so a GUI can show progress.
    """
    names = list(selected) if selected is not None else list(ALL_DETECTORS)
    total = len(names)

    result = ScanResult()
    result.started_at = time.time()
    result.ran_as_root = procinfo.running_as_root()

    for i, name in enumerate(names):
        detector = ALL_DETECTORS.get(name)
        if detector is None:
            result.errors.append((name, "unknown detector"))
            continue
        if progress is not None:
            progress(name, i, total)
        try:
            result.findings.extend(detector())
        except Exception:  # noqa: BLE001 - one bad detector must not kill the scan
            result.errors.append((name, traceback.format_exc()))

    result.finished_at = time.time()
    return result
