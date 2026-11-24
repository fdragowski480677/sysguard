"""Data model for scan results."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """How urgent a finding is. Higher value = more serious."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name


@dataclass
class Finding:
    """A single thing the scanner noticed.

    A finding is *not* proof of compromise. It is an observation that a
    human should review, together with an explanation of why it matters
    and what to do about it.
    """

    category: str
    title: str
    severity: Severity
    detail: str
    evidence: dict = field(default_factory=dict)
    remediation: str = ""

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.label
        return data
