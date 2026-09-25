"""Shared result shape returned by every check in `checks/`."""

from dataclasses import dataclass
from typing import Literal

Status = Literal["pass", "warn", "fail"]


@dataclass(frozen=True)
class CheckResult:
    status: Status
    raw_evidence: str
    explanation: str
