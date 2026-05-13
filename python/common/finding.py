"""Shared output schema for all Python detections.

Every detection emits findings as newline-delimited JSON to stdout via
`emit(finding)`. The schema and severity ordering are defined here so
downstream consumers (mapper skills, SIEM, jq pipelines) can rely on a
single contract.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import sys
from typing import Any, Iterable

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
GATE_SEVERITY = "HIGH"


@dataclasses.dataclass(frozen=True)
class Finding:
    id: str
    severity: str
    framework: str
    control: str
    resource: str
    evidence: dict[str, Any]
    detected_at: str = dataclasses.field(
        default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    )

    def __post_init__(self) -> None:
        if self.severity not in _SEVERITY_RANK:
            raise ValueError(f"unknown severity {self.severity!r}; expected one of {SEVERITIES}")

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), sort_keys=True, separators=(",", ":"))


def emit(finding: Finding) -> None:
    """Write a single finding to stdout, flushed, so interrupts leave valid NDJSON."""
    sys.stdout.write(finding.to_json() + "\n")
    sys.stdout.flush()


def gate_exit_code(findings: Iterable[Finding], threshold: str = GATE_SEVERITY) -> int:
    """Return 1 if any finding meets or exceeds the threshold severity, else 0."""
    floor = _SEVERITY_RANK[threshold]
    for f in findings:
        if _SEVERITY_RANK[f.severity] >= floor:
            return 1
    return 0


def auth_error(message: str, *, exit_code: int = 2) -> None:
    """Standard fail-closed handler for missing/insufficient credentials."""
    sys.stderr.write(f"ERROR: auth — {message}\n")
    sys.exit(exit_code)
