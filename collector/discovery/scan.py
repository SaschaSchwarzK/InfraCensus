from dataclasses import dataclass

from collector.scanners.base import ScanResult


@dataclass(frozen=True)
class ScanTarget:
    cidr: str


def run_scan(target: ScanTarget) -> list[ScanResult]:
    return [
        ScanResult(
            ip=target.cidr,
            success=True,
            duration_ms=0,
            data={"status": "placeholder"},
        )
    ]
