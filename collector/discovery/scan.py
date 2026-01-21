from dataclasses import dataclass


@dataclass(frozen=True)
class ScanTarget:
    cidr: str


def run_scan(target: ScanTarget) -> list[dict]:
    return [{"ip": target.cidr, "status": "placeholder"}]
