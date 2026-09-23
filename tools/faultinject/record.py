from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path


HYBRID_GROUPS = {
    "X25519MLKEM768",
    "X25519Kyber768Draft00",
    "sntrup761x25519-sha512@openssh.com",
}


def run_id(impl: str, fault: str, rep: int, condition: str) -> str:
    return f"{impl}_{fault}_r{rep:02d}_{condition}"


@dataclass
class Metrics:
    negotiated_group: str | None
    is_hybrid: bool
    downgrade_visible: bool
    handshake_result: str
    detail: str = ""
    hrr_present: bool | None = None
    downgrade_flagged: bool | None = None
    advertised_hybrid: bool | None = None


@dataclass
class RunRecord:
    run_id: str
    implementation: str
    fault_type: str
    repetition: int
    condition: str
    metrics: Metrics
    manipulation_verified: bool
    artifacts: dict = field(default_factory=dict)

    def to_json_path(self, base_dir: str | Path) -> Path:
        path = Path(base_dir) / f"{self.run_id}.json"
        path.write_text(
            json.dumps(asdict(self), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return path

    @classmethod
    def from_json(cls, path: str | Path) -> "RunRecord":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        data["metrics"] = Metrics(**data["metrics"])
        return cls(**data)
