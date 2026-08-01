#!/usr/bin/env python3
"""Xuất bộ sample evidence thật, nhỏ gọn để commit lên GitHub."""

from __future__ import annotations

import argparse
import copy
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


EVIDENCE_LIMITS = {
    "patch_diff": 2,
    "pull_request_patch": 1,
    "issue_evidence": 1,
    "proof_of_concept": 2,
}

MODEL_LIMITS = {
    "source": 3,
    "sink": 3,
    "propagator": 3,
    "sanitizer_or_barrier": 10,
    "sanitizer_or_guard": 10,
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n",
        encoding="utf-8",
    )


def portable_record(record: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(record)
    source = value.get("source") or {}
    local_paths = source.pop("local_paths", [])
    local_path = source.pop("local_path", None)
    source.pop("local_hashes", None)
    names = [Path(path).name for path in local_paths]
    if local_path:
        names.append(Path(local_path).name)
    if names:
        source["local_artifact_names"] = sorted(set(names))
    value["source"] = source
    repository = value.get("repository") or {}
    if repository.get("raw_path"):
        repository["raw_artifact_name"] = Path(repository.pop("raw_path")).name
    if repository:
        value["repository"] = repository
    value["sample_export"] = {
        "scope": "curated_real_evidence",
        "content_must_not_be_executed": True,
    }
    return value


def select_by_group(
    rows: list[dict[str, Any]], key: str, limits: dict[str, int]
) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    selected: list[dict[str, Any]] = []
    for row in rows:
        group = str(row.get(key))
        if group not in limits or counts[group] >= limits[group]:
            continue
        selected.append(portable_record(row))
        counts[group] += 1
    return selected


def patch_name(artifact_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", artifact_id).strip("_") + ".patch"


def portable_source_path(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base).as_posix()
    except ValueError:
        return path.name


def main() -> int:
    base = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evidence",
        type=Path,
        default=base / "data" / "processed" / "github_evidence.jsonl",
    )
    parser.add_argument(
        "--models",
        type=Path,
        default=base / "data" / "processed" / "codeql_models.jsonl",
    )
    parser.add_argument("--output-dir", type=Path, default=base / "samples")
    args = parser.parse_args()

    evidence = select_by_group(
        load_jsonl(args.evidence), "artifact_type", EVIDENCE_LIMITS
    )
    models = select_by_group(load_jsonl(args.models), "model_group", MODEL_LIMITS)

    write_jsonl(args.output_dir / "github_evidence.jsonl", evidence)
    write_jsonl(args.output_dir / "codeql_models.jsonl", models)

    patch_dir = args.output_dir / "patches"
    patch_dir.mkdir(parents=True, exist_ok=True)
    patch_files: list[str] = []
    for record in evidence:
        if record.get("artifact_type") not in {"patch_diff", "pull_request_patch"}:
            continue
        unified_diff = (record.get("content") or {}).get("unified_diff")
        if not unified_diff:
            continue
        name = patch_name(str(record.get("artifact_id")))
        (patch_dir / name).write_text(unified_diff, encoding="utf-8")
        patch_files.append(f"patches/{name}")

    manifest = {
        "dataset_type": "curated_real_security_evidence",
        "source_files": [
            portable_source_path(args.evidence, base),
            portable_source_path(args.models, base),
        ],
        "github_evidence_count": len(evidence),
        "github_evidence_types": dict(
            Counter(row["artifact_type"] for row in evidence)
        ),
        "codeql_model_count": len(models),
        "codeql_model_groups": dict(Counter(row["model_group"] for row in models)),
        "patch_files": patch_files,
        "safety": "Evidence text only; never execute PoC or downloaded code.",
    }
    (args.output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Evidence samples: {len(evidence)}")
    print(f"CodeQL samples: {len(models)}")
    print(f"Patch files: {len(patch_files)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
