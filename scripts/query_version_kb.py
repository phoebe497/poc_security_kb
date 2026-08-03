#!/usr/bin/env python3
"""Tra cứu evidence bảo mật cho một phiên bản Django hoặc Log4j Core."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable


LIBRARY_ALIASES = {
    "django": "django",
    "pypi:django": "django",
    "log4j": "log4j",
    "log4j-core": "log4j",
    "maven:org.apache.logging.log4j:log4j-core": "log4j",
}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Không tìm thấy dataset: {path}")
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def fixed_versions(advisory: dict[str, Any], library_id: str) -> list[str]:
    expected = {
        "django": ("pypi", "django"),
        "log4j": ("maven", "org.apache.logging.log4j:log4j-core"),
    }[library_id]
    values: list[str] = []
    for affected in advisory.get("affected") or []:
        package = affected.get("package") or {}
        key = (
            str(package.get("ecosystem") or "").casefold(),
            str(package.get("name") or "").casefold(),
        )
        if key != expected:
            continue
        for version_range in affected.get("ranges") or []:
            for event in version_range.get("events") or []:
                if event.get("fixed"):
                    values.append(str(event["fixed"]))
    return unique(values)


def build_version_report(
    dataset_dir: Path,
    library_id: str,
    version: str,
) -> dict[str, Any]:
    releases = read_jsonl(dataset_dir / "library_releases.jsonl")
    matrix = read_jsonl(dataset_dir / "version_security_matrix.jsonl")
    advisories = read_jsonl(dataset_dir / "advisories.jsonl")
    patches = read_jsonl(dataset_dir / "patch_diffs.jsonl")
    release = next(
        (
            item
            for item in releases
            if item.get("library_id") == library_id and item.get("version") == version
        ),
        None,
    )
    status = next(
        (
            item
            for item in matrix
            if item.get("library_id") == library_id and item.get("version") == version
        ),
        None,
    )
    if not release or not status:
        available = [
            item.get("version")
            for item in releases
            if item.get("library_id") == library_id
        ]
        raise ValueError(
            f"Không có version {version!r} của {library_id}. "
            f"Dataset có {len(available)} version; hãy crawl/refresh lại nếu đây là release mới."
        )

    vulnerability_ids = set(status.get("vulnerability_ids") or [])
    matched_advisories = []
    matched_ids: set[str] = set()
    for advisory in advisories:
        identity = {str(advisory.get("id") or ""), *(advisory.get("aliases") or [])}
        if vulnerability_ids.intersection(identity):
            matched_advisories.append(advisory)
            matched_ids.update(identity)
    patch_records = [
        item
        for item in patches
        if item.get("library_id") == library_id
        and set(item.get("advisory_ids") or []).intersection(matched_ids)
    ]
    evidence = []
    for advisory in matched_advisories:
        advisory_identity = {advisory.get("id"), *(advisory.get("aliases") or [])}
        advisory_patches = [
            item
            for item in patch_records
            if set(item.get("advisory_ids") or []).intersection(advisory_identity)
        ]
        evidence.append(
            {
                "id": advisory.get("id"),
                "aliases": advisory.get("aliases") or [],
                "summary": advisory.get("summary"),
                "fixed_versions": fixed_versions(advisory, library_id),
                "commit_shas": [item.get("commit_sha") for item in advisory_patches],
                "references": advisory.get("references") or [],
            }
        )
    missing = sorted(vulnerability_ids - matched_ids)
    return {
        "library_id": library_id,
        "package": release.get("package"),
        "version": version,
        "published_at": release.get("published_at"),
        "yanked": release.get("yanked"),
        "status": status.get("status"),
        "status_semantics": status.get("status_semantics"),
        "vulnerability_ids": sorted(vulnerability_ids),
        "advisory_evidence": evidence,
        "patch_count": len(patch_records),
        "missing_advisory_snapshots": missing,
        "verdict_note": (
            "Package/version affected không tự chứng minh finding SAST exploitable; "
            "cần đối chiếu source, sink, sanitizer, call path và điều kiện cấu hình."
        ),
    }


def render_markdown(report: dict[str, Any]) -> str:
    package = report.get("package") or {}
    lines = [
        f"# Version KB: {report['library_id']} {report['version']}",
        "",
        f"- Package: `{package.get('ecosystem')}:{package.get('name')}`",
        f"- Published: `{report.get('published_at')}`",
        f"- Status: **{report.get('status')}**",
        f"- Vulnerability IDs: **{len(report.get('vulnerability_ids') or [])}**",
        f"- Patch snapshots matched: **{report.get('patch_count')}**",
        "",
        f"> {report.get('status_semantics')}",
        "",
        "## Advisory evidence đã snapshot",
        "",
    ]
    for advisory in report.get("advisory_evidence") or []:
        fixed = ", ".join(advisory.get("fixed_versions") or []) or "chưa xác định"
        commits = ", ".join(advisory.get("commit_shas") or []) or "chưa crawl patch"
        lines.extend(
            [
                f"### {advisory.get('id')}",
                "",
                f"- {advisory.get('summary')}",
                f"- Fixed version(s): `{fixed}`",
                f"- Patch commit(s): `{commits}`",
                "",
            ]
        )
    if not report.get("advisory_evidence"):
        lines.append("- Không có advisory detail trong sample hiện tại.")
        lines.append("")
    missing = report.get("missing_advisory_snapshots") or []
    if missing:
        lines.extend(
            [
                "## Evidence chưa snapshot trong sample",
                "",
                f"Còn {len(missing)} ID chỉ có trong matrix. Chạy crawler với "
                "`--max-advisories 0` để lấy toàn bộ detail.",
                "",
            ]
        )
    lines.extend(["## Lưu ý verdict", "", report["verdict_note"], ""])
    return "\n".join(lines)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--library",
        required=True,
        help="django, log4j, log4j-core hoặc canonical ecosystem:package.",
    )
    parser.add_argument("--version", required=True)
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=project_root / "data" / "samples" / "sprint-03-version-aware-kb",
    )
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    args = parser.parse_args()
    library_key = args.library.casefold()
    library_id = LIBRARY_ALIASES.get(library_key)
    if not library_id:
        parser.error("--library chỉ hỗ trợ django hoặc log4j/log4j-core")
    try:
        report = build_version_report(args.dataset_dir, library_id, args.version)
    except (FileNotFoundError, ValueError) as exc:
        parser.error(str(exc))
    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(render_markdown(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
