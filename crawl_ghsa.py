#!/usr/bin/env python3
"""PoC: thu thập GitHub Security Advisories và chuẩn hóa cho Security KB."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


API_URL = "https://api.github.com/advisories"
CSV_FIELDS = [
    "ghsa_id",
    "cve_id",
    "severity",
    "summary",
    "cwe_ids",
    "ecosystems",
    "packages",
    "vulnerable_version_ranges",
    "first_patched_versions",
    "published_at",
    "updated_at",
    "html_url",
]


def fetch_advisories(limit: int) -> list[dict[str, Any]]:
    query = urllib.parse.urlencode(
        {
            "type": "reviewed",
            "sort": "published",
            "direction": "desc",
            "per_page": limit,
        }
    )
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "security-kb-poc/1.0",
    }
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(f"{API_URL}?{query}", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub API trả về HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Không thể kết nối GitHub API: {exc.reason}") from exc


def normalize(advisory: dict[str, Any], collected_at: str) -> dict[str, Any]:
    cwes = [
        {"id": item.get("cwe_id"), "name": item.get("name")}
        for item in advisory.get("cwes", [])
    ]
    affected_packages = []
    for vulnerability in advisory.get("vulnerabilities", []):
        package = vulnerability.get("package") or {}
        fixed = vulnerability.get("first_patched_version")
        if isinstance(fixed, dict):
            fixed_version = fixed.get("identifier")
        elif isinstance(fixed, str):
            fixed_version = fixed
        else:
            fixed_version = None
        affected_packages.append(
            {
                "ecosystem": package.get("ecosystem"),
                "name": package.get("name"),
                "vulnerable_version_range": vulnerability.get(
                    "vulnerable_version_range"
                ),
                "first_patched_version": fixed_version,
                "vulnerable_functions": vulnerability.get(
                    "vulnerable_functions", []
                ),
            }
        )

    return {
        "knowledge_id": f"GHSA-{advisory.get('ghsa_id', 'UNKNOWN')}",
        "knowledge_type": "security_advisory",
        "ghsa_id": advisory.get("ghsa_id"),
        "cve_id": advisory.get("cve_id"),
        "summary": advisory.get("summary"),
        "description": advisory.get("description"),
        "severity": advisory.get("severity"),
        "cwes": cwes,
        "affected_packages": affected_packages,
        "cvss": advisory.get("cvss"),
        "references": advisory.get("references", []),
        "published_at": advisory.get("published_at"),
        "updated_at": advisory.get("updated_at"),
        "withdrawn_at": advisory.get("withdrawn_at"),
        "source": {
            "name": "GitHub Advisory Database",
            "url": advisory.get("html_url"),
            "api_url": advisory.get("url"),
            "reviewed_at": advisory.get("github_reviewed_at"),
            "trust_level": "official_reviewed",
        },
        "collection": {
            "collected_at": collected_at,
            "collector": "poc_security_kb/crawl_ghsa.py",
            "schema_version": "1.0",
        },
    }


def csv_row(record: dict[str, Any]) -> dict[str, str]:
    packages = record["affected_packages"]
    return {
        "ghsa_id": record.get("ghsa_id") or "",
        "cve_id": record.get("cve_id") or "",
        "severity": record.get("severity") or "",
        "summary": record.get("summary") or "",
        "cwe_ids": "; ".join(
            item["id"] for item in record["cwes"] if item.get("id")
        ),
        "ecosystems": "; ".join(
            sorted({item["ecosystem"] for item in packages if item.get("ecosystem")})
        ),
        "packages": "; ".join(
            item["name"] for item in packages if item.get("name")
        ),
        "vulnerable_version_ranges": "; ".join(
            item["vulnerable_version_range"]
            for item in packages
            if item.get("vulnerable_version_range")
        ),
        "first_patched_versions": "; ".join(
            item["first_patched_version"]
            for item in packages
            if item.get("first_patched_version")
        ),
        "published_at": record.get("published_at") or "",
        "updated_at": record.get("updated_at") or "",
        "html_url": record["source"].get("url") or "",
    }


def write_summary(records: list[dict[str, Any]], path: Path) -> None:
    severity_counts = Counter(record.get("severity") or "unknown" for record in records)
    cwe_counts = Counter(
        cwe["id"]
        for record in records
        for cwe in record["cwes"]
        if cwe.get("id")
    )
    ecosystem_counts = Counter(
        package["ecosystem"]
        for record in records
        for package in record["affected_packages"]
        if package.get("ecosystem")
    )

    lines = [
        "# Tóm tắt PoC thu thập dữ liệu Security KB",
        "",
        f"- Số advisory đã thu thập: **{len(records)}**",
        "- Nguồn: **GitHub Advisory Database (reviewed advisories)**",
        f"- Thời điểm thu thập: **{records[0]['collection']['collected_at'] if records else 'N/A'}**",
        "",
        "## Phân bố severity",
        "",
        "| Severity | Số lượng |",
        "|---|---:|",
    ]
    lines.extend(
        f"| {name} | {count} |"
        for name, count in severity_counts.most_common()
    )
    lines.extend(
        [
            "",
            "## CWE xuất hiện nhiều nhất",
            "",
            "| CWE | Số lượng |",
            "|---|---:|",
        ]
    )
    lines.extend(f"| {name} | {count} |" for name, count in cwe_counts.most_common(10))
    lines.extend(
        [
            "",
            "## Hệ sinh thái package",
            "",
            "| Ecosystem | Số lượng |",
            "|---|---:|",
        ]
    )
    lines.extend(
        f"| {name} | {count} |"
        for name, count in ecosystem_counts.most_common()
    )
    lines.extend(
        [
            "",
            "## Giới hạn của PoC",
            "",
            "- Đây là mẫu thu thập metadata, chưa phải Knowledge Base hoàn chỉnh.",
            "- Dữ liệu chưa chứa source, sink, sanitizer, patch diff hoặc PoC đã chuẩn hóa.",
            "- Cần bổ sung bước liên kết advisory với commit, test và rule trong giai đoạn tiếp theo.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Thu thập mẫu GitHub Security Advisories cho Security KB."
    )
    parser.add_argument("--limit", type=int, default=30, help="Số record, tối đa 100.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).parent / "output",
        help="Thư mục đầu ra.",
    )
    args = parser.parse_args()

    if not 1 <= args.limit <= 100:
        parser.error("--limit phải nằm trong khoảng 1..100")

    collected_at = datetime.now(timezone.utc).isoformat()
    raw = fetch_advisories(args.limit)
    records = [normalize(item, collected_at) for item in raw]

    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / "ghsa_advisories.json"
    csv_path = args.output_dir / "ghsa_advisories.csv"
    summary_path = args.output_dir / "summary.md"

    json_path.write_text(
        json.dumps(records, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    with csv_path.open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(csv_row(record) for record in records)
    write_summary(records, summary_path)

    print(f"Collected {len(records)} advisories.")
    print(f"JSON: {json_path.resolve()}")
    print(f"CSV: {csv_path.resolve()}")
    print(f"Summary: {summary_path.resolve()}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"Lỗi: {exc}", file=sys.stderr)
        raise SystemExit(1)
