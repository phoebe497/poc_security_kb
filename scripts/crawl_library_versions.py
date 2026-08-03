#!/usr/bin/env python3
"""Crawl KB theo phiên bản thư viện cho Django và Apache Log4j.

Pipeline chỉ tải metadata/advisory dạng dữ liệu; không tải hoặc thực thi PoC.
Registry là nguồn inventory phiên bản, còn OSV querybatch quyết định trạng thái
"known affected" cho đúng từng version theo quy tắc của ecosystem.
"""

from __future__ import annotations

import argparse
import json
import urllib.parse
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from kb_common import (
    HttpClient,
    parse_github_reference,
    safe_slug,
    sha256_bytes,
    utc_now,
    write_json,
    write_jsonl,
)


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"


@dataclass(frozen=True)
class LibraryConfig:
    library_id: str
    display_name: str
    ecosystem: str
    package_name: str
    purl: str
    registry: str
    repository_url: str
    official_security_url: str


LIBRARIES = {
    "django": LibraryConfig(
        library_id="django",
        display_name="Django",
        ecosystem="PyPI",
        package_name="Django",
        purl="pkg:pypi/django",
        registry="pypi",
        repository_url="https://github.com/django/django",
        official_security_url="https://docs.djangoproject.com/en/stable/releases/security/",
    ),
    "log4j": LibraryConfig(
        library_id="log4j",
        display_name="Apache Log4j Core",
        ecosystem="Maven",
        package_name="org.apache.logging.log4j:log4j-core",
        purl="pkg:maven/org.apache.logging.log4j/log4j-core",
        registry="maven",
        repository_url="https://github.com/apache/logging-log4j2",
        official_security_url="https://logging.apache.org/security.html",
    ),
}


def chunks(values: list[Any], size: int) -> Iterable[list[Any]]:
    for index in range(0, len(values), size):
        yield values[index : index + size]


def fetch_json_get(
    client: HttpClient,
    url: str,
    raw_path: Path,
    *,
    max_bytes: int = 20 * 1024 * 1024,
) -> tuple[Any, dict[str, str]]:
    raw, metadata = client.get_bytes(
        url,
        accept="application/json",
        max_bytes=max_bytes,
    )
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_bytes(raw)
    return json.loads(raw.decode("utf-8")), {
        "url": url,
        "retrieved_at": utc_now(),
        "content_sha256": sha256_bytes(raw),
        "raw_path": str(raw_path),
        **metadata,
    }


def release_record(
    config: LibraryConfig,
    version: str,
    published_at: str | None,
    artifacts: list[dict[str, Any]],
    source: dict[str, Any],
    *,
    yanked: bool = False,
    yanked_reason: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "2.0",
        "record_type": "library_release",
        "library_id": config.library_id,
        "display_name": config.display_name,
        "package": {
            "ecosystem": config.ecosystem,
            "name": config.package_name,
            "purl": config.purl,
        },
        "version": version,
        "published_at": published_at,
        "yanked": yanked,
        "yanked_reason": yanked_reason,
        "artifacts": artifacts,
        "repository_url": config.repository_url,
        "official_security_url": config.official_security_url,
        "source": source,
    }


def crawl_pypi(
    client: HttpClient,
    config: LibraryConfig,
    raw_dir: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    url = f"https://pypi.org/pypi/{urllib.parse.quote(config.package_name)}/json"
    payload, source = fetch_json_get(client, url, raw_dir / "pypi-project.json")
    records: list[dict[str, Any]] = []
    for version, files in (payload.get("releases") or {}).items():
        files = files or []
        upload_times = sorted(
            value
            for value in (item.get("upload_time_iso_8601") for item in files)
            if value
        )
        artifacts = [
            {
                "filename": item.get("filename"),
                "package_type": item.get("packagetype"),
                "url": item.get("url"),
                "size": item.get("size"),
                "sha256": (item.get("digests") or {}).get("sha256"),
                "requires_python": item.get("requires_python"),
                "yanked": bool(item.get("yanked")),
            }
            for item in files
        ]
        yanked = bool(files) and all(bool(item.get("yanked")) for item in files)
        reasons = sorted(
            {
                str(item.get("yanked_reason"))
                for item in files
                if item.get("yanked_reason")
            }
        )
        records.append(
            release_record(
                config,
                version,
                upload_times[0] if upload_times else None,
                artifacts,
                source,
                yanked=yanked,
                yanked_reason="; ".join(reasons) or None,
            )
        )
    return records, [source]


def crawl_maven(
    client: HttpClient,
    config: LibraryConfig,
    raw_dir: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    group_id, artifact_id = config.package_name.split(":", 1)
    query = f'g:"{group_id}" AND a:"{artifact_id}"'
    rows = 200
    start = 0
    records: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    while True:
        params = urllib.parse.urlencode(
            {
                "q": query,
                "core": "gav",
                "rows": rows,
                "start": start,
                "wt": "json",
            }
        )
        url = f"https://search.maven.org/solrsearch/select?{params}"
        payload, source = fetch_json_get(
            client,
            url,
            raw_dir / f"maven-page-{start // rows + 1}.json",
        )
        sources.append(source)
        response = payload.get("response") or {}
        docs = response.get("docs") or []
        for item in docs:
            version = str(item.get("v") or "")
            if not version:
                continue
            timestamp = item.get("timestamp")
            published_at = None
            if isinstance(timestamp, (int, float)):
                from datetime import datetime, timezone

                published_at = datetime.fromtimestamp(
                    timestamp / 1000,
                    timezone.utc,
                ).isoformat()
            records.append(
                release_record(
                    config,
                    version,
                    published_at,
                    [
                        {
                            "repository": "Maven Central",
                            "group_id": group_id,
                            "artifact_id": artifact_id,
                            "packaging": item.get("p"),
                            "extensions": item.get("ec") or [],
                        }
                    ],
                    source,
                )
            )
        start += len(docs)
        if not docs or start >= int(response.get("numFound") or 0):
            break
    return records, sources


def crawl_registry(
    client: HttpClient,
    config: LibraryConfig,
    raw_dir: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if config.registry == "pypi":
        return crawl_pypi(client, config, raw_dir)
    if config.registry == "maven":
        return crawl_maven(client, config, raw_dir)
    raise ValueError(f"Registry chưa được hỗ trợ: {config.registry}")


def crawl_osv_matrix(
    client: HttpClient,
    config: LibraryConfig,
    releases: list[dict[str, Any]],
    raw_dir: Path,
    batch_size: int,
) -> tuple[list[dict[str, Any]], Counter[str], list[dict[str, Any]], list[str]]:
    matrix: list[dict[str, Any]] = []
    vuln_counts: Counter[str] = Counter()
    sources: list[dict[str, Any]] = []
    errors: list[str] = []
    for page, batch in enumerate(chunks(releases, batch_size), start=1):
        payload = {
            "queries": [
                {
                    "package": {
                        "ecosystem": config.ecosystem,
                        "name": config.package_name,
                    },
                    "version": item["version"],
                }
                for item in batch
            ]
        }
        try:
            response, raw, metadata = client.post_json(
                OSV_BATCH_URL,
                payload,
                max_bytes=20 * 1024 * 1024,
            )
            raw_path = raw_dir / f"osv-querybatch-{page}.json"
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            raw_path.write_bytes(raw)
            sources.append(
                {
                    "url": OSV_BATCH_URL,
                    "retrieved_at": utc_now(),
                    "content_sha256": sha256_bytes(raw),
                    "raw_path": str(raw_path),
                    **metadata,
                }
            )
            results = response.get("results") or []
            if len(results) != len(batch):
                raise RuntimeError(
                    f"OSV trả {len(results)} kết quả cho {len(batch)} queries"
                )
            for release, result in zip(batch, results):
                vulns = sorted(
                    {
                        str(item.get("id"))
                        for item in (result.get("vulns") or [])
                        if item.get("id")
                    }
                )
                vuln_counts.update(vulns)
                if result.get("next_page_token"):
                    errors.append(
                        f"OSV pagination chưa xử lý cho {config.library_id} "
                        f"{release['version']}"
                    )
                matrix.append(
                    {
                        "schema_version": "2.0",
                        "record_type": "library_version_security_status",
                        "library_id": config.library_id,
                        "package": release["package"],
                        "version": release["version"],
                        "published_at": release.get("published_at"),
                        "status": (
                            "known_affected" if vulns else "no_known_vulnerability"
                        ),
                        "vulnerability_ids": vulns,
                        "status_semantics": (
                            "OSV khớp ít nhất một advisory với đúng ecosystem/package/version; "
                            "vẫn cần kiểm tra điều kiện khai thác trong code đang scan."
                            if vulns
                            else "Không có advisory trong OSV không đồng nghĩa phiên bản an toàn."
                        ),
                        "query_method": "OSV /v1/querybatch exact ecosystem version",
                        "queried_at": utc_now(),
                    }
                )
        except RuntimeError as exc:
            errors.append(str(exc))
            for release in batch:
                matrix.append(
                    {
                        "schema_version": "2.0",
                        "record_type": "library_version_security_status",
                        "library_id": config.library_id,
                        "package": release["package"],
                        "version": release["version"],
                        "published_at": release.get("published_at"),
                        "status": "query_error",
                        "vulnerability_ids": [],
                        "status_semantics": "Không được suy diễn an toàn khi query lỗi.",
                        "query_method": "OSV /v1/querybatch exact ecosystem version",
                        "queried_at": utc_now(),
                    }
                )
    return matrix, vuln_counts, sources, errors


def crawl_advisory_details(
    client: HttpClient,
    vulnerability_counts_by_library: dict[str, Counter[str]],
    configs: dict[str, LibraryConfig],
    raw_root: Path,
    max_advisories: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str], list[str]]:
    all_counts: Counter[str] = Counter()
    for counts in vulnerability_counts_by_library.values():
        all_counts.update(counts)
    ranked_all = sorted(
        all_counts,
        key=lambda vuln_id: (-all_counts[vuln_id], vuln_id),
    )
    if max_advisories > 0:
        selected: list[str] = []
        quota = max(1, max_advisories // max(1, len(configs)))
        for library_id in configs:
            counts = vulnerability_counts_by_library.get(library_id, Counter())
            ranked_library = sorted(
                counts,
                key=lambda vuln_id: (-counts[vuln_id], vuln_id),
            )
            for vuln_id in ranked_library[:quota]:
                if vuln_id not in selected:
                    selected.append(vuln_id)
        for vuln_id in ranked_all:
            if len(selected) >= max_advisories:
                break
            if vuln_id not in selected:
                selected.append(vuln_id)
    else:
        selected = ranked_all
    skipped = [vuln_id for vuln_id in ranked_all if vuln_id not in selected]
    records: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    errors: list[str] = []
    package_to_library = {
        (config.ecosystem.casefold(), config.package_name.casefold()): config.library_id
        for config in configs.values()
    }
    for vuln_id in selected:
        url = OSV_VULN_URL.format(vuln_id=urllib.parse.quote(vuln_id, safe=""))
        try:
            osv, source = fetch_json_get(
                client,
                url,
                raw_root / "osv-advisories" / f"{vuln_id}.json",
            )
            sources.append(source)
            library_ids = sorted(
                {
                    package_to_library[(
                        str((item.get("package") or {}).get("ecosystem") or "").casefold(),
                        str((item.get("package") or {}).get("name") or "").casefold(),
                    )]
                    for item in (osv.get("affected") or [])
                    if (
                        str((item.get("package") or {}).get("ecosystem") or "").casefold(),
                        str((item.get("package") or {}).get("name") or "").casefold(),
                    )
                    in package_to_library
                }
            )
            records.append(
                {
                    "schema_version": "2.0",
                    "record_type": "library_version_advisory",
                    "id": osv.get("id") or vuln_id,
                    "aliases": osv.get("aliases") or [],
                    "summary": osv.get("summary"),
                    "details": osv.get("details"),
                    "published": osv.get("published"),
                    "modified": osv.get("modified"),
                    "withdrawn": osv.get("withdrawn"),
                    "library_ids": library_ids,
                    "affected": osv.get("affected") or [],
                    "severity": osv.get("severity") or [],
                    "references": osv.get("references") or [],
                    "credits": osv.get("credits") or [],
                    "database_specific": osv.get("database_specific") or {},
                    "ecosystem_specific_preserved": True,
                    "source": source,
                }
            )
        except RuntimeError as exc:
            errors.append(f"{vuln_id}: {exc}")
    return records, sources, errors, skipped


def crawl_upstream_patches(
    client: HttpClient,
    advisories: list[dict[str, Any]],
    configs: dict[str, LibraryConfig],
    raw_root: Path,
    max_patches: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Lấy patch từ commit upstream được advisory tham chiếu.

    Chỉ nhận commit thuộc repository chính thức của library; issue/PR và fork
    không được tự động coi là fix. Giới hạn số patch để PoC không phình raw cache.
    """
    config_repos: dict[str, tuple[str, str]] = {}
    for library_id, config in configs.items():
        parsed = parse_github_reference(config.repository_url)
        if parsed:
            config_repos[library_id] = (parsed.owner, parsed.repo)
    candidates_by_library: dict[str, list[tuple[str, str, str, str]]] = {
        library_id: [] for library_id in configs
    }
    seen: set[tuple[str, str]] = set()
    for advisory in advisories:
        for library_id in advisory.get("library_ids") or []:
            expected_repo = config_repos.get(library_id)
            if not expected_repo:
                continue
            for reference in advisory.get("references") or []:
                parsed = parse_github_reference(str(reference.get("url") or ""))
                if not parsed or parsed.kind != "commit" or not parsed.identifier:
                    continue
                if (parsed.owner, parsed.repo) != expected_repo:
                    continue
                key = (library_id, parsed.identifier)
                if key in seen:
                    continue
                seen.add(key)
                candidates_by_library[library_id].append(
                    (library_id, advisory.get("id") or "", parsed.identifier, parsed.canonical_url)
                )
    candidates: list[tuple[str, str, str, str]] = []
    if max_patches > 0:
        quota = max(1, max_patches // max(1, len(configs)))
        for library_id in configs:
            candidates.extend(candidates_by_library.get(library_id, [])[:quota])
        remaining = [
            candidate
            for library_id in configs
            for candidate in candidates_by_library.get(library_id, [])[quota:]
        ]
        candidates.extend(remaining[: max(0, max_patches - len(candidates))])
    else:
        candidates = [
            candidate
            for library_id in configs
            for candidate in candidates_by_library.get(library_id, [])
        ]
    patches: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    errors: list[str] = []
    for library_id, advisory_id, commit_sha, commit_url in candidates:
        patch_url = f"{commit_url}.patch"
        try:
            patch_bytes, metadata = client.get_bytes(
                patch_url,
                accept="text/plain",
                max_bytes=10 * 1024 * 1024,
            )
            raw_path = raw_root / "upstream-patches" / f"{safe_slug(library_id)}-{commit_sha}.patch"
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            raw_path.write_bytes(patch_bytes)
            source = {
                "url": commit_url,
                "patch_url": patch_url,
                "retrieved_at": utc_now(),
                "content_sha256": sha256_bytes(patch_bytes),
                "raw_path": str(raw_path),
                **metadata,
            }
            sources.append(source)
            patches.append(
                {
                    "schema_version": "2.0",
                    "record_type": "version_patch_diff",
                    "library_id": library_id,
                    "advisory_ids": [advisory_id],
                    "commit_sha": commit_sha,
                    "unified_diff": patch_bytes.decode("utf-8", errors="replace"),
                    "source": source,
                    "offline_evidence": True,
                }
            )
        except RuntimeError as exc:
            errors.append(f"{library_id}/{commit_sha}: {exc}")
    return patches, sources, errors


def sanitize_for_committed_sample(value: Any, root: Path) -> Any:
    """Loại đường dẫn tuyệt đối local nhưng giữ hash và URL provenance."""
    if isinstance(value, list):
        return [sanitize_for_committed_sample(item, root) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key == "raw_path":
                try:
                    result["raw_artifact"] = Path(item).relative_to(root).as_posix()
                except (ValueError, TypeError):
                    result["raw_artifact"] = Path(str(item)).name
            else:
                result[key] = sanitize_for_committed_sample(item, root)
        return result
    return value


def write_report(
    path: Path,
    libraries: dict[str, LibraryConfig],
    releases: list[dict[str, Any]],
    matrix: list[dict[str, Any]],
    advisories: list[dict[str, Any]],
    patches: list[dict[str, Any]],
    errors: list[str],
) -> None:
    per_library = Counter(item["library_id"] for item in releases)
    affected = Counter(
        item["library_id"]
        for item in matrix
        if item["status"] == "known_affected"
    )
    lines = [
        "# Kết quả PoC crawl KB theo phiên bản thư viện",
        "",
        f"Thời điểm chạy: `{utc_now()}`",
        "",
        "| Library | Ecosystem/package | Số phiên bản | Phiên bản có advisory |",
        "|---|---|---:|---:|",
    ]
    for library_id, config in libraries.items():
        lines.append(
            f"| {config.display_name} | `{config.ecosystem}:{config.package_name}` | "
            f"{per_library[library_id]} | {affected[library_id]} |"
        )
    lines.extend(
        [
            "",
            f"Số advisory snapshot chi tiết: **{len(advisories)}**.",
            f"Số patch diff upstream đã snapshot: **{len(patches)}**.",
            "Số version affected cao vì inventory gồm toàn bộ lịch sử release; "
            "đây không phải tỷ lệ rủi ro của các bản đang được hỗ trợ.",
            "",
            "## Cách đọc kết quả",
            "",
            "- `known_affected`: OSV trả advisory cho đúng package + version.",
            "- `no_known_vulnerability`: không tìm thấy advisory đã biết; không được hiểu là an toàn.",
            "- `query_error`: thiếu bằng chứng, không được tự suy diễn verdict.",
            "",
            "## Lỗi/cảnh báo",
            "",
        ]
    )
    lines.extend([f"- {item}" for item in errors] or ["- Không có."])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--libraries",
        default="django,log4j",
        help="Danh sách library id, hỗ trợ django,log4j.",
    )
    parser.add_argument(
        "--max-versions",
        type=int,
        default=0,
        help="0 = toàn bộ inventory; số dương = các release mới nhất theo thời gian.",
    )
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument(
        "--max-advisories",
        type=int,
        default=40,
        help="Số OSV record đầy đủ; ưu tiên advisory ảnh hưởng nhiều version nhất.",
    )
    parser.add_argument(
        "--max-patches",
        type=int,
        default=20,
        help="Số commit patch upstream tối đa lấy từ advisory references; 0 = không giới hạn.",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=project_root / "data",
    )
    parser.add_argument(
        "--sample-dir",
        type=Path,
        default=project_root / "data" / "samples" / "sprint-03-version-aware-kb",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=(
            project_root
            / "docs"
            / "sprints"
            / "sprint-03-version-aware-kb"
            / "crawl-report.md"
        ),
    )
    args = parser.parse_args()
    selected_ids = [item.strip().lower() for item in args.libraries.split(",") if item.strip()]
    unknown = sorted(set(selected_ids) - set(LIBRARIES))
    if unknown:
        parser.error(f"Library chưa hỗ trợ: {', '.join(unknown)}")
    if not 1 <= args.batch_size <= 1000:
        parser.error("--batch-size phải từ 1 đến 1000")

    selected = {library_id: LIBRARIES[library_id] for library_id in selected_ids}
    client = HttpClient(timeout=40, retries=2)
    raw_root = args.data_dir / "raw" / "library_versions"
    processed_root = args.data_dir / "processed" / "version_kb"
    all_releases: list[dict[str, Any]] = []
    all_matrix: list[dict[str, Any]] = []
    all_sources: list[dict[str, Any]] = []
    all_errors: list[str] = []
    vulnerability_counts_by_library: dict[str, Counter[str]] = {}

    for library_id, config in selected.items():
        try:
            releases, sources = crawl_registry(
                client,
                config,
                raw_root / library_id,
            )
            releases.sort(key=lambda item: (item.get("published_at") or "", item["version"]))
            if args.max_versions > 0:
                releases = releases[-args.max_versions :]
            all_releases.extend(releases)
            all_sources.extend(sources)
            matrix, counts, sources, errors = crawl_osv_matrix(
                client,
                config,
                releases,
                raw_root / library_id,
                args.batch_size,
            )
            all_matrix.extend(matrix)
            vulnerability_counts_by_library[library_id] = counts
            all_sources.extend(sources)
            all_errors.extend(errors)
        except RuntimeError as exc:
            all_errors.append(f"{library_id}: {exc}")

    advisories, sources, errors, skipped = crawl_advisory_details(
        client,
        vulnerability_counts_by_library,
        selected,
        raw_root,
        args.max_advisories,
    )
    all_sources.extend(sources)
    all_errors.extend(errors)
    patches, sources, errors = crawl_upstream_patches(
        client,
        advisories,
        selected,
        raw_root,
        args.max_patches,
    )
    all_sources.extend(sources)
    all_errors.extend(errors)
    processed_root.mkdir(parents=True, exist_ok=True)
    write_jsonl(processed_root / "library_releases.jsonl", all_releases)
    write_jsonl(processed_root / "version_security_matrix.jsonl", all_matrix)
    write_jsonl(processed_root / "advisories.jsonl", advisories)
    write_jsonl(processed_root / "patch_diffs.jsonl", patches)
    manifest = {
        "schema_version": "2.0",
        "generated_at": utc_now(),
        "libraries": [asdict(config) for config in selected.values()],
        "statistics": {
            "release_count": len(all_releases),
            "matrix_count": len(all_matrix),
            "known_affected_version_count": sum(
                item["status"] == "known_affected" for item in all_matrix
            ),
            "unique_vulnerability_count": len(
                set().union(
                    *(set(counts) for counts in vulnerability_counts_by_library.values())
                )
            ),
            "advisory_snapshot_count": len(advisories),
            "patch_diff_count": len(patches),
            "skipped_advisory_detail_count": len(skipped),
            "error_count": len(all_errors),
        },
        "skipped_advisory_ids": skipped,
        "sources": all_sources,
        "errors": all_errors,
        "semantics": {
            "known_affected": "OSV matched exact ecosystem package version.",
            "no_known_vulnerability": "No known match; not proof of safety.",
            "query_error": "Evidence unavailable; do not infer a verdict.",
        },
    }
    write_json(processed_root / "manifest.json", manifest)

    args.sample_dir.mkdir(parents=True, exist_ok=True)
    for name in (
        "library_releases.jsonl",
        "version_security_matrix.jsonl",
        "advisories.jsonl",
        "patch_diffs.jsonl",
    ):
        values = [
            json.loads(line)
            for line in (processed_root / name).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        write_jsonl(
            args.sample_dir / name,
            [sanitize_for_committed_sample(value, project_root) for value in values],
        )
    write_json(
        args.sample_dir / "manifest.json",
        sanitize_for_committed_sample(manifest, project_root),
    )
    write_report(
        args.report,
        selected,
        all_releases,
        all_matrix,
        advisories,
        patches,
        all_errors,
    )
    print(json.dumps(manifest["statistics"], ensure_ascii=False, indent=2))
    return 0 if all_releases and all_matrix else 1


if __name__ == "__main__":
    raise SystemExit(main())
