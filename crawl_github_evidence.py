#!/usr/bin/env python3
"""Crawl patch diff, PR/issue và PoC từ các reference của GHSA.

Script lưu cả raw response và record đã chuẩn hóa. Nội dung tải về không được
thực thi; nó chỉ được lưu như evidence phục vụ KB/RAG.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from kb_common import (
    HttpClient,
    extract_poc_sections,
    extract_urls,
    parse_github_reference,
    safe_slug,
    sha256_bytes,
    utc_now,
    write_json,
    write_jsonl,
)


def source_metadata(
    *,
    url: str,
    api_url: str | None,
    raw_bytes: bytes,
    response_metadata: dict[str, str],
    local_paths: list[str],
    trust_level: str,
) -> dict[str, Any]:
    return {
        "url": url,
        "api_url": api_url,
        "retrieved_at": utc_now(),
        "content_sha256": sha256_bytes(raw_bytes),
        "content_type": response_metadata.get("content_type"),
        "etag": response_metadata.get("etag"),
        "last_modified": response_metadata.get("last_modified"),
        "local_paths": local_paths,
        "trust_level": trust_level,
    }


def save_raw_json(path: Path, raw_bytes: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        value = json.loads(raw_bytes.decode("utf-8"))
        path.write_text(
            json.dumps(value, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        path.write_bytes(raw_bytes)


def repo_metadata(
    client: HttpClient,
    owner: str,
    repo: str,
    raw_root: Path,
    cache: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    key = f"{owner}/{repo}"
    if key in cache:
        return cache[key]
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    value, raw, _ = client.get_json(api_url)
    raw_path = raw_root / "repositories" / f"{safe_slug(owner)}__{safe_slug(repo)}.json"
    save_raw_json(raw_path, raw)
    result = {
        "full_name": value.get("full_name"),
        "default_branch": value.get("default_branch"),
        "license": (value.get("license") or {}).get("spdx_id"),
        "archived": value.get("archived"),
        "visibility": value.get("visibility"),
        "source_url": value.get("html_url"),
        "raw_path": str(raw_path),
    }
    cache[key] = result
    return result


def crawl_commit(
    client: HttpClient,
    reference: Any,
    raw_root: Path,
    repo_cache: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    owner, repo, sha = reference.owner, reference.repo, reference.identifier
    repository = repo_metadata(client, owner, repo, raw_root, repo_cache)
    if repository.get("visibility") != "public":
        raise RuntimeError(
            f"Bỏ qua repository không public: {owner}/{repo}"
        )
    api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    commit, raw_json, api_metadata = client.get_json(api_url, max_bytes=10 * 1024 * 1024)
    stem = f"{safe_slug(owner)}__{safe_slug(repo)}__{safe_slug(sha)}"
    json_path = raw_root / "commits" / f"{stem}.json"
    save_raw_json(json_path, raw_json)
    patch_url = f"https://github.com/{owner}/{repo}/commit/{sha}.patch"
    patch_bytes, patch_metadata = client.get_bytes(
        patch_url,
        accept="text/plain",
        max_bytes=10 * 1024 * 1024,
    )

    patch_path = raw_root / "commits" / f"{stem}.patch"
    patch_path.parent.mkdir(parents=True, exist_ok=True)
    patch_path.write_bytes(patch_bytes)

    files = [
        {
            "filename": item.get("filename"),
            "previous_filename": item.get("previous_filename"),
            "status": item.get("status"),
            "additions": item.get("additions"),
            "deletions": item.get("deletions"),
            "changes": item.get("changes"),
            "patch": item.get("patch"),
        }
        for item in commit.get("files", [])
    ]
    record = {
        "artifact_id": f"github-commit:{owner}/{repo}@{commit.get('sha') or sha}",
        "artifact_type": "patch_diff",
        "repository": repository,
        "content": {
            "commit_sha": commit.get("sha"),
            "parent_shas": [
                parent.get("sha") for parent in commit.get("parents", [])
            ],
            "message": (commit.get("commit") or {}).get("message"),
            "author": (commit.get("commit") or {}).get("author"),
            "stats": commit.get("stats"),
            "files": files,
            "unified_diff": patch_bytes.decode("utf-8", errors="replace"),
            "diff_complete": True,
        },
        "source": source_metadata(
            url=reference.canonical_url,
            api_url=api_url,
            raw_bytes=patch_bytes,
            response_metadata=patch_metadata or api_metadata,
            local_paths=[str(json_path), str(patch_path)],
            trust_level="upstream_repository_commit",
        ),
    }
    record["source"]["local_hashes"] = {
        str(json_path): sha256_bytes(raw_json),
        str(patch_path): sha256_bytes(patch_bytes),
    }
    pocs = extract_poc_sections(record["content"]["message"])
    return record, pocs


def crawl_pull(
    client: HttpClient,
    reference: Any,
    raw_root: Path,
    repo_cache: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    owner, repo, number = reference.owner, reference.repo, reference.identifier
    repository = repo_metadata(client, owner, repo, raw_root, repo_cache)
    if repository.get("visibility") != "public":
        raise RuntimeError(
            f"Bỏ qua repository không public: {owner}/{repo}"
        )
    api_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{number}"
    pull, raw_json, api_metadata = client.get_json(api_url)
    stem = f"{safe_slug(owner)}__{safe_slug(repo)}__pr_{safe_slug(number)}"
    json_path = raw_root / "pulls" / f"{stem}.json"
    save_raw_json(json_path, raw_json)
    patch_url = f"https://github.com/{owner}/{repo}/pull/{number}.patch"
    patch_bytes, patch_metadata = client.get_bytes(
        patch_url,
        accept="text/plain",
        max_bytes=10 * 1024 * 1024,
    )

    patch_path = raw_root / "pulls" / f"{stem}.patch"
    patch_path.parent.mkdir(parents=True, exist_ok=True)
    patch_path.write_bytes(patch_bytes)

    record = {
        "artifact_id": f"github-pr:{owner}/{repo}#{number}",
        "artifact_type": "pull_request_patch",
        "repository": repository,
        "content": {
            "number": pull.get("number"),
            "title": pull.get("title"),
            "body": pull.get("body"),
            "state": pull.get("state"),
            "merged": pull.get("merged"),
            "merge_commit_sha": pull.get("merge_commit_sha"),
            "base_sha": (pull.get("base") or {}).get("sha"),
            "head_sha": (pull.get("head") or {}).get("sha"),
            "unified_diff": patch_bytes.decode("utf-8", errors="replace"),
            "diff_complete": True,
        },
        "source": source_metadata(
            url=reference.canonical_url,
            api_url=api_url,
            raw_bytes=patch_bytes,
            response_metadata=patch_metadata or api_metadata,
            local_paths=[str(json_path), str(patch_path)],
            trust_level="upstream_repository_pull_request",
        ),
    }
    record["source"]["local_hashes"] = {
        str(json_path): sha256_bytes(raw_json),
        str(patch_path): sha256_bytes(patch_bytes),
    }
    return record, extract_poc_sections(pull.get("body"))


def crawl_issue(
    client: HttpClient,
    reference: Any,
    raw_root: Path,
    repo_cache: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    owner, repo, number = reference.owner, reference.repo, reference.identifier
    repository = repo_metadata(client, owner, repo, raw_root, repo_cache)
    if repository.get("visibility") != "public":
        raise RuntimeError(
            f"Bỏ qua repository không public: {owner}/{repo}"
        )
    api_url = f"https://api.github.com/repos/{owner}/{repo}/issues/{number}"
    issue, raw_json, api_metadata = client.get_json(api_url)
    stem = f"{safe_slug(owner)}__{safe_slug(repo)}__issue_{safe_slug(number)}"
    json_path = raw_root / "issues" / f"{stem}.json"
    save_raw_json(json_path, raw_json)
    record = {
        "artifact_id": f"github-issue:{owner}/{repo}#{number}",
        "artifact_type": "issue_evidence",
        "repository": repository,
        "content": {
            "number": issue.get("number"),
            "title": issue.get("title"),
            "body": issue.get("body"),
            "state": issue.get("state"),
            "labels": [
                item.get("name") for item in issue.get("labels", [])
            ],
            "created_at": issue.get("created_at"),
            "updated_at": issue.get("updated_at"),
        },
        "source": source_metadata(
            url=reference.canonical_url,
            api_url=api_url,
            raw_bytes=raw_json,
            response_metadata=api_metadata,
            local_paths=[str(json_path)],
            trust_level="upstream_repository_issue",
        ),
    }
    return record, extract_poc_sections(issue.get("body"))


def advisory_snapshot(
    advisory: dict[str, Any],
    raw_root: Path,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    advisory_id = advisory.get("ghsa_id") or advisory.get("knowledge_id") or "unknown"
    raw = json.dumps(advisory, ensure_ascii=False, indent=2).encode("utf-8")
    raw_path = (
        raw_root
        / "evidence_advisories"
        / f"{safe_slug(advisory_id)}.json"
    )
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_bytes(raw)
    record = {
        "artifact_id": f"ghsa-snapshot:{advisory_id}",
        "artifact_type": "security_advisory_snapshot",
        "content": advisory,
        "source": {
            "url": (advisory.get("source") or {}).get("url"),
            "api_url": (advisory.get("source") or {}).get("api_url"),
            "retrieved_at": utc_now(),
            "content_sha256": sha256_bytes(raw),
            "content_type": "application/json",
            "local_paths": [str(raw_path)],
            "trust_level": (advisory.get("source") or {}).get(
                "trust_level", "official_reviewed"
            ),
        },
    }
    return record, extract_poc_sections(advisory.get("description"))


def attach_poc_records(
    artifacts: list[dict[str, Any]],
    parent: dict[str, Any],
    sections: list[dict[str, str]],
    advisory_id: str,
) -> None:
    for index, section in enumerate(sections, start=1):
        artifacts.append(
            {
                "artifact_id": f"{parent['artifact_id']}:poc:{index}",
                "artifact_type": "proof_of_concept",
                "advisory_ids": [advisory_id],
                "content": {
                    "title": section["title"],
                    "body": section["body"],
                    "extraction_method": "verbatim_markdown_section",
                },
                "source": parent["source"],
                "parent_artifact_id": parent["artifact_id"],
            }
        )


def merge_advisory_id(
    artifacts: list[dict[str, Any]],
    parent: dict[str, Any],
    advisory_id: str,
) -> None:
    if advisory_id not in parent.setdefault("advisory_ids", []):
        parent["advisory_ids"].append(advisory_id)
    for child in artifacts:
        if child.get("parent_artifact_id") != parent.get("artifact_id"):
            continue
        if advisory_id not in child.setdefault("advisory_ids", []):
            child["advisory_ids"].append(advisory_id)


def load_previous_artifacts(path: Path) -> dict[str, list[dict[str, Any]]]:
    if not path.exists():
        return {}
    previous: dict[str, list[dict[str, Any]]] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            url = (item.get("source") or {}).get("url")
            if url:
                previous.setdefault(url.casefold(), []).append(item)
    except (OSError, json.JSONDecodeError):
        return {}
    return previous


def write_summary(
    artifacts: list[dict[str, Any]],
    errors: list[dict[str, str]],
    path: Path,
) -> None:
    counts = Counter(item["artifact_type"] for item in artifacts)
    lines = [
        "# Kết quả crawl GitHub evidence",
        "",
        f"- Tổng số artifact: **{len(artifacts)}**",
        f"- Số lỗi/URL bỏ qua: **{len(errors)}**",
        "",
        "## Loại dữ liệu",
        "",
        "| Loại | Số lượng |",
        "|---|---:|",
    ]
    lines.extend(f"| {key} | {value} |" for key, value in counts.most_common())
    lines.extend(
        [
            "",
            "## Ghi chú",
            "",
            "- Patch/PR/issue được lưu tại chỗ, không phụ thuộc URL còn sống.",
            "- PoC là đoạn nguyên văn được trích từ heading PoC/Reproduction/Exploit.",
            "- Nội dung crawl là dữ liệu không tin cậy và không được tự động thực thi.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Crawl patch diff, PR/issue và PoC từ GHSA references."
    )
    base = Path(__file__).parent
    parser.add_argument(
        "--input",
        type=Path,
        default=base / "output" / "ghsa_advisories.json",
    )
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=base / "data",
    )
    parser.add_argument(
        "--max-github-artifacts",
        type=int,
        default=30,
        help="Giới hạn commit/PR/issue để tránh vượt API rate limit.",
    )
    args = parser.parse_args()

    advisories = json.loads(args.input.read_text(encoding="utf-8"))
    advisories = advisories[: args.limit]
    client = HttpClient()
    raw_root = args.output_dir / "raw" / "github"
    artifacts: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    repo_cache: dict[str, dict[str, Any]] = {}
    seen_references: set[str] = set()
    github_artifact_count = 0
    processed = args.output_dir / "processed"
    previous_by_url = load_previous_artifacts(
        processed / "github_evidence.jsonl"
    )

    for advisory in advisories:
        advisory_id = advisory.get("ghsa_id") or advisory.get("knowledge_id")
        snapshot, poc_sections = advisory_snapshot(advisory, raw_root)
        snapshot["advisory_ids"] = [advisory_id]
        artifacts.append(snapshot)
        attach_poc_records(artifacts, snapshot, poc_sections, advisory_id)

        references = advisory.get("references", [])
        if isinstance(references, str):
            urls = [references]
        elif isinstance(references, list):
            urls = references[:]
        else:
            urls = []
            errors.append(
                {
                    "url": str(references),
                    "error": "references_must_be_list_or_string",
                }
            )
        urls.extend(extract_urls(advisory.get("description")))
        for url in urls:
            reference = parse_github_reference(url)
            if not reference or reference.kind not in {"commit", "pull", "issues"}:
                continue
            canonical = reference.canonical_url
            canonical_key = canonical.casefold()
            if canonical_key in seen_references:
                existing = next(
                    item
                    for item in artifacts
                    if item.get("source", {}).get("url") == canonical
                )
                merge_advisory_id(artifacts, existing, advisory_id)
                continue
            if github_artifact_count >= args.max_github_artifacts:
                errors.append({"url": canonical, "error": "artifact_limit_reached"})
                old_rows = previous_by_url.get(canonical_key, [])
                existing_ids = {item.get("artifact_id") for item in artifacts}
                for old in old_rows:
                    if old.get("artifact_id") in existing_ids:
                        continue
                    artifacts.append(old)
                    existing_ids.add(old.get("artifact_id"))
                old = next(
                    (
                        item
                        for item in old_rows
                        if item.get("artifact_type") != "proof_of_concept"
                    ),
                    None,
                )
                if old:
                    merge_advisory_id(artifacts, old, advisory_id)
                    seen_references.add(canonical_key)
                continue
            try:
                if reference.kind == "commit":
                    artifact, sections = crawl_commit(
                        client, reference, raw_root, repo_cache
                    )
                elif reference.kind == "pull":
                    artifact, sections = crawl_pull(
                        client, reference, raw_root, repo_cache
                    )
                else:
                    artifact, sections = crawl_issue(
                        client, reference, raw_root, repo_cache
                    )
                artifact["advisory_ids"] = [advisory_id]
                artifacts.append(artifact)
                attach_poc_records(artifacts, artifact, sections, advisory_id)
                seen_references.add(canonical_key)
                github_artifact_count += 1
            except (RuntimeError, json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
                errors.append({"url": canonical, "error": str(exc)})
                old_rows = previous_by_url.get(canonical_key, [])
                existing_ids = {item.get("artifact_id") for item in artifacts}
                for old in old_rows:
                    if old.get("artifact_id") in existing_ids:
                        continue
                    artifacts.append(old)
                    existing_ids.add(old.get("artifact_id"))
                old = next(
                    (
                        item
                        for item in old_rows
                        if item.get("artifact_type") != "proof_of_concept"
                    ),
                    None,
                )
                if old:
                    merge_advisory_id(artifacts, old, advisory_id)
                    seen_references.add(canonical_key)

    write_jsonl(processed / "github_evidence.jsonl", artifacts)
    write_json(processed / "github_evidence_errors.json", errors)
    write_json(
        processed / "github_evidence_manifest.json",
        {
            "generated_at": utc_now(),
            "input": str(args.input),
            "advisory_count": len(advisories),
            "artifact_count": len(artifacts),
            "error_count": len(errors),
            "artifact_types": dict(
                Counter(item["artifact_type"] for item in artifacts)
            ),
        },
    )
    write_summary(artifacts, errors, args.output_dir / "reports" / "github_evidence.md")
    print(f"Artifacts: {len(artifacts)}")
    print(f"Errors: {len(errors)}")
    print(f"Output: {(processed / 'github_evidence.jsonl').resolve()}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
