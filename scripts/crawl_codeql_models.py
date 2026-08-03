#!/usr/bin/env python3
"""Crawl CodeQL library models và chuẩn hóa source/sink/barrier/summary."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from kb_common import (
    HttpClient,
    safe_slug,
    sha256_bytes,
    utc_now,
    write_json,
    write_jsonl,
)


CODEQL_EXT_PATHS = {
    "python": "python/ql/lib/ext",
    "javascript": "javascript/ql/lib/ext",
    "java": "java/ql/lib/ext",
    "csharp": "csharp/ql/lib/ext",
    "go": "go/ql/lib/ext",
    "ruby": "ruby/ql/lib/ext",
    "rust": "rust/ql/lib/ext",
}

CODEQL_DOC_PATHS = {
    "javascript": (
        "docs/codeql/codeql-language-guides/"
        "customizing-library-models-for-javascript.rst"
    ),
    "ruby": (
        "docs/codeql/codeql-language-guides/"
        "customizing-library-models-for-ruby.rst"
    ),
}

MODEL_GROUPS = {
    "sourceModel": "source",
    "sinkModel": "sink",
    "summaryModel": "propagator",
    "barrierModel": "sanitizer_or_barrier",
    "barrierGuardModel": "sanitizer_or_guard",
    "neutralModel": "neutral",
    "typeModel": "type_relation",
    "packageGrouping": "package_relation",
    "namespaceGrouping": "namespace_relation",
}


def extract_documentation_model_examples(
    rst_text: str,
) -> list[dict[str, Any]]:
    """Lấy YAML barrier/barrier guard từ RST chính thức trong github/codeql."""

    lines = rst_text.splitlines()
    blocks: list[str] = []
    index = 0
    while index < len(lines):
        if lines[index].strip() != ".. code-block:: yaml":
            index += 1
            continue
        index += 1
        while index < len(lines) and not lines[index].strip():
            index += 1
        if index >= len(lines):
            break
        indent = len(lines[index]) - len(lines[index].lstrip())
        parts: list[str] = []
        while index < len(lines):
            line = lines[index]
            current_indent = len(line) - len(line.lstrip())
            if line.strip() and current_indent < indent:
                break
            parts.append(line[indent:] if line.strip() else "")
            index += 1
        blocks.append("\n".join(parts).rstrip())

    examples: list[dict[str, Any]] = []
    for block in blocks:
        if (
            "extensible: barrierModel" not in block
            and "extensible: barrierGuardModel" not in block
        ):
            continue
        try:
            value = yaml.safe_load(block)
        except yaml.YAMLError:
            continue
        if isinstance(value, dict) and isinstance(value.get("extensions"), list):
            examples.append({"yaml_text": block, "yaml_value": value})
    return examples


def list_model_files(
    client: HttpClient,
    language: str,
    repository_commit_sha: str,
) -> list[dict[str, Any]]:
    path = CODEQL_EXT_PATHS[language]
    api_url = (
        f"https://api.github.com/repos/github/codeql/contents/{path}"
        f"?ref={repository_commit_sha}"
    )
    value, _, _ = client.get_json(api_url, max_bytes=10 * 1024 * 1024)
    if not isinstance(value, list):
        raise RuntimeError(f"GitHub contents API không trả về danh sách: {api_url}")
    return [
        item
        for item in value
        if item.get("type") == "file"
        and str(item.get("name", "")).endswith(".model.yml")
    ]


def normalize_rows(
    *,
    language: str,
    file_info: dict[str, Any],
    yaml_value: dict[str, Any],
    raw_path: Path,
    raw_bytes: bytes,
    response_metadata: dict[str, str],
    repository_commit_sha: str | None = None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not isinstance(yaml_value, dict):
        raise RuntimeError("CodeQL model YAML phải có root là mapping.")
    for extension_index, extension in enumerate(
        yaml_value.get("extensions", []), start=1
    ):
        if not isinstance(extension, dict):
            raise RuntimeError(
                f"CodeQL extension #{extension_index} phải là mapping."
            )
        adds_to = extension.get("addsTo") or {}
        if not isinstance(adds_to, dict):
            raise RuntimeError(
                f"CodeQL addsTo #{extension_index} phải là mapping."
            )
        predicate = adds_to.get("extensible")
        data = extension.get("data", [])
        if not isinstance(data, list):
            raise RuntimeError(
                f"CodeQL data #{extension_index} phải là list."
            )
        for row_index, row in enumerate(data, start=1):
            model_id = (
                f"codeql:{language}:{file_info.get('name')}:"
                f"{predicate}:{extension_index}:{row_index}"
            )
            rows.append(
                {
                    "model_id": model_id,
                    "knowledge_type": "codeql_library_model",
                    "language": language,
                    "library_model_file": file_info.get("name"),
                    "model_group": MODEL_GROUPS.get(predicate, "other"),
                    "codeql_predicate": predicate,
                    "codeql_pack": adds_to.get("pack"),
                    "model_tuple": row,
                    "semantics": {
                        "is_source": predicate == "sourceModel",
                        "is_sink": predicate == "sinkModel",
                        "is_propagator": predicate == "summaryModel",
                        "is_sanitizer_or_barrier": predicate
                        in {"barrierModel", "barrierGuardModel"},
                        "requires_human_interpretation": True,
                    },
                    "source": {
                        "repository": "github/codeql",
                        "repository_license": "MIT",
                        "repository_commit_sha": repository_commit_sha,
                        "git_blob_sha": file_info.get("sha"),
                        "url": file_info.get("html_url"),
                        "download_url": file_info.get("download_url"),
                        "retrieved_at": utc_now(),
                        "content_sha256": sha256_bytes(raw_bytes),
                        "etag": response_metadata.get("etag"),
                        "last_modified": response_metadata.get("last_modified"),
                        "local_path": str(raw_path),
                        "trust_level": "official_codeql_model",
                    },
                }
            )
    return rows


def crawl_documentation_examples(
    *,
    client: HttpClient,
    languages: list[str],
    raw_root: Path,
    repository_commit_sha: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, str]]]:
    """Crawl ví dụ sanitizer/validator trong github/codeql và lưu RST gốc."""

    rows: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for language in languages:
        repository_path = CODEQL_DOC_PATHS.get(language)
        if not repository_path:
            continue
        url = (
            "https://raw.githubusercontent.com/github/codeql/"
            f"{repository_commit_sha}/{repository_path}"
        )
        html_url = (
            "https://github.com/github/codeql/blob/"
            f"{repository_commit_sha}/{repository_path}"
        )
        try:
            raw_bytes, metadata = client.get_bytes(
                url,
                accept="text/plain",
                max_bytes=5 * 1024 * 1024,
            )
            raw_path = (
                raw_root
                / "documentation"
                / f"{safe_slug(language)}-library-models.rst"
            )
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            raw_path.write_bytes(raw_bytes)
            examples = extract_documentation_model_examples(
                raw_bytes.decode("utf-8")
            )
            for index, example in enumerate(examples, start=1):
                file_info = {
                    "name": f"documentation-example-{index}.model.yml",
                    "sha": sha256_bytes(
                        example["yaml_text"].encode("utf-8")
                    ),
                    "html_url": html_url,
                    "download_url": url,
                }
                example_rows = normalize_rows(
                    language=language,
                    file_info=file_info,
                    yaml_value=example["yaml_value"],
                    raw_path=raw_path,
                    raw_bytes=raw_bytes,
                    response_metadata=metadata,
                    repository_commit_sha=repository_commit_sha,
                )
                for row in example_rows:
                    row["knowledge_type"] = (
                        "codeql_documentation_model_example"
                    )
                    row["example_status"] = (
                        "official_documentation_example_not_repo_runtime_model"
                    )
                    row["source"].update(
                        {
                            "repository": "github/codeql",
                            "repository_license": "MIT",
                            "trust_level": (
                                "official_codeql_repository_documentation_example"
                            ),
                        }
                    )
                rows.extend(example_rows)
            sources.append(
                {
                    "language": language,
                    "name": "official-documentation-examples",
                    "sha": sha256_bytes(raw_bytes),
                    "repository_commit_sha": repository_commit_sha,
                    "url": html_url,
                    "download_url": url,
                    "repository_path": repository_path,
                    "local_path": str(raw_path),
                    "model_count": sum(
                        1
                        for row in rows
                        if row["language"] == language
                        and row["knowledge_type"]
                        == "codeql_documentation_model_example"
                    ),
                    "source_kind": "documentation",
                }
            )
        except (RuntimeError, UnicodeDecodeError, yaml.YAMLError) as exc:
            errors.append(
                {
                    "language": language,
                    "url": url,
                    "error": str(exc),
                }
            )
    return rows, sources, errors


def write_summary(
    rows: list[dict[str, Any]],
    files: list[dict[str, Any]],
    path: Path,
) -> None:
    group_counts = Counter(row["model_group"] for row in rows)
    language_counts = Counter(row["language"] for row in rows)
    lines = [
        "# Kết quả crawl CodeQL library models",
        "",
        f"- Số nguồn/file: **{len(files)}**",
        f"- Số model tuple: **{len(rows)}**",
        "- Repository: **github/codeql**",
        "- Tài liệu sanitizer: **docs/ trong github/codeql**",
        "- License repository và tài liệu trong repo: **MIT**.",
        "",
        "## Nhóm model",
        "",
        "| Nhóm | Số lượng |",
        "|---|---:|",
    ]
    lines.extend(f"| {key} | {value} |" for key, value in group_counts.most_common())
    lines.extend(
        [
            "",
            "## Ngôn ngữ",
            "",
            "| Ngôn ngữ | Số lượng model |",
            "|---|---:|",
        ]
    )
    lines.extend(
        f"| {key} | {value} |" for key, value in language_counts.most_common()
    )
    lines.extend(
        [
            "",
            "## Cách hiểu dữ liệu",
            "",
            "- `sourceModel` → source.",
            "- `sinkModel` → sink.",
            "- `summaryModel` → propagator/data-flow summary.",
            "- `barrierModel` và `barrierGuardModel` → sanitizer/barrier/guard.",
            "- Record giữ nguyên tuple CodeQL; không tự suy diễn tên API.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def resolve_codeql_commit(client: HttpClient) -> str:
    value, _, _ = client.get_json(
        "https://api.github.com/repos/github/codeql/commits/main"
    )
    sha = value.get("sha") if isinstance(value, dict) else None
    if not sha:
        raise RuntimeError("Không resolve được commit SHA của github/codeql/main.")
    return str(sha)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Crawl source/sink/barrier models từ github/codeql."
    )
    base = Path(__file__).resolve().parents[1]
    parser.add_argument(
        "--languages",
        default="python,javascript",
        help=f"Danh sách phân cách bằng dấu phẩy: {','.join(CODEQL_EXT_PATHS)}",
    )
    parser.add_argument(
        "--max-files-per-language",
        type=int,
        default=25,
        help="0 nghĩa là lấy toàn bộ file trong thư mục ext cấp đầu.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=base / "data",
    )
    parser.add_argument(
        "--repository-commit",
        help="Commit SHA của github/codeql; tránh phụ thuộc branch main.",
    )
    parser.add_argument(
        "--skip-documentation-examples",
        action="store_true",
        help="Không crawl ví dụ barrier/barrierGuard từ tài liệu CodeQL.",
    )
    args = parser.parse_args()

    languages = list(
        dict.fromkeys(item.strip().lower() for item in args.languages.split(","))
    )
    invalid = sorted(set(languages) - set(CODEQL_EXT_PATHS))
    if invalid:
        parser.error(f"Ngôn ngữ chưa hỗ trợ: {', '.join(invalid)}")

    client = HttpClient()
    rows: list[dict[str, Any]] = []
    crawled_files: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    raw_root = args.output_dir / "raw" / "codeql"
    processed = args.output_dir / "processed"
    previous_rows: list[dict[str, Any]] = []
    previous_manifest: dict[str, Any] = {}
    previous_models_path = processed / "codeql_models.jsonl"
    previous_manifest_path = processed / "codeql_model_manifest.json"
    if previous_models_path.exists():
        try:
            previous_rows = [
                json.loads(line)
                for line in previous_models_path.read_text(
                    encoding="utf-8"
                ).splitlines()
                if line.strip()
            ]
        except (OSError, json.JSONDecodeError):
            previous_rows = []
    if previous_manifest_path.exists():
        try:
            previous_manifest = json.loads(
                previous_manifest_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            previous_manifest = {}
    try:
        repository_commit_sha = args.repository_commit or resolve_codeql_commit(client)
    except RuntimeError as exc:
        errors.append({"repository": "github/codeql", "error": str(exc)})
        repository_commit_sha = (
            args.repository_commit
            or previous_manifest.get("repository_commit_sha")
            or "main"
        )

    for language in languages:
        try:
            file_infos = list_model_files(
                client, language, repository_commit_sha
            )
        except RuntimeError as exc:
            errors.append({"language": language, "error": str(exc)})
            cached = [
                row
                for row in previous_rows
                if row.get("language") == language
                and row.get("knowledge_type")
                != "codeql_documentation_model_example"
            ]
            for row in cached:
                source = row.get("source") or {}
                source["repository_commit_sha"] = repository_commit_sha
                source["url"] = str(source.get("url", "")).replace(
                    "/main/", f"/{repository_commit_sha}/"
                )
                source["download_url"] = str(
                    source.get("download_url", "")
                ).replace("/main/", f"/{repository_commit_sha}/")
                row["source"] = source
            rows.extend(cached)
            crawled_files.extend(
                item
                for item in previous_manifest.get("files", [])
                if item.get("language") == language
                and item.get("source_kind") != "documentation"
            )
            continue
        file_infos.sort(key=lambda item: item.get("name", ""))
        if args.max_files_per_language > 0:
            file_infos = file_infos[: args.max_files_per_language]

        for file_info in file_infos:
            try:
                raw_bytes, metadata = client.get_bytes(
                    file_info["download_url"],
                    accept="text/plain",
                    max_bytes=5 * 1024 * 1024,
                )
                raw_path = (
                    raw_root
                    / safe_slug(language)
                    / safe_slug(file_info["name"])
                )
                raw_path.parent.mkdir(parents=True, exist_ok=True)
                raw_path.write_bytes(raw_bytes)
                yaml_value = yaml.safe_load(raw_bytes.decode("utf-8")) or {}
                file_rows = normalize_rows(
                    language=language,
                    file_info=file_info,
                    yaml_value=yaml_value,
                    raw_path=raw_path,
                    raw_bytes=raw_bytes,
                    response_metadata=metadata,
                    repository_commit_sha=repository_commit_sha,
                )
                rows.extend(file_rows)
                crawled_files.append(
                    {
                        "language": language,
                        "name": file_info.get("name"),
                        "sha": file_info.get("sha"),
                        "repository_commit_sha": repository_commit_sha,
                        "url": file_info.get("html_url"),
                        "local_path": str(raw_path),
                        "model_count": len(file_rows),
                    }
                )
            except (RuntimeError, UnicodeDecodeError, yaml.YAMLError) as exc:
                errors.append(
                    {
                        "language": language,
                        "file": file_info.get("name", ""),
                        "error": str(exc),
                    }
                )

    if not args.skip_documentation_examples:
        doc_rows, doc_sources, doc_errors = crawl_documentation_examples(
            client=client,
            languages=languages,
            raw_root=raw_root,
            repository_commit_sha=repository_commit_sha,
        )
        rows.extend(doc_rows)
        crawled_files.extend(doc_sources)
        errors.extend(doc_errors)

    write_jsonl(processed / "codeql_models.jsonl", rows)
    write_json(
        processed / "codeql_model_manifest.json",
        {
            "generated_at": utc_now(),
            "repository": "github/codeql",
            "repository_license": "MIT",
            "languages": languages,
            "repository_commit_sha": repository_commit_sha,
            "file_count": len(crawled_files),
            "model_count": len(rows),
            "model_groups": dict(Counter(row["model_group"] for row in rows)),
            "files": crawled_files,
            "errors": errors,
        },
    )
    write_summary(
        rows,
        crawled_files,
        args.output_dir / "reports" / "codeql_models.md",
    )
    print(f"Files: {len(crawled_files)}")
    print(f"Models: {len(rows)}")
    print(f"Errors: {len(errors)}")
    print(f"Output: {(processed / 'codeql_models.jsonl').resolve()}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
