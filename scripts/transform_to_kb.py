#!/usr/bin/env python3
"""Chuyển raw/processed evidence sang entry Markdown và JSON theo schema mentor."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

import yaml


VI_KEYWORDS = {
    "CWE-22": "path traversal",
    "CWE-79": "cross-site scripting",
    "CWE-78": "thực thi lệnh",
    "CWE-89": "SQL injection",
    "CWE-90": "LDAP injection",
    "CWE-94": "code injection",
    "CWE-1321": "prototype pollution",
    "CWE-502": "deserialization không an toàn",
    "CWE-918": "SSRF",
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_number}: JSONL không hợp lệ: {exc}") from exc
    return rows


def canonical_id(value: str | None, prefix: str = "kb") -> str:
    value = value or "unknown"
    value = value.removeprefix("GHSA-")
    value = value.removeprefix("ghsa-")
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-")
    normalized = f"{prefix}-{value.lower()}"
    if len(normalized) <= 120:
        return normalized
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:12]
    return f"{normalized[:107]}-{digest}"


def md(value: Any) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, (list, tuple)):
        return ", ".join(md(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value).strip() or "N/A"


def bullets(values: Iterable[Any]) -> str:
    values = list(values)
    return "\n".join(f"- {md(value)}" for value in values) if values else "- N/A"


def safe_summary(summary: str | None, source_name: str) -> str:
    """Không tự bịa bản dịch; ghi rõ đây là summary nguồn."""
    summary = (summary or "Không có summary từ nguồn.").strip()
    return f"Bản ghi được thu thập từ {source_name}. Nội dung kỹ thuật gốc: {summary}"


def frontmatter(data: dict[str, Any]) -> str:
    return "---\n" + yaml.safe_dump(
        data,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    ).rstrip() + "\n---\n"


FRONTMATTER_FIELDS = [
    "id",
    "source_type",
    "title",
    "aliases",
    "author",
    "date",
    "event",
    "category",
    "tags",
    "keywords_vi",
    "summary",
    "summary_vi",
    "repo",
    "file_path",
    "crawled_at",
    "severity",
    "cvss_score",
    "cve_id",
    "affected_software",
    "affected_versions",
]


def fenced(value: str, language: str = "text", limit: int = 100_000) -> str:
    value = value or "N/A"
    if len(value) > limit:
        value = value[:limit] + "\n\n[Đã rút gọn trong Markdown; raw artifact vẫn giữ đầy đủ.]"
    max_run = max((len(run) for run in re.findall(r"`+", value)), default=0)
    fence = "`" * max(3, max_run + 1)
    return f"{fence}{language}\n{value}\n{fence}"


def related_artifacts(
    artifacts: list[dict[str, Any]],
    advisory_id: str,
    artifact_type: str,
) -> list[dict[str, Any]]:
    return [
        item
        for item in artifacts
        if advisory_id in item.get("advisory_ids", [])
        and item.get("artifact_type") == artifact_type
    ]


def advisory_entry(
    advisory: dict[str, Any],
    artifacts: list[dict[str, Any]],
    output_root: Path,
) -> dict[str, Any]:
    ghsa_id = advisory.get("ghsa_id") or advisory.get("knowledge_id") or "unknown"
    entry_id = canonical_id(ghsa_id, "ghsa")
    cwes = advisory.get("cwes") or []
    cwe_ids = [item.get("id") for item in cwes if item.get("id")]
    tags = ["ghsa", "security-advisory", *[item.lower() for item in cwe_ids]]
    keywords = [VI_KEYWORDS[item] for item in cwe_ids if item in VI_KEYWORDS]
    packages = advisory.get("affected_packages") or []
    software = sorted(
        {
            item.get("name")
            for item in packages
            if item.get("name")
        }
    )
    versions = sorted(
        {
            item.get("vulnerable_version_range")
            for item in packages
            if item.get("vulnerable_version_range")
        }
    )
    source = advisory.get("source") or {}
    source_url = source.get("url") or source.get("api_url")
    poc_records = related_artifacts(artifacts, ghsa_id, "proof_of_concept")
    patch_records = [
        item
        for item in artifacts
        if ghsa_id in item.get("advisory_ids", [])
        and item.get("artifact_type") in {"patch_diff", "pull_request_patch"}
    ]
    patch_repositories = sorted(
        {
            (item.get("repository") or {}).get("full_name")
            for item in patch_records
            if (item.get("repository") or {}).get("full_name")
        }
    )
    title = advisory.get("summary") or ghsa_id
    path = output_root / "entries" / f"{entry_id}.md"

    poc_text = []
    for item in poc_records:
        content = item.get("content") or {}
        poc_text.append(f"### {content.get('title', 'PoC')}\n\n{content.get('body', 'N/A')}")
    patch_text = []
    for item in patch_records:
        content = item.get("content") or {}
        patch_text.append(
            f"### {item.get('artifact_id')}\n\n"
            f"- Commit/PR message: {md(content.get('message') or content.get('title'))}\n"
            f"- Local raw: {md((item.get('source') or {}).get('local_paths'))}\n\n"
            f"{fenced(content.get('unified_diff', ''), 'diff')}"
        )

    cvss = advisory.get("cvss") or {}
    cwe_description = ", ".join(
        f"{item.get('id')}: {item.get('name')}"
        for item in cwes
        if item.get("id")
    ) or "Chưa có CWE từ advisory."
    content = (
        f"# {title}\n\n"
        "## Metadata\n\n"
        "| Field | Value |\n|-------|-------|\n"
        f"| **ID** | {entry_id} |\n"
        f"| **Source** | {source_url or 'N/A'} |\n"
        f"| **Aliases** | {ghsa_id}, {advisory.get('cve_id') or 'N/A'} |\n"
        f"| **Severity** | {advisory.get('severity') or 'N/A'} |\n"
        f"| **CVSS Score** | {cvss.get('score', 'N/A') if isinstance(cvss, dict) else cvss} |\n"
        f"| **CVE** | {advisory.get('cve_id') or 'N/A'} |\n\n"
        "## Overview\n\n"
        f"{advisory.get('summary') or 'N/A'}\n\n"
        "## Tóm tắt (Tiếng Việt)\n\n"
        f"> {safe_summary(advisory.get('summary'), 'GitHub Advisory Database')}\n\n"
        f"- **Từ khóa:** {', '.join(keywords) or 'Chưa có mapping tiếng Việt'}\n\n"
        "## Technical Details\n\n"
        "### Affected Software\n\n"
        f"- **Software:** {', '.join(software) or 'N/A'}\n"
        f"- **Version:** {', '.join(versions) or 'N/A'}\n"
        f"- **CWE:** {cwe_description}\n\n"
        "### Vulnerability Description\n\n"
        f"{advisory.get('description') or 'N/A'}\n\n"
        "### Root Cause\n\n"
        "Root cause chi tiết cần được đối chiếu với patch diff và code path; "
        "crawler không tự suy diễn khi advisory chưa cung cấp bằng chứng.\n\n"
        "## Impact\n\n"
        f"- **Severity:** {advisory.get('severity') or 'N/A'}\n"
        f"- **CVSS:** {md(cvss)}\n\n"
        "## Proof of Concept\n\n"
        + ("\n\n".join(poc_text) if poc_text else "Không tìm thấy section PoC/Reproduction trong artifact đã crawl.")
        + "\n\n## Detection\n\n"
        "Advisory metadata không tự chứng minh source-to-sink. Hãy dùng các CodeQL "
        "model record tương ứng và evidence từ code scanner để xác nhận.\n\n"
        "## Remediation\n\n"
        + ("\n\n".join(patch_text) if patch_text else "Chưa tìm thấy patch diff từ references.")
        + "\n\n## References\n\n"
        + bullets(
            [source_url, *(advisory.get("references") or [])]
        )
        + "\n\n## Additional Notes\n\n"
        "- Raw artifact được lưu offline để không phụ thuộc URL còn sống.\n"
        "- Nội dung PoC chỉ là evidence và không được tự động thực thi.\n"
        "- Không có suy diễn tự động về exploitability từ metadata.\n\n"
        "## Exploitation\n\n"
        "Không thực thi exploit; chỉ lưu PoC/patch như evidence để reviewer đối chiếu.\n\n"
        "## Related Knowledge Base Entries\n\n"
        "Có thể liên kết entry này với CodeQL source/sink/barrier và artifact patch "
        "theo `advisory_ids`/`artifact_id`.\n"
    )
    record = {
        "id": entry_id,
        "source_type": "github",
        "title": title,
        "aliases": [item for item in [ghsa_id, advisory.get("cve_id")] if item],
        "author": None,
        "date": advisory.get("published_at"),
        "event": None,
        "category": "vulnerability",
        "tags": tags,
        "keywords_vi": keywords,
        "summary": advisory.get("summary"),
        "summary_vi": safe_summary(advisory.get("summary"), "GitHub Advisory Database"),
        "repo": ", ".join(patch_repositories) or None,
        "file_path": str(path.relative_to(output_root)).replace("\\", "/"),
        "crawled_at": (advisory.get("collection") or {}).get("collected_at"),
        "severity": advisory.get("severity"),
        "cvss_score": cvss.get("score") if isinstance(cvss, dict) else cvss,
        "cve_id": advisory.get("cve_id"),
        "affected_software": ", ".join(software) or None,
        "affected_versions": ", ".join(versions) or None,
        "source_url": source_url,
        "provenance": source,
        "content": content,
        "references": [item for item in [source_url, *(advisory.get("references") or [])] if item],
    }
    return {"path": path, "record": record}


def codeql_entry(model: dict[str, Any], output_root: Path) -> dict[str, Any]:
    model_id = model.get("model_id") or "codeql-unknown"
    entry_id = canonical_id(model_id, "model")
    group = model.get("model_group") or "other"
    predicate = model.get("codeql_predicate") or "unknown"
    source = model.get("source") or {}
    tuple_value = json.dumps(model.get("model_tuple"), ensure_ascii=False, indent=2)
    title = f"CodeQL {predicate}: {model.get('library_model_file') or model_id}"
    is_doc_example = (
        model.get("knowledge_type")
        == "codeql_documentation_model_example"
    )
    model_label = (
        "Official CodeQL documentation example (not a runtime repository model)"
        if is_doc_example
        else "Official CodeQL library model"
    )
    content = (
        f"# {title}\n\n"
        "## Overview\n\n"
        f"{model_label} thuộc nhóm **{group}**.\n\n"
        "## Metadata\n\n"
        f"- **Source URL:** {source.get('url') or source.get('download_url') or 'N/A'}\n"
        f"- **Local raw:** {source.get('local_path') or 'N/A'}\n"
        f"- **Content SHA-256:** {source.get('content_sha256') or 'N/A'}\n\n"
        "## Tóm tắt (Tiếng Việt)\n\n"
        f"Model CodeQL nhóm {group}; cần đọc tuple theo context.\n\n"
        "## Technical Details\n\n"
        "Tuple giữ nguyên predicate và access path từ nguồn.\n\n"
        "## Impact\n\n"
        "Đây là semantic evidence, không tự kết luận lỗ hổng.\n\n"
        "## Proof of Concept\n\n"
        "Không có PoC; đây là model/data-flow evidence.\n\n"
        "## Detection\n\n"
        f"- **Predicate:** `{predicate}`\n"
        f"- **Pack:** `{model.get('codeql_pack') or 'N/A'}`\n"
        f"- **Language:** `{model.get('language') or 'N/A'}`\n"
        f"- **Human interpretation required:** "
        f"`{(model.get('semantics') or {}).get('requires_human_interpretation', True)}`\n\n"
        "### Model tuple\n\n"
        f"{fenced(tuple_value, 'json')}\n\n"
        "### Mapping cho KB\n\n"
        f"- Source: `{(model.get('semantics') or {}).get('is_source', False)}`\n"
        f"- Sink: `{(model.get('semantics') or {}).get('is_sink', False)}`\n"
        f"- Propagator: `{(model.get('semantics') or {}).get('is_propagator', False)}`\n"
        f"- Sanitizer/barrier: `{(model.get('semantics') or {}).get('is_sanitizer_or_barrier', False)}`\n\n"
        "## References\n\n"
        f"- {source.get('url') or source.get('download_url') or 'N/A'}\n\n"
        "## Exploitation\n\n"
        "Không thực thi exploit.\n\n"
        "## Remediation\n\n"
        "Cần xác nhận model bằng AST/CFG/call graph của codebase trước khi dùng.\n\n"
        "## Related Knowledge Base Entries\n\n"
        "Liên kết với source/sink/patch/PoC cùng vulnerability category khi có.\n\n"
        "## Additional Notes\n\n"
        "CodeQL tuple được giữ nguyên; không coi mọi barrier là sanitizer hợp lệ "
        "cho mọi vulnerability context.\n"
    )
    path = output_root / "entries" / f"{entry_id}.md"
    record = {
        "id": entry_id,
        "source_type": "github",
        "title": title,
        "aliases": [],
        "author": "GitHub CodeQL",
        "date": None,
        "event": None,
        "category": "technique",
        "tags": [
            item
            for item in ["codeql", model.get("language"), group, predicate]
            if item
        ],
        "keywords_vi": [group],
        "summary": (
            f"{model_label} for {model.get('library_model_file')}."
        ),
        "summary_vi": f"{model_label}; nhóm {group}, cần đọc tuple theo context.",
        "repo": source.get("repository"),
        "file_path": str(path.relative_to(output_root)).replace("\\", "/"),
        "crawled_at": source.get("retrieved_at"),
        "severity": "info",
        "cvss_score": None,
        "cve_id": None,
        "affected_software": model.get("codeql_pack"),
        "affected_versions": None,
        "source_url": source.get("url") or source.get("download_url"),
        "content": content,
        "references": [item for item in [source.get("url"), source.get("download_url")] if item],
        "provenance": source,
        "example_status": model.get("example_status"),
    }
    return {"path": path, "record": record}


def main() -> int:
    parser = argparse.ArgumentParser(description="Transform evidence thành KB entries.")
    base = Path(__file__).resolve().parents[1]
    parser.add_argument("--advisories", type=Path, default=base / "data" / "processed" / "ghsa" / "ghsa_advisories.json")
    parser.add_argument("--evidence", type=Path, default=base / "data" / "processed" / "github_evidence.jsonl")
    parser.add_argument("--models", type=Path, default=base / "data" / "processed" / "codeql_models.jsonl")
    parser.add_argument("--output-dir", type=Path, default=base / "data" / "processed" / "knowledge_base")
    args = parser.parse_args()

    advisories = json.loads(args.advisories.read_text(encoding="utf-8"))
    evidence = load_jsonl(args.evidence)
    models = load_jsonl(args.models)
    entries: list[dict[str, Any]] = []
    for advisory in advisories:
        entries.append(advisory_entry(advisory, evidence, args.output_dir))
    entries.extend(codeql_entry(model, args.output_dir) for model in models)

    args.output_dir.joinpath("entries").mkdir(parents=True, exist_ok=True)
    manifest_path = args.output_dir / "manifest.json"
    previous_manifest: dict[str, Any] = {}
    if manifest_path.exists():
        try:
            previous_manifest = json.loads(
                manifest_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            previous_manifest = {}
    current_paths = {
        item["record"]["file_path"] for item in entries
    }
    for stale_path in set(previous_manifest.get("entry_files", [])) - current_paths:
        stale_file = args.output_dir / stale_path
        if stale_file.is_file() and stale_file.suffix == ".md":
            stale_file.unlink()
    for item in entries:
        header = {
            key: item["record"].get(key)
            for key in FRONTMATTER_FIELDS
        }
        item["path"].write_text(
            frontmatter(header) + "\n" + item["record"]["content"],
            encoding="utf-8",
        )
        item["record"]["content_path"] = item["record"]["file_path"]
    output_jsonl = args.output_dir / "knowledge_base.jsonl"
    output_jsonl.write_text(
        "\n".join(json.dumps(item["record"], ensure_ascii=False) for item in entries) + "\n",
        encoding="utf-8",
    )
    manifest_path.write_text(
        json.dumps(
            {
                "entry_count": len(entries),
                "advisory_count": len(advisories),
                "codeql_model_count": len(models),
                "output_jsonl": str(output_jsonl),
                "entry_files": sorted(current_paths),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"Entries: {len(entries)}")
    print(f"Output: {output_jsonl.resolve()}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
