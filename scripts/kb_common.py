"""Tiện ích dùng chung cho các crawler Security KB.

Chỉ tải nội dung văn bản/JSON từ các URL do crawler tạo ra. Nội dung tải về
được coi là dữ liệu không tin cậy và không bao giờ được thực thi.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_MAX_BYTES = 5 * 1024 * 1024
GITHUB_URL_RE = re.compile(
    r"https://github\.com/"
    r"(?P<owner>[^/\s]+)/(?P<repo>[^/\s?#]+)"
    r"(?:/(?P<kind>commit|pull|issues)/(?P<identifier>[^/\s?#]+))?"
)
URL_RE = re.compile(r"https?://[^\s<>()\]\"']+")
POC_HEADING_RE = re.compile(
    r"(?i)\b("
    r"proof[\s-]+of[\s-]+concept|poc|"
    r"steps?[\s-]+to[\s-]+reproduce|reproduction|"
    r"exploit(?:ation)?|demonstration"
    r")\b"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_slug(value: str, max_length: int = 120) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return (value or "unknown")[:max_length]


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")


@dataclass(frozen=True)
class GitHubReference:
    owner: str
    repo: str
    kind: str | None
    identifier: str | None
    url: str

    @property
    def canonical_url(self) -> str:
        base = f"https://github.com/{self.owner}/{self.repo}"
        if self.kind and self.identifier:
            return f"{base}/{self.kind}/{self.identifier}"
        return base


def parse_github_reference(url: str) -> GitHubReference | None:
    match = GITHUB_URL_RE.search(url.rstrip(".,;:"))
    if not match:
        return None
    kind = match.group("kind")
    identifier = match.group("identifier")
    if kind in {"commit", "pull"} and identifier:
        identifier = re.sub(r"\.(?:patch|diff)$", "", identifier)
    return GitHubReference(
        owner=match.group("owner"),
        repo=match.group("repo").removesuffix(".git"),
        kind=kind,
        identifier=identifier,
        url=url.rstrip(".,;:"),
    )


def extract_urls(text: str | None) -> list[str]:
    if not text:
        return []
    return [match.group(0).rstrip(".,;:") for match in URL_RE.finditer(text)]


def extract_poc_sections(markdown: str | None) -> list[dict[str, str]]:
    """Lấy các section PoC/reproduction từ Markdown, không diễn giải nội dung."""
    if not markdown:
        return []
    headings = list(
        re.finditer(r"(?m)^(?P<marks>#{1,6})[ \t]+(?P<title>.+?)[ \t]*$", markdown)
    )
    sections: list[dict[str, str]] = []
    for index, heading in enumerate(headings):
        title = heading.group("title").strip()
        if not POC_HEADING_RE.search(title):
            continue
        end = len(markdown)
        current_level = len(heading.group("marks"))
        for next_heading in headings[index + 1 :]:
            if len(next_heading.group("marks")) <= current_level:
                end = next_heading.start()
                break
        body = markdown[heading.end() : end]
        if body.strip():
            sections.append({"title": title, "body": body})
    return sections


class HttpClient:
    def __init__(self, timeout: int = 30, retries: int = 2) -> None:
        self.timeout = timeout
        self.retries = retries
        self.default_headers = {
            "User-Agent": "security-kb-crawler/2.0",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        token = os.getenv("GITHUB_TOKEN")
        if token:
            self.default_headers["Authorization"] = f"Bearer {token}"

    def get_bytes(
        self,
        url: str,
        *,
        accept: str | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> tuple[bytes, dict[str, str]]:
        headers = dict(self.default_headers)
        if accept:
            headers["Accept"] = accept
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            request = urllib.request.Request(url, headers=headers)
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    length = response.headers.get("Content-Length")
                    if length:
                        try:
                            length_value = int(length)
                        except ValueError as exc:
                            raise RuntimeError(
                                f"Content-Length không hợp lệ từ {url}: {length}"
                            ) from exc
                        if length_value > max_bytes:
                            raise RuntimeError(
                                f"Nội dung quá lớn ({length} bytes), "
                                f"giới hạn {max_bytes}: {url}"
                            )
                    data = response.read(max_bytes + 1)
                    if len(data) > max_bytes:
                        raise RuntimeError(
                            f"Nội dung vượt giới hạn {max_bytes} bytes: {url}"
                        )
                    metadata = {
                        "final_url": response.geturl(),
                        "content_type": response.headers.get("Content-Type", ""),
                        "etag": response.headers.get("ETag", ""),
                        "last_modified": response.headers.get("Last-Modified", ""),
                    }
                    return data, metadata
            except urllib.error.HTTPError as exc:
                body = exc.read(4096).decode("utf-8", errors="replace")
                last_error = RuntimeError(
                    f"HTTP {exc.code} khi tải {url}: {body}"
                )
                rate_limited = exc.code == 403 and (
                    exc.headers.get("Retry-After")
                    or exc.headers.get("X-RateLimit-Remaining") == "0"
                )
                if exc.code not in {429, 500, 502, 503, 504} and not rate_limited:
                    break
            except (urllib.error.URLError, TimeoutError, RuntimeError) as exc:
                last_error = exc
            if attempt < self.retries:
                time.sleep(1 + attempt)
        raise RuntimeError(str(last_error or f"Không thể tải {url}"))

    def get_json(
        self,
        url: str,
        *,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> tuple[Any, bytes, dict[str, str]]:
        data, metadata = self.get_bytes(
            url,
            accept="application/vnd.github+json",
            max_bytes=max_bytes,
        )
        return json.loads(data.decode("utf-8")), data, metadata

    def post_json(
        self,
        url: str,
        payload: dict[str, Any],
        *,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> tuple[Any, bytes, dict[str, str]]:
        """POST JSON với cùng giới hạn timeout/retry/size như các GET request."""
        request_body = json.dumps(payload).encode("utf-8")
        headers = dict(self.default_headers)
        headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            request = urllib.request.Request(
                url,
                data=request_body,
                headers=headers,
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    data = response.read(max_bytes + 1)
                    if len(data) > max_bytes:
                        raise RuntimeError(
                            f"Nội dung vượt giới hạn {max_bytes} bytes: {url}"
                        )
                    metadata = {
                        "final_url": response.geturl(),
                        "content_type": response.headers.get("Content-Type", ""),
                        "etag": response.headers.get("ETag", ""),
                        "last_modified": response.headers.get("Last-Modified", ""),
                    }
                    return json.loads(data.decode("utf-8")), data, metadata
            except urllib.error.HTTPError as exc:
                body = exc.read(4096).decode("utf-8", errors="replace")
                last_error = RuntimeError(
                    f"HTTP {exc.code} khi POST {url}: {body}"
                )
                if exc.code not in {429, 500, 502, 503, 504}:
                    break
            except (urllib.error.URLError, TimeoutError, RuntimeError) as exc:
                last_error = exc
            if attempt < self.retries:
                time.sleep(1 + attempt)
        raise RuntimeError(str(last_error or f"Không thể POST {url}"))
