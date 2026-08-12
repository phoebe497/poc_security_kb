"""Crawler PortSwigger Business Logic Vulnerabilities.

Thu thập HTML từ các trang Business Logic của PortSwigger Web Security Academy:
overview, examples, prevention và lab pages. Lưu raw HTML local với SHA-256 và
thông tin provenance. Không chạy JavaScript, lab hoặc payload.

Phạm vi được phép:
  https://portswigger.net/web-security/logic-flaws
  và các trang được discovery từ trang đó trong cùng phạm vi /web-security/.

Chính sách dữ liệu:
  - Raw HTML giữ local (data/raw/portswigger/), không commit.
  - Chỉ commit manifest và playbook đã chuẩn hóa.
  - Không sao chép nguyên văn toàn bộ bài viết lên Git.
  - Không tự thực thi bất kỳ code hoặc payload nào lấy từ trang.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent.parent
RAW_DIR = ROOT / "data" / "raw" / "portswigger"

_LAB_BASE = "https://portswigger.net/web-security/logic-flaws/examples/"
_RACE_BASE = "https://portswigger.net/web-security/race-conditions"

# Lab URLs lấy từ sitemap PortSwigger (cố định, không thay đổi theo crawl)
_KNOWN_LABS = [
    _LAB_BASE + "lab-logic-flaws-excessive-trust-in-client-side-controls",
    _LAB_BASE + "lab-logic-flaws-high-level",
    _LAB_BASE + "lab-logic-flaws-low-level",
    _LAB_BASE + "lab-logic-flaws-inconsistent-handling-of-exceptional-input",
    _LAB_BASE + "lab-logic-flaws-inconsistent-security-controls",
    _LAB_BASE + "lab-logic-flaws-weak-isolation-on-dual-use-endpoint",
    _LAB_BASE + "lab-logic-flaws-insufficient-workflow-validation",
    _LAB_BASE + "lab-logic-flaws-authentication-bypass-via-flawed-state-machine",
    _LAB_BASE + "lab-logic-flaws-infinite-money",
    _LAB_BASE + "lab-logic-flaws-flawed-enforcement-of-business-rules",
    _LAB_BASE + "lab-logic-flaws-authentication-bypass-via-encryption-oracle",
    _LAB_BASE + "lab-logic-flaws-bypassing-access-controls-using-email-address-parsing-discrepancies",
    # Race condition labs (idempotency / replay)
    _RACE_BASE,
    _RACE_BASE + "/lab-race-conditions-limit-overrun",
    _RACE_BASE + "/lab-race-conditions-bypassing-rate-limits",
    _RACE_BASE + "/lab-race-conditions-multi-endpoint",
    _RACE_BASE + "/lab-race-conditions-single-endpoint",
    _RACE_BASE + "/lab-race-conditions-partial-construction",
    _RACE_BASE + "/lab-race-conditions-exploiting-time-sensitive-vulnerabilities",
]

SEED_URLS = [
    "https://portswigger.net/web-security/logic-flaws",
    "https://portswigger.net/web-security/logic-flaws/examples",
] + _KNOWN_LABS

# Chỉ follow link nằm trong các prefix BL-relevant
BL_PREFIXES = (
    "https://portswigger.net/web-security/logic-flaws",
    "https://portswigger.net/web-security/race-conditions",
)

ALLOWED_PREFIX = "https://portswigger.net/web-security/"
EXCLUDE_PATTERNS = re.compile(
    r"/(login|register|sign-up|dashboard|forum|community|pro|burp|careers)"
)

USER_AGENT = "security-kb-crawler/3.0 (research, non-commercial)"
TIMEOUT = 20
RETRIES = 2
CRAWL_DELAY = 1.5
MAX_PAGES = 80
MAX_BYTES = 2 * 1024 * 1024

LINK_RE = re.compile(r'href=["\'](/web-security/[^"\'#?]+)["\']')
ID_RE = re.compile(r"[^A-Za-z0-9]+")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_id(url: str, index: int) -> str:
    slug = ID_RE.sub("-", urllib.parse.urlparse(url).path.strip("/"))[:60]
    return f"PS-SOURCE-{index:03d}-{slug}"


def fetch(url: str, session_headers: dict[str, str]) -> tuple[bytes, str, int]:
    """Tải URL, trả về (body_bytes, final_url, status). Ném RuntimeError khi thất bại."""
    last_exc: Exception | None = None
    for attempt in range(RETRIES + 1):
        req = urllib.request.Request(url, headers=session_headers)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                body = resp.read(MAX_BYTES + 1)
                if len(body) > MAX_BYTES:
                    raise RuntimeError(f"Nội dung vượt giới hạn {MAX_BYTES} bytes: {url}")
                return body, resp.geturl(), resp.status
        except urllib.error.HTTPError as exc:
            last_exc = RuntimeError(f"HTTP {exc.code}: {url}")
            if exc.code not in {429, 500, 502, 503, 504}:
                break
        except (urllib.error.URLError, TimeoutError) as exc:
            last_exc = exc
        if attempt < RETRIES:
            time.sleep(1 + attempt)
    raise RuntimeError(str(last_exc or f"Không thể tải: {url}"))


def is_bl_relevant(url: str) -> bool:
    """Chỉ follow link trong phạm vi Business Logic / Race Conditions."""
    return any(url.startswith(p) for p in BL_PREFIXES)


def discover_links(html: bytes, base: str) -> list[str]:
    """Trích link /web-security/... từ HTML, chỉ giữ link BL-relevant."""
    text = html.decode("utf-8", errors="replace")
    urls: list[str] = []
    for match in LINK_RE.finditer(text):
        path = match.group(1)
        url = urllib.parse.urljoin(base, path)
        if (
            is_bl_relevant(url)
            and not EXCLUDE_PATTERNS.search(url)
            and "#" not in url
        ):
            urls.append(url)
    return list(dict.fromkeys(urls))


def crawl(limit: int = MAX_PAGES) -> list[dict[str, Any]]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
    }

    queue = list(SEED_URLS)
    visited: set[str] = set()
    sources: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    index = 1

    RAW_DIR.mkdir(parents=True, exist_ok=True)

    while queue and len(visited) < limit:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            body, final_url, status = fetch(url, headers)
        except RuntimeError as exc:
            errors.append({"url": url, "error": str(exc), "crawled_at": utc_now()})
            print(f"  ERROR {url}: {exc}", file=sys.stderr)
            continue

        digest = sha256_bytes(body)
        sid = source_id(url, index)
        slug = ID_RE.sub("_", urllib.parse.urlparse(url).path.strip("/"))[:80]
        raw_path = RAW_DIR / f"{sid}.html"
        raw_path.write_bytes(body)

        record: dict[str, Any] = {
            "source_id": sid,
            "url": url,
            "final_url": final_url,
            "crawled_at": utc_now(),
            "http_status": status,
            "content_type": "text/html",
            "sha256": digest,
            "raw_path": str(raw_path.relative_to(ROOT)),
            "byte_size": len(body),
        }
        sources.append(record)
        print(f"  OK [{index:03d}] {url}")

        new_links = discover_links(body, final_url)
        for link in new_links:
            if link not in visited and link not in queue:
                queue.append(link)

        index += 1
        time.sleep(CRAWL_DELAY)

    manifest: dict[str, Any] = {
        "schema_version": "1",
        "crawled_at": utc_now(),
        "seed_urls": SEED_URLS,
        "total_pages": len(sources),
        "total_errors": len(errors),
        "sources": sources,
        "errors": errors,
    }

    manifest_path = RAW_DIR / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"\nCrawl xong: {len(sources)} trang, {len(errors)} lỗi.")
    print(f"Manifest: {manifest_path}")
    return sources


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Crawl PortSwigger Business Logic pages."
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=MAX_PAGES,
        help=f"Số trang tối đa (mặc định {MAX_PAGES})",
    )
    args = parser.parse_args()
    crawl(limit=args.limit)


if __name__ == "__main__":
    main()
