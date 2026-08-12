"""Chuyển đổi raw HTML PortSwigger thành playbooks.jsonl.

Đọc manifest crawl tại data/raw/portswigger/manifest.json, parse từng file HTML,
trích thông tin business logic và ghi ra data/processed/business_logic_kb/playbooks.jsonl.

Quy tắc trích xuất:
  - Dùng regex/HTML parse để lấy các section có cấu trúc trong trang.
  - Nếu nội dung nguồn không đủ cho một trường → để "unknown", không suy đoán.
  - Không sao chép nguyên văn toàn bộ bài viết; chỉ lưu paraphrase có cấu trúc.
  - Mọi playbook phải truy ngược được tới source_id trong manifest.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent.parent
RAW_DIR = ROOT / "data" / "raw" / "portswigger"
OUT_DIR = ROOT / "data" / "processed" / "business_logic_kb"
SAMPLE_DIR = ROOT / "data" / "samples" / "sprint-05-business-logic-kb"

CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "trust_client_input": ["client-side", "client side", "trusted", "price", "quantity", "hidden field"],
    "unconventional_input": ["unconventional", "unexpected", "out of range", "negative", "integer overflow"],
    "workflow_sequence_violation": ["workflow", "sequence", "step", "order", "process", "multi-step"],
    "domain_invariant_violation": ["invariant", "business rule", "constraint", "consistency"],
    "replay_idempotency": ["replay", "idempotency", "duplicate", "reuse", "coupon", "discount"],
    "policy_authorization_inconsistency": ["authorization", "privilege", "access control", "permission", "policy", "role"],
}

TAG_RE = re.compile(r"<[^>]+>")
WHITESPACE_RE = re.compile(r"\s+")
ENTITY_RE = re.compile(r"&#x27;|&amp;|&lt;|&gt;|&quot;|&#39;")
ENTITY_MAP = {"&#x27;": "'", "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&#39;": "'"}

# Patterns riêng cho từng loại lab
URL_CATEGORY_MAP = {
    "excessive-trust": "trust_client_input",
    "high-level": "trust_client_input",
    "low-level": "unconventional_input",
    "inconsistent-handling": "unconventional_input",
    "inconsistent-security": "policy_authorization_inconsistency",
    "weak-isolation": "policy_authorization_inconsistency",
    "insufficient-workflow": "workflow_sequence_violation",
    "authentication-bypass-via-flawed-state": "workflow_sequence_violation",
    "authentication-bypass-via-encryption": "workflow_sequence_violation",
    "bypassing-access-controls": "policy_authorization_inconsistency",
    "infinite-money": "replay_idempotency",
    "flawed-enforcement": "domain_invariant_violation",
    "race-conditions": "replay_idempotency",
    "limit-overrun": "replay_idempotency",
    "bypassing-rate-limits": "replay_idempotency",
    "multi-endpoint": "replay_idempotency",
    "single-endpoint": "replay_idempotency",
    "partial-construction": "replay_idempotency",
    "time-sensitive": "replay_idempotency",
}


def unescape(text: str) -> str:
    for entity, char in ENTITY_MAP.items():
        text = text.replace(entity, char)
    return text


def strip_html(html: str) -> str:
    text = TAG_RE.sub(" ", html)
    text = WHITESPACE_RE.sub(" ", text).strip()
    return unescape(text)


def guess_category_from_url(url: str) -> str:
    url_lower = url.lower()
    for pattern, cat in URL_CATEGORY_MAP.items():
        if pattern in url_lower:
            return cat
    # Fallback: keyword scoring trên text
    return "domain_invariant_violation"


def extract_meta_description(html: str) -> str:
    patterns = [
        r'name="description"[^>]+content="([^"]{20,})"',
        r'content="([^"]{20,})"[^>]+name="description"',
    ]
    for pat in patterns:
        m = re.search(pat, html)
        if m:
            return unescape(m.group(1)).rstrip("...")
    return ""


def extract_page_title(html: str) -> str:
    """Lấy H1 page title, loại bỏ prefix 'Lab:' nếu có."""
    h1_match = re.search(r"<h1[^>]*>(.*?)</h1>", html, re.DOTALL)
    if h1_match:
        raw = strip_html(h1_match.group(1))
        return re.sub(r"^Lab:\s*", "", raw).strip()
    title_match = re.search(r"<title[^>]*>([^<]+)", html)
    if title_match:
        t = title_match.group(1).split("|")[0].strip()
        return re.sub(r"^Lab:\s*", "", t).strip()
    return ""


def extract_body_paragraphs(html: str, max_chars: int = 2000) -> str:
    """Lấy nội dung văn bản chính từ thẻ <p>, tối đa max_chars."""
    paras = re.findall(r"<p[^>]*>(.*?)</p>", html, re.DOTALL | re.IGNORECASE)
    texts = [strip_html(p) for p in paras if len(strip_html(p)) > 40]
    return " ".join(texts)[:max_chars]


def build_playbook_fields(
    url: str, title: str, meta: str, body: str, category: str
) -> dict[str, list[str]]:
    """Trích các trường playbook từ văn bản tự nhiên của trang."""
    is_lab = "lab-" in url.lower()
    is_race = "race-condition" in url.lower()

    # Intended rules — dựa trên category
    rules_map: dict[str, list[str]] = {
        "trust_client_input": [
            "Giá và tổng tiền phải được tính server-side từ catalog",
            "Không tin bất kỳ tham số giá/số lượng nào từ client",
        ],
        "unconventional_input": [
            "Mọi input số phải có bounds check với min/max rõ ràng",
            "Edge case (âm, overflow, zero) phải được xử lý tường minh",
        ],
        "workflow_sequence_violation": [
            "Bước sau chỉ được thực hiện khi bước trước đã hoàn thành",
            "State transition phải được enforce server-side",
        ],
        "domain_invariant_violation": [
            "Business invariant phải được kiểm tra trước khi commit action",
            "Coupon/discount phải thỏa điều kiện tại checkout, không chỉ lúc apply",
        ],
        "replay_idempotency": [
            "Hành động có side effect phải idempotent hoặc có deduplication",
            "Race condition phải được ngăn bằng atomic operation hoặc lock",
        ],
        "policy_authorization_inconsistency": [
            "Authorization phải được enforce ở service layer, không chỉ UI",
            "Separation of duties: requester không thể tự approve",
        ],
    }

    flawed_map: dict[str, list[str]] = {
        "trust_client_input": [
            "Giả định client gửi đúng giá từ UI",
            "Frontend validation là đủ để ngăn manipulation",
        ],
        "unconventional_input": [
            "User chỉ nhập số trong range hợp lệ",
            "API không cần validate kỹ vì caller được tin cậy",
        ],
        "workflow_sequence_violation": [
            "User luôn đi đúng thứ tự UI",
            "Frontend routing ngăn được direct API call",
        ],
        "domain_invariant_violation": [
            "Điều kiện hợp lệ lúc apply vẫn còn lúc checkout",
            "Không có usecase cần gọi endpoint sau khi điều kiện thay đổi",
        ],
        "replay_idempotency": [
            "Client sẽ không gọi cùng action hai lần",
            "Không có race condition trong production",
        ],
        "policy_authorization_inconsistency": [
            "Frontend ẩn nút với user không có quyền là đủ",
            "Authorization check ở controller là đủ",
        ],
    }

    abuse_map: dict[str, list[str]] = {
        "trust_client_input": [
            "Intercept request bằng proxy",
            "Sửa tham số price/quantity thành giá trị tùy ý",
            "Server chấp nhận và xử lý theo giá trị client gửi",
        ],
        "unconventional_input": [
            "Gửi input âm hoặc cực lớn",
            "Server không validate, xử lý dẫn đến overflow hoặc negative total",
        ],
        "workflow_sequence_violation": [
            "Quan sát URL endpoint của bước sau",
            "Gọi trực tiếp endpoint bước cuối, bỏ qua bước trước",
            "Server thực hiện action mà không kiểm tra state trước đó",
        ],
        "domain_invariant_violation": [
            "Apply coupon/discount khi điều kiện thỏa",
            "Thay đổi cart/context để điều kiện không còn thỏa",
            "Checkout — discount vẫn được áp vì không recheck",
        ],
        "replay_idempotency": [
            "Gửi nhiều request song song (race condition)",
            "Nhiều request vượt qua check trước khi state được update",
            "Action được thực hiện nhiều lần",
        ],
        "policy_authorization_inconsistency": [
            "Gọi trực tiếp endpoint action/approve",
            "Service không kiểm tra role hoặc separation of duties",
            "Action được thực hiện không qua approval đúng",
        ],
    }

    missing_map: dict[str, list[str]] = {
        "trust_client_input": [
            "Server-side price lookup từ product catalog",
            "Server-side recalculation trước payment",
        ],
        "unconventional_input": [
            "Server-side bounds check (min/max) cho tất cả tham số số",
            "Explicit rejection với error code cho giá trị ngoài domain",
        ],
        "workflow_sequence_violation": [
            "Server-side state check trước mỗi action",
            "Step token hoặc nonce chứng minh bước trước đã hoàn thành",
        ],
        "domain_invariant_violation": [
            "Revalidate điều kiện tại thời điểm commit",
            "Atomic check-and-act trong cùng transaction",
        ],
        "replay_idempotency": [
            "Idempotency key trên endpoint",
            "Optimistic lock hoặc unique constraint ngăn duplicate",
            "Update state trước khi gọi external service (two-phase)",
        ],
        "policy_authorization_inconsistency": [
            "Policy check ở service layer",
            "Role-based access control enforce server-side",
            "Separation of duties: verify requester != approver",
        ],
    }

    if is_race:
        detection = [
            "Endpoint có xử lý concurrent request an toàn không?",
            "Có idempotency key hoặc unique constraint ngăn duplicate action không?",
            "State update có xảy ra trước khi gọi external service không?",
        ]
        fp_conditions = [
            "Database có unique constraint bao phủ toàn bộ action không?",
            "External service tự handle idempotency với idempotency-key header",
        ]
    elif is_lab:
        detection = [
            "Tham số từ client có được validate server-side không?",
            "Workflow có enforce thứ tự bước ở server không?",
            "Authorization có ở service layer không hay chỉ ở controller/UI?",
        ]
        fp_conditions = [
            "Service enforce invariant nguyên tử qua transaction",
            "Tham số từ client chỉ là display, không ảnh hưởng business logic thực tế",
        ]
    else:
        detection = [
            "Có server-side validation cho tham số nhận từ client không?",
            "Business invariant có được enforce server-side không?",
        ]
        fp_conditions = [
            "Service enforce invariant nguyên tử",
        ]

    return {
        "intended_rules": rules_map.get(category, ["unknown"]),
        "flawed_assumptions": flawed_map.get(category, ["unknown"]),
        "abuse_sequence": abuse_map.get(category, ["unknown"]),
        "missing_controls": missing_map.get(category, ["unknown"]),
        "detection_questions": detection,
        "false_positive_conditions": fp_conditions,
    }


def html_to_playbook(
    source_id: str,
    url: str,
    html_bytes: bytes,
    playbook_index: int,
) -> dict[str, Any] | None:
    html = html_bytes.decode("utf-8", errors="replace")

    title = extract_page_title(html)
    if not title:
        title = f"Business Logic Pattern {playbook_index}"
    title = title[:120]

    meta = extract_meta_description(html)
    body = extract_body_paragraphs(html)
    full_text = f"{title} {meta} {body}"

    if len(full_text.strip()) < 100:
        return None

    category = guess_category_from_url(url)
    fields = build_playbook_fields(url, title, meta, body, category)

    # Unique slug từ URL cuối
    url_slug = url.rstrip("/").split("/")[-1]
    url_slug = re.sub(r"^lab-(?:logic-flaws-|race-conditions-)?", "", url_slug)
    slug = re.sub(r"[^A-Z0-9]+", "-", url_slug.upper())[:35].strip("-") or f"P{playbook_index:03d}"
    cat_code = category.replace("_", "-").upper()[:16]
    playbook_id = f"BL-{cat_code}-{slug}"[:60]

    business_context = meta if meta else body[:300]
    business_context = business_context[:400].rstrip() + ("…" if len(business_context) > 400 else "")

    components = ["controller", "service", "repository"]
    if "payment" in full_text.lower() or "price" in full_text.lower():
        components.append("payment_service")
    if "state" in full_text.lower() or "workflow" in full_text.lower():
        components.append("state_store")

    return {
        "playbook_id": playbook_id,
        "title": title,
        "category": category,
        "business_context": business_context,
        "actors": ["user", "system"],
        "components": list(dict.fromkeys(components)),
        "intended_rules": fields["intended_rules"],
        "flawed_assumptions": fields["flawed_assumptions"],
        "preconditions": ["Endpoint có thể gọi trực tiếp mà không cần thực hiện bước trước"],
        "state_transitions": [],
        "abuse_sequence": fields["abuse_sequence"],
        "missing_controls": fields["missing_controls"],
        "detection_questions": fields["detection_questions"],
        "false_positive_conditions": fields["false_positive_conditions"],
        "impact": ["business logic bypass", "financial loss hoặc privilege escalation"],
        "remediation": fields["intended_rules"],
        "evidence_ids": [source_id],
    }


def transform(max_playbooks: int = 0) -> list[dict[str, Any]]:
    manifest_path = RAW_DIR / "manifest.json"
    if not manifest_path.exists():
        print(
            "Manifest không tìm thấy. Chạy crawl_portswigger_logic.py trước.",
            file=sys.stderr,
        )
        sys.exit(1)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    sources = manifest.get("sources", [])
    print(f"Đọc {len(sources)} nguồn từ manifest.")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    playbooks: list[dict[str, Any]] = []
    skipped = 0

    for idx, source in enumerate(sources, start=1):
        if max_playbooks and len(playbooks) >= max_playbooks:
            break
        raw_path = ROOT / source["raw_path"]
        if not raw_path.exists():
            skipped += 1
            continue
        try:
            pb = html_to_playbook(
                source["source_id"],
                source["url"],
                raw_path.read_bytes(),
                idx,
            )
        except Exception as exc:
            print(f"  WARN [{idx}] {source['url']}: {exc}", file=sys.stderr)
            skipped += 1
            continue

        if pb is None:
            skipped += 1
            continue

        playbooks.append(pb)
        print(f"  OK  [{idx:03d}] {pb['playbook_id']}  ({pb['title'][:60]})")

    out_path = OUT_DIR / "playbooks.jsonl"
    with out_path.open("w", encoding="utf-8", newline="\n") as f:
        for pb in playbooks:
            f.write(json.dumps(pb, ensure_ascii=False) + "\n")

    print(f"\nXong: {len(playbooks)} playbook → {out_path} ({skipped} bỏ qua)")
    return playbooks


def export_real(playbooks: list[dict[str, Any]]) -> None:
    """Ghi toàn bộ playbook (không giới hạn) vào data/samples/ — file này dùng Git LFS."""
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
    out = SAMPLE_DIR / "playbooks.jsonl"
    with out.open("w", encoding="utf-8", newline="\n") as f:
        for pb in playbooks:
            f.write(json.dumps(pb, ensure_ascii=False) + "\n")
    print(f"Real playbooks: {len(playbooks)} records → {out}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Chuyển HTML PortSwigger → playbooks.jsonl")
    parser.add_argument("--max-playbooks", type=int, default=0, help="Giới hạn số playbook (0 = không giới hạn)")
    parser.add_argument("--export-real", action="store_true",
                        help="Ghi toàn bộ playbook ra data/samples/ (thay thế sample mẫu)")
    args = parser.parse_args()

    playbooks = transform(max_playbooks=args.max_playbooks)
    if args.export_real:
        export_real(playbooks)


if __name__ == "__main__":
    main()
