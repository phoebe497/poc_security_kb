"""Benchmark LLM không KB vs có KB trên bộ câu hỏi Business Logic.

Hai vòng lặp:
  A — Baseline: question + code, không có KB context
  B — KB-assisted: question + code + toàn bộ playbook KB

Chấm điểm: LLM-as-Judge — một model riêng biệt đọc câu trả lời, gold answer
và rubric, trả về JSON điểm từng tiêu chí kèm lý do ngắn. Không dùng keyword
matching; không dùng cùng model vừa trả lời làm giám khảo.

API: OpenCode Zen (OpenAI-compatible). Chỉ cần thay OPENCODE_API_KEY.

Cấu hình mặc định (đã chọn sẵn):
  --model        glm-5.1        (responder — model năng lực thấp được đánh giá)
  --judge-model  gpt-5.6-luna   (judge — khác họ model, mạnh hơn, output sạch)
  --base-url     https://opencode.ai/zen/go/v1
  --temperature  0 (bắt buộc để tái lập)
  --runs         số lần chạy mỗi câu mỗi condition (mặc định 1; dùng 3 khi cần CI)

Lưu toàn bộ raw response và rubric JSON vào benchmark_runs.jsonl (Git LFS).
Kết quả aggregate vào benchmark_summary.json.

Yêu cầu:
  - Python 3.10+
  - OPENCODE_API_KEY  (qua file .env ở gốc repo, hoặc export ra môi trường)
  - data/samples/sprint-05-business-logic-kb/playbooks.jsonl
  - data/samples/sprint-05-business-logic-kb/questions.jsonl
  - data/samples/sprint-05-business-logic-kb/answer_key.jsonl

Chạy:
  cp .env.example .env          # rồi sửa OPENCODE_API_KEY trong .env
  python3 scripts/run_business_logic_benchmark.py
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent.parent
SAMPLE_DIR = ROOT / "data" / "samples" / "sprint-05-business-logic-kb"

# ── OpenCode Zen defaults (chỉ cần thay OPENCODE_API_KEY) ────────────────────────
DEFAULT_BASE_URL = "https://opencode.ai/zen/go/v1"
DEFAULT_RESPONDER_MODEL = "glm-5.1"             # model năng lực thấp được đánh giá
DEFAULT_JUDGE_MODEL = "gpt-5.6-luna"            # judge khác họ model, output sạch
DEFAULT_MAX_TOKENS = 4000                       # headroom cho model reasoning (glm) không bị cụt


def load_dotenv(path: Path) -> None:
    """Đọc file .env đơn giản (KEY=VALUE) và nạp vào os.environ.

    Không ghi đè biến môi trường đã có sẵn. Bỏ qua dòng trống và comment.
    Không cần thư viện ngoài để giữ script tự chứa.
    """
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value

# ── Rubric ─────────────────────────────────────────────────────────────────────
RUBRIC: dict[str, dict[str, Any]] = {
    "correct_bug_identified": {
        "max": 2,
        "description": "Xác định đúng loại lỗi business logic (không phải lỗi kỹ thuật như SQLi/XSS).",
    },
    "business_rule_stated": {
        "max": 2,
        "description": "Nêu đúng business rule hoặc invariant bị vi phạm.",
    },
    "abuse_flow_described": {
        "max": 2,
        "description": "Mô tả abuse flow đi qua ít nhất 2 component (controller, service, repo, v.v.).",
    },
    "precondition_stated": {
        "max": 1,
        "description": "Nêu điều kiện cần để khai thác lỗi.",
    },
    "impact_stated": {
        "max": 1,
        "description": "Nêu hậu quả nghiệp vụ cụ thể (không chỉ 'có lỗi').",
    },
    "remediation_server_side": {
        "max": 1,
        "description": "Đề xuất cách sửa đúng tầng server/service, không chỉ client-side.",
    },
    "no_hallucination": {
        "max": 1,
        "description": "Không hallucinate lỗi kỹ thuật không liên quan (SQLi, XSS, auth bypass không có trong code).",
    },
}
MAX_SCORE = sum(c["max"] for c in RUBRIC.values())  # 10

# ── System prompts ──────────────────────────────────────────────────────────────
RESPONDER_SYSTEM = (
    "You are a security code reviewer specializing in business logic vulnerabilities. "
    "Analyze the provided source code carefully. "
    "For each finding report: (1) the vulnerability type, (2) the business rule or invariant violated, "
    "(3) the abuse flow across components step by step, (4) preconditions required to exploit, "
    "(5) business impact, (6) server-side remediation. "
    "If there is no exploitable vulnerability, explain why the code is safe. "
    "Do NOT invent SQL injection, XSS, or authentication issues unless clearly present."
)

JUDGE_SYSTEM = (
    "You are an objective benchmark judge evaluating security code review responses. "
    "You will receive: a question, a gold answer, a candidate response, and a rubric. "
    "Score each rubric criterion independently based on the candidate response. "
    "Return ONLY valid JSON with no markdown fences, no explanation outside JSON. "
    "Format: {\"scores\": {\"<criterion>\": <int>, ...}, \"reasons\": {\"<criterion>\": \"<1-sentence reason>\", ...}}"
)


# ── HTTP helpers ────────────────────────────────────────────────────────────────
def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        print(f"File không tìm thấy: {path}", file=sys.stderr)
        sys.exit(1)
    records = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def call_llm(
    messages: list[dict[str, str]],
    *,
    model: str,
    temperature: float,
    max_tokens: int,
    api_key: str,
    base_url: str,
    retries: int = 2,
) -> str:
    payload = {
        "model": model,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "messages": messages,
    }
    body = json.dumps(payload).encode("utf-8")
    url = f"{base_url.rstrip('/')}/chat/completions"
    last_err: Exception | None = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {api_key}",
                # Cloudflare (error 1010) chặn UA mặc định của urllib → giả UA trình duyệt
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=90) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as exc:
            body_err = exc.read(512).decode("utf-8", errors="replace")
            last_err = RuntimeError(f"HTTP {exc.code}: {body_err}")
            if exc.code not in {429, 500, 502, 503, 504}:
                break
        except Exception as exc:
            last_err = exc
        if attempt < retries:
            time.sleep(2 ** attempt)
    raise RuntimeError(str(last_err or "API call failed"))


# ── LLM-as-Judge ───────────────────────────────────────────────────────────────
def judge_response(
    question: dict[str, Any],
    gold: dict[str, Any],
    candidate_response: str,
    *,
    judge_model: str,
    temperature: float,
    api_key: str,
    base_url: str,
) -> dict[str, Any]:
    """Gọi LLM judge để chấm điểm một response theo rubric.

    Judge trả về JSON với scores và reasons cho từng criterion. Nếu parse JSON
    thất bại, tất cả scores = 0 và lý do ghi lại error.
    """
    rubric_text = "\n".join(
        f"  - {k} (0–{v['max']}): {v['description']}"
        for k, v in RUBRIC.items()
    )
    judge_prompt = f"""Question:
{question['requirements']}

Source code:
```
{question['source_code']}
```

Gold answer (reference):
{gold.get('gold_summary', '')}

Candidate response to evaluate:
{candidate_response}

Rubric (score each independently):
{rubric_text}

Return ONLY JSON. Example:
{{
  "scores": {{
    "correct_bug_identified": 2,
    "business_rule_stated": 1,
    "abuse_flow_described": 2,
    "precondition_stated": 1,
    "impact_stated": 0,
    "remediation_server_side": 1,
    "no_hallucination": 1
  }},
  "reasons": {{
    "correct_bug_identified": "Correctly identified price manipulation",
    "business_rule_stated": "Stated rule partially but missed server-side enforcement requirement",
    "abuse_flow_described": "Described full flow through controller and payment service",
    "precondition_stated": "Noted attacker needs to intercept request",
    "impact_stated": "Did not state business impact clearly",
    "remediation_server_side": "Suggested looking up price from catalog",
    "no_hallucination": "No hallucinated issues"
  }}
}}"""

    messages = [
        {"role": "system", "content": JUDGE_SYSTEM},
        {"role": "user", "content": judge_prompt},
    ]
    try:
        raw = call_llm(
            messages,
            model=judge_model,
            temperature=0.0,
            max_tokens=800,
            api_key=api_key,
            base_url=base_url,
        )
        # Strip markdown fences if judge returned them anyway
        clean = raw.strip()
        if clean.startswith("```"):
            clean = "\n".join(clean.split("\n")[1:])
            if clean.endswith("```"):
                clean = clean[: clean.rfind("```")]
        result = json.loads(clean)
        scores: dict[str, int] = result.get("scores", {})
        reasons: dict[str, str] = result.get("reasons", {})
        # Clamp to valid range
        for k, v in RUBRIC.items():
            scores[k] = max(0, min(int(scores.get(k, 0)), v["max"]))
        total = sum(scores.values())
        return {
            "scores": scores,
            "reasons": reasons,
            "total": total,
            "max": MAX_SCORE,
            "judge_model": judge_model,
            "judge_raw": raw,
        }
    except Exception as exc:
        return {
            "scores": {k: 0 for k in RUBRIC},
            "reasons": {k: f"judge error: {exc}" for k in RUBRIC},
            "total": 0,
            "max": MAX_SCORE,
            "judge_model": judge_model,
            "judge_raw": f"ERROR: {exc}",
        }


# ── KB context builder ──────────────────────────────────────────────────────────
def build_kb_context(playbooks: list[dict[str, Any]]) -> str:
    lines = ["=== BUSINESS LOGIC KNOWLEDGE BASE ===\n"]
    for pb in playbooks:
        lines.append(f"[{pb['playbook_id']}] {pb['title']}")
        lines.append(f"  Category: {pb['category']}")
        lines.append(f"  Business context: {pb['business_context'][:200]}")
        lines.append(f"  Intended rules: {'; '.join(pb['intended_rules'])}")
        lines.append(f"  Flawed assumptions: {'; '.join(pb['flawed_assumptions'])}")
        lines.append(f"  Preconditions: {'; '.join(pb['preconditions'])}")
        if pb.get("state_transitions"):
            lines.append(f"  State transitions: {'; '.join(pb['state_transitions'])}")
        lines.append(f"  Abuse sequence: {' → '.join(pb['abuse_sequence'])}")
        lines.append(f"  Missing controls: {'; '.join(pb['missing_controls'])}")
        lines.append(f"  False positive conditions: {'; '.join(pb['false_positive_conditions'])}")
        lines.append(f"  Remediation: {'; '.join(pb['remediation'])}")
        lines.append("")
    return "\n".join(lines)


# ── Main benchmark loop ─────────────────────────────────────────────────────────
def run_benchmark(
    *,
    model: str,
    judge_model: str,
    temperature: float,
    max_tokens: int,
    api_key: str,
    base_url: str,
    runs_per_condition: int,
    out_dir: Path,
) -> None:
    playbooks = load_jsonl(out_dir / "playbooks.jsonl")
    questions = load_jsonl(out_dir / "questions.jsonl")
    answer_key = {r["question_id"]: r for r in load_jsonl(out_dir / "answer_key.jsonl")}

    kb_context = build_kb_context(playbooks)
    run_id_base = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")

    print(f"Model: {model}  Judge: {judge_model}  Runs/condition: {runs_per_condition}")
    print(f"Questions: {len(questions)}  Playbooks: {len(playbooks)}\n")

    all_runs: list[dict[str, Any]] = []
    per_question: dict[str, dict[str, list[int]]] = {}

    for q in questions:
        qid = q["question_id"]
        per_question[qid] = {"baseline": [], "kb_assisted": []}
        prompt_base = f"{q['requirements']}\n\n```\n{q['source_code']}\n```"

        for condition in ("baseline", "kb_assisted"):
            user_content = (
                prompt_base
                if condition == "baseline"
                else f"{kb_context}\n\n{prompt_base}"
            )
            for run_num in range(1, runs_per_condition + 1):
                run_id = f"{run_id_base}-{qid}-{condition}-run{run_num}"
                print(f"  ▶ {run_id}")
                started = utc_now()
                response = ""
                resp_error: str | None = None
                try:
                    response = call_llm(
                        [
                            {"role": "system", "content": RESPONDER_SYSTEM},
                            {"role": "user", "content": user_content},
                        ],
                        model=model,
                        temperature=temperature,
                        max_tokens=max_tokens,
                        api_key=api_key,
                        base_url=base_url,
                    )
                except RuntimeError as exc:
                    resp_error = str(exc)
                    print(f"    RESPONDER ERROR: {resp_error}", file=sys.stderr)

                rubric: dict[str, Any]
                if resp_error or not response:
                    rubric = {
                        "scores": {k: 0 for k in RUBRIC},
                        "reasons": {k: "no response" for k in RUBRIC},
                        "total": 0,
                        "max": MAX_SCORE,
                        "judge_model": judge_model,
                        "judge_raw": "",
                    }
                else:
                    print(f"    ✓ response ({len(response)} chars) → judging…")
                    rubric = judge_response(
                        q,
                        answer_key.get(qid, {}),
                        response,
                        judge_model=judge_model,
                        temperature=temperature,
                        api_key=api_key,
                        base_url=base_url,
                    )
                    print(f"    ✓ judge score: {rubric['total']}/{MAX_SCORE}")

                all_runs.append({
                    "run_id": run_id,
                    "question_id": qid,
                    "condition": condition,
                    "run_number": run_num,
                    "model": model,
                    "judge_model": judge_model,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                    "started_at": started,
                    "finished_at": utc_now(),
                    "prompt_chars": len(user_content),
                    "response": response,
                    "responder_error": resp_error,
                    "rubric": rubric,
                })
                per_question[qid][condition].append(rubric["total"])
                time.sleep(0.5)

    # ── Write runs (Git LFS) ────────────────────────────────────────────────────
    runs_path = out_dir / "benchmark_runs.jsonl"
    with runs_path.open("w", encoding="utf-8", newline="\n") as f:
        for r in all_runs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"\n{len(all_runs)} runs → {runs_path}")

    # ── Summary ─────────────────────────────────────────────────────────────────
    def avg(lst: list[int]) -> float:
        return round(sum(lst) / len(lst), 2) if lst else 0.0

    questions_summary: dict[str, Any] = {}
    all_baseline: list[float] = []
    all_kb: list[float] = []

    for qid, cond in per_question.items():
        b = avg(cond["baseline"])
        k = avg(cond["kb_assisted"])
        q_title = next((q["title"] for q in questions if q["question_id"] == qid), qid)
        questions_summary[qid] = {
            "title": q_title,
            "baseline_avg": b,
            "kb_assisted_avg": k,
            "delta": round(k - b, 2),
        }
        all_baseline.append(b)
        all_kb.append(k)

    b_total = avg([int(x * 100) for x in all_baseline]) / 100
    k_total = avg([int(x * 100) for x in all_kb]) / 100

    summary: dict[str, Any] = {
        "generated_at": utc_now(),
        "model": model,
        "judge_model": judge_model,
        "temperature": temperature,
        "runs_per_condition": runs_per_condition,
        "max_score_per_question": MAX_SCORE,
        "rubric": {k: v["description"] for k, v in RUBRIC.items()},
        "questions": questions_summary,
        "aggregate": {
            "baseline_avg": b_total,
            "kb_assisted_avg": k_total,
            "delta": round(k_total - b_total, 2),
            "baseline_fp_count": sum(
                1 for r in all_runs
                if r["condition"] == "baseline"
                and r["rubric"]["scores"].get("no_hallucination", 1) == 0
            ),
            "kb_assisted_fp_count": sum(
                1 for r in all_runs
                if r["condition"] == "kb_assisted"
                and r["rubric"]["scores"].get("no_hallucination", 1) == 0
            ),
            "note": "LLM-as-Judge — phải được người thực hiện xem xét lại trước khi publish",
        },
    }

    summary_path = out_dir / "benchmark_summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Summary → {summary_path}")

    agg = summary["aggregate"]
    print(
        f"\n{'='*50}\n"
        f"  Baseline:    {agg['baseline_avg']:5.1f} / {MAX_SCORE}\n"
        f"  KB-assisted: {agg['kb_assisted_avg']:5.1f} / {MAX_SCORE}\n"
        f"  Delta:       {agg['delta']:+.1f}\n"
        f"  FP baseline: {agg['baseline_fp_count']}  FP KB: {agg['kb_assisted_fp_count']}\n"
        f"{'='*50}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark LLM không KB vs có KB — dùng LLM-as-Judge để chấm điểm."
    )
    parser.add_argument("--model", default=DEFAULT_RESPONDER_MODEL,
                        help=f"Model trả lời câu hỏi (mặc định: {DEFAULT_RESPONDER_MODEL})")
    parser.add_argument("--judge-model", default=DEFAULT_JUDGE_MODEL,
                        help=f"Model chấm điểm LLM-as-Judge (mặc định: {DEFAULT_JUDGE_MODEL})")
    parser.add_argument("--temperature", type=float, default=0.0,
                        help="Temperature cho cả responder và judge (mặc định: 0)")
    parser.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_TOKENS,
                        help=f"Max tokens cho response (mặc định: {DEFAULT_MAX_TOKENS})")
    parser.add_argument("--runs", type=int, default=1,
                        help="Số lần chạy mỗi câu mỗi condition (dùng 3 khi cần CI)")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL,
                        help=f"OpenAI-compatible API base URL (mặc định: {DEFAULT_BASE_URL})")
    parser.add_argument("--out-dir",
                        default=str(SAMPLE_DIR),
                        help="Thư mục chứa playbooks/questions/answer_key và output")
    args = parser.parse_args()

    # Nạp .env ở gốc repo (nếu có) trước khi đọc key
    load_dotenv(ROOT / ".env")

    # OpenCode Zen key; fallback OPENAI_API_KEY để tương thích ngược
    api_key = os.getenv("OPENCODE_API_KEY", "") or os.getenv("OPENAI_API_KEY", "")
    if not api_key:
        print(
            "ERROR: Cần đặt OPENCODE_API_KEY (qua file .env ở gốc repo hoặc export).\n"
            "  cp .env.example .env  &&  sửa OPENCODE_API_KEY trong .env\n"
            "  python3 scripts/run_business_logic_benchmark.py\n"
            f"  (mặc định: responder={DEFAULT_RESPONDER_MODEL}, judge={DEFAULT_JUDGE_MODEL}, "
            f"base-url={DEFAULT_BASE_URL})",
            file=sys.stderr,
        )
        sys.exit(1)

    run_benchmark(
        model=args.model,
        judge_model=args.judge_model,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
        api_key=api_key,
        base_url=args.base_url,
        runs_per_condition=args.runs,
        out_dir=Path(args.out_dir),
    )


if __name__ == "__main__":
    main()
