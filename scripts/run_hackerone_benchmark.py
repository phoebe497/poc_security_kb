"""Benchmark KB trên bộ items-hackerone (dmk1en/business_flaws).

Mỗi item là một change-set code (Go/TS/Java) kèm gold answer (invariant,
patch_assertions có trọng số, patch_forbidden, known_benign). Ta cho một LLM
review code ở hai điều kiện:
  A — NO-KB:      chỉ context + files + ask
  B — KB-assisted: thêm toàn bộ playbook KB business logic vào context

Chấm điểm bằng LLM-as-Judge (model khác họ) theo rubric 10 điểm dựa trên gold:
  detected_required (4) + cwe_ok (1) + patch_quality (3) + precision_no_fp (2)

Tái dùng call_llm/load_dotenv/build_kb_context/DEFAULT_* từ
run_business_logic_benchmark.py. Cấu hình model/API qua .env (OPENCODE_API_KEY).

Chạy:
  cp .env.example .env    # đặt OPENCODE_API_KEY
  python3 scripts/run_hackerone_benchmark.py \
      --items-dir external/business_flaws/items-hackerone
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from run_business_logic_benchmark import (  # noqa: E402
    DEFAULT_BASE_URL,
    DEFAULT_JUDGE_MODEL,
    DEFAULT_MAX_TOKENS,
    DEFAULT_RESPONDER_MODEL,
    build_kb_context,
    call_llm,
    load_dotenv,
    utc_now,
)

SAMPLE_DIR = ROOT / "data" / "samples" / "sprint-05-business-logic-kb"
PLAYBOOKS = SAMPLE_DIR / "playbooks.jsonl"
DEFAULT_ITEMS_DIR = ROOT / "external" / "business_flaws" / "items-hackerone"
DEFAULT_OUT_DIR = SAMPLE_DIR / "hackerone"

RUBRIC = {
    "detected_required": {"max": 4, "desc": "Báo đúng finding required tại đúng file/symbol và nêu đúng invariant bị vi phạm"},
    "cwe_ok": {"max": 1, "desc": "CWE báo cáo nằm trong cwe_accept của gold"},
    "patch_quality": {"max": 3, "desc": "Patch thoả patch_assertions (có trọng số) và KHÔNG rơi vào patch_forbidden"},
    "precision_no_fp": {"max": 2, "desc": "Không gắn cờ known_benign thành lỗi; không bịa thêm finding ngoài n_expected_findings"},
}
MAX_SCORE = sum(v["max"] for v in RUBRIC.values())

RESPONDER_SYSTEM_SUFFIX = (
    "\n\nReturn ONLY a JSON object, no prose, no markdown fences. Shape:\n"
    '{"findings":[{"file":str,"symbol":str,"vuln_type":str,"cwe":"CWE-NNN",'
    '"why":str,"patch":str}], "kb_used":[playbook_id,...]}\n'
    'Use "kb_used" to list any KB playbook_id that informed a finding (empty list if none/no KB).'
)

JUDGE_SYSTEM = (
    "You are a strict security-review grader. You are given a code-review task, its gold "
    "answer (violated invariant, weighted patch assertions, forbidden patch shapes, and "
    "deliberately-benign patterns), and a candidate's findings JSON. Score the candidate "
    "against the rubric. Be objective: reward only substantiated detections and patches "
    "that match the assertions without matching a forbidden shape; penalise flagging "
    "known-benign patterns or inventing findings. Return ONLY JSON."
)

LANG_HINT = {"go": "go", "typescript": "ts", "java": "java", "python": "python"}


def load_items(items_dir: Path) -> list[dict[str, Any]]:
    items = []
    for f in sorted(items_dir.glob("*.yaml")):
        items.append(yaml.safe_load(f.read_text(encoding="utf-8")))
    return items


def render_files(item: dict[str, Any]) -> str:
    lang = LANG_HINT.get(item.get("lang", ""), "")
    out = []
    for fobj in item["prompt"].get("files", []):
        out.append(f"### File: {fobj['path']}\n```{lang}\n{fobj['code'].rstrip()}\n```")
    return "\n\n".join(out)


def build_responder_messages(item: dict[str, Any], kb_context: str | None) -> list[dict[str, str]]:
    system = item["prompt"]["system"].strip() + RESPONDER_SYSTEM_SUFFIX
    ask = item.get("ask", {})
    parts = []
    if kb_context:
        parts.append(kb_context)
        parts.append(
            "Use the knowledge base above only where it genuinely applies to the code below.\n"
        )
    parts.append(item["prompt"].get("context", "").strip())
    parts.append("\n" + render_files(item))
    parts.append(
        "\nTask: " + ask.get("instruction", "Report security defects you can substantiate.")
    )
    parts.append(
        f"There may be up to {item.get('n_expected_findings', 1)} genuine finding(s); "
        "report none if the code is sound."
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": "\n".join(parts)},
    ]


def extract_json(text: str) -> dict[str, Any]:
    t = text.strip()
    t = re.sub(r"^```(?:json)?\s*", "", t)
    t = re.sub(r"\s*```$", "", t)
    # grab outermost object
    start = t.find("{")
    end = t.rfind("}")
    if start != -1 and end != -1 and end > start:
        t = t[start : end + 1]
    try:
        return json.loads(t)
    except Exception:
        return {"findings": [], "kb_used": [], "_parse_error": True}


def build_judge_messages(item: dict[str, Any], responder_json: dict[str, Any]) -> list[dict[str, str]]:
    golds = item.get("gold", {}).get("findings", []) or []
    gold_view = []
    for g in golds:
        gold_view.append(
            {
                "file": g.get("file"),
                "symbol": g.get("symbol"),
                "required": g.get("required", True),
                "invariant": g.get("invariant"),
                "cwe_accept": g.get("cwe_accept", [g.get("cwe_primary")]),
                "patch_assertions": [
                    {"id": a.get("id"), "text": a.get("text"), "weight": a.get("weight", 1)}
                    for a in g.get("patch_assertions", [])
                ],
                "patch_forbidden": g.get("patch_forbidden", []),
            }
        )
    known_benign = [
        {"what": b.get("what"), "why": b.get("why")}
        for b in item.get("known_benign", []) or []
    ]
    payload = {
        "item_id": item.get("id"),
        "family": item.get("family"),
        "lang": item.get("lang"),
        "n_expected_findings": item.get("n_expected_findings", 1),
        "gold_findings": gold_view,
        "known_benign": known_benign,
        "candidate_findings": responder_json.get("findings", []),
    }
    rubric_desc = "\n".join(f"- {k} (0..{v['max']}): {v['desc']}" for k, v in RUBRIC.items())
    user = (
        "Grade the candidate against the gold. Rubric:\n"
        f"{rubric_desc}\n\n"
        "DATA (JSON):\n"
        f"{json.dumps(payload, ensure_ascii=False)}\n\n"
        'Return ONLY JSON: {"scores":{"detected_required":int,"cwe_ok":int,'
        '"patch_quality":int,"precision_no_fp":int},"reasons":{same keys: short string},'
        '"detected":bool,"had_false_positive":bool}'
    )
    return [
        {"role": "system", "content": JUDGE_SYSTEM},
        {"role": "user", "content": user},
    ]


def clamp(v: Any, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(round(float(v)))))
    except Exception:
        return lo


def judge_item(item, responder_json, *, judge_model, temperature, api_key, base_url):
    msgs = build_judge_messages(item, responder_json)
    raw = call_llm(msgs, model=judge_model, temperature=temperature,
                   max_tokens=1200, api_key=api_key, base_url=base_url)
    parsed = extract_json(raw)
    scores_in = parsed.get("scores", {})
    scores = {k: clamp(scores_in.get(k, 0), 0, v["max"]) for k, v in RUBRIC.items()}
    total = sum(scores.values())
    return {
        "scores": scores,
        "reasons": parsed.get("reasons", {}),
        "total": total,
        "max": MAX_SCORE,
        "detected": bool(parsed.get("detected", scores["detected_required"] >= 3)),
        "had_false_positive": bool(parsed.get("had_false_positive", scores["precision_no_fp"] < 2)),
        "judge_model": judge_model,
        "judge_raw": raw[:400],
    }


def run(args) -> None:
    load_dotenv(ROOT / ".env")
    api_key = os.getenv("OPENCODE_API_KEY", "") or os.getenv("OPENAI_API_KEY", "")
    if not api_key:
        print("ERROR: cần OPENCODE_API_KEY (đặt trong .env).", file=sys.stderr)
        sys.exit(1)

    items = load_items(Path(args.items_dir))
    if args.limit:
        items = items[: args.limit]
    playbooks = [json.loads(l) for l in PLAYBOOKS.read_text(encoding="utf-8").splitlines() if l.strip()]
    kb_context = build_kb_context(playbooks)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    conditions = ["baseline", "kb_assisted"]
    all_runs: list[dict[str, Any]] = []
    per_family: dict[str, dict[str, list[int]]] = {}
    coverage: list[dict[str, Any]] = []

    print(f"Model: {args.model}  Judge: {args.judge_model}  Items: {len(items)}")
    for item in items:
        iid = item["id"]
        fam = item.get("family", "unknown")
        per_family.setdefault(fam, {"baseline": [], "kb_assisted": []})
        item_scores: dict[str, int] = {}
        kb_used_all: list[str] = []
        for cond in conditions:
            started = utc_now()
            msgs = build_responder_messages(item, kb_context if cond == "kb_assisted" else None)
            print(f"  ▶ {iid} [{fam}] {cond} …", flush=True)
            resp_error = ""
            try:
                raw = call_llm(msgs, model=args.model, temperature=args.temperature,
                               max_tokens=args.max_tokens, api_key=api_key, base_url=args.base_url)
            except Exception as exc:
                raw, resp_error = "", str(exc)[:300]
            responder_json = extract_json(raw) if raw else {"findings": [], "kb_used": []}
            if cond == "kb_assisted":
                kb_used_all = [p for p in responder_json.get("kb_used", []) if isinstance(p, str)]

            if resp_error or not raw:
                rubric = {"scores": {k: 0 for k in RUBRIC}, "reasons": {}, "total": 0,
                          "max": MAX_SCORE, "detected": False, "had_false_positive": False,
                          "judge_model": args.judge_model, "judge_raw": ""}
            else:
                rubric = judge_item(item, responder_json, judge_model=args.judge_model,
                                    temperature=args.temperature, api_key=api_key, base_url=args.base_url)
            print(f"      → {rubric['total']}/{MAX_SCORE}"
                  f"{' (kb_used: ' + ','.join(kb_used_all) + ')' if cond=='kb_assisted' and kb_used_all else ''}")

            item_scores[cond] = rubric["total"]
            per_family[fam][cond].append(rubric["total"])
            all_runs.append({
                "run_id": f"{started.replace(':','').replace('-','')[:15]}-{iid}-{cond}",
                "item_id": iid, "family": fam, "lang": item.get("lang"),
                "condition": cond, "model": args.model, "judge_model": args.judge_model,
                "n_expected_findings": item.get("n_expected_findings"),
                "started_at": started, "finished_at": utc_now(),
                "responder_error": resp_error,
                "findings": responder_json.get("findings", []),
                "kb_used": responder_json.get("kb_used", []) if cond == "kb_assisted" else [],
                "rubric": rubric,
            })
            time.sleep(0.3)

        coverage.append({
            "item_id": iid, "family": fam, "lang": item.get("lang"),
            "baseline": item_scores.get("baseline", 0),
            "kb_assisted": item_scores.get("kb_assisted", 0),
            "delta": item_scores.get("kb_assisted", 0) - item_scores.get("baseline", 0),
            "kb_used": kb_used_all,
            "covered": bool(kb_used_all),
        })

    # write runs
    runs_path = out_dir / "benchmark_runs.jsonl"
    with runs_path.open("w", encoding="utf-8", newline="\n") as f:
        for r in all_runs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    def avg(xs: list[int]) -> float:
        return round(sum(xs) / len(xs), 2) if xs else 0.0

    fam_summary = {}
    for fam, cond in per_family.items():
        b, k = avg(cond["baseline"]), avg(cond["kb_assisted"])
        fam_summary[fam] = {"n": len(cond["baseline"]), "baseline_avg": b,
                            "kb_assisted_avg": k, "delta": round(k - b, 2)}

    all_b = [r["rubric"]["total"] for r in all_runs if r["condition"] == "baseline"]
    all_k = [r["rubric"]["total"] for r in all_runs if r["condition"] == "kb_assisted"]
    fp_b = sum(1 for r in all_runs if r["condition"] == "baseline" and r["rubric"]["had_false_positive"])
    fp_k = sum(1 for r in all_runs if r["condition"] == "kb_assisted" and r["rubric"]["had_false_positive"])

    summary = {
        "status": "completed",
        "generated_at": utc_now(),
        "source": "dmk1en/business_flaws — items-hackerone",
        "model": args.model, "judge_model": args.judge_model,
        "base_url": args.base_url, "temperature": args.temperature,
        "n_items": len(items), "max_score_per_item": MAX_SCORE,
        "rubric": {k: v["max"] for k, v in RUBRIC.items()},
        "aggregate": {
            "baseline_avg": avg(all_b), "kb_assisted_avg": avg(all_k),
            "delta": round(avg(all_k) - avg(all_b), 2),
            "baseline_fp_count": fp_b, "kb_assisted_fp_count": fp_k,
        },
        "by_family": fam_summary,
        "coverage_note": "kb_used = playbook_id model tự trích khi có KB; covered=false ⇒ gap.",
    }
    (out_dir / "benchmark_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "coverage.json").write_text(
        json.dumps(coverage, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\n{len(all_runs)} runs → {runs_path}")
    agg = summary["aggregate"]
    print(f"{'='*52}\n  Baseline:    {agg['baseline_avg']:5.2f}/{MAX_SCORE}\n"
          f"  KB-assisted: {agg['kb_assisted_avg']:5.2f}/{MAX_SCORE}\n"
          f"  Delta:       {agg['delta']:+.2f}\n"
          f"  FP baseline: {fp_b}  FP KB: {fp_k}\n{'='*52}")


def main() -> None:
    p = argparse.ArgumentParser(description="Benchmark KB trên bộ items-hackerone (NO-KB vs KB).")
    p.add_argument("--items-dir", default=str(DEFAULT_ITEMS_DIR))
    p.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR))
    p.add_argument("--model", default=DEFAULT_RESPONDER_MODEL)
    p.add_argument("--judge-model", default=DEFAULT_JUDGE_MODEL)
    p.add_argument("--base-url", default=DEFAULT_BASE_URL)
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_TOKENS)
    p.add_argument("--limit", type=int, default=0)
    run(p.parse_args())


if __name__ == "__main__":
    main()
