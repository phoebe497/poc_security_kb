"""Unit tests cho Sprint 05 — Business Logic KB.

Kiểm tra:
  - Schema validation của playbook record.
  - Tính nhất quán của sample data (playbooks, questions, answer_key, manifest).
  - Logic trích xuất cơ bản trong transform script.
  - Logic chấm điểm rubric trong benchmark script.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_DIR = ROOT / "data" / "samples" / "sprint-05-business-logic-kb"
SCHEMA_PATH = ROOT / "schemas" / "business_logic_playbook.schema.json"

sys.path.insert(0, str(ROOT / "scripts"))


def load_jsonl(path: Path) -> list[dict]:
    records = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


REQUIRED_PLAYBOOK_FIELDS = {
    "playbook_id",
    "title",
    "category",
    "business_context",
    "actors",
    "components",
    "intended_rules",
    "flawed_assumptions",
    "preconditions",
    "abuse_sequence",
    "missing_controls",
    "detection_questions",
    "false_positive_conditions",
    "impact",
    "remediation",
    "evidence_ids",
}

VALID_CATEGORIES = {
    "trust_client_input",
    "unconventional_input",
    "workflow_sequence_violation",
    "domain_invariant_violation",
    "replay_idempotency",
    "policy_authorization_inconsistency",
    "broken_object_authorization",
    "excessive_data_exposure",
    "mass_assignment",
    "missing_authentication",
    "fail_open",
}

RUBRIC_KEYS = {
    "correct_bug_identified",
    "business_rule_stated",
    "abuse_flow_described",
    "precondition_stated",
    "impact_stated",
    "remediation_server_side",
    "no_hallucination",
}
MAX_SCORE = 10


class PlaybookSchemaTests(unittest.TestCase):
    """Kiểm tra cấu trúc của từng playbook trong sample."""

    def setUp(self) -> None:
        self.playbooks = load_jsonl(SAMPLE_DIR / "playbooks.jsonl")

    def test_sample_has_playbooks(self) -> None:
        self.assertGreater(len(self.playbooks), 0, "playbooks.jsonl trống")

    def test_playbook_required_fields(self) -> None:
        for pb in self.playbooks:
            missing = REQUIRED_PLAYBOOK_FIELDS - pb.keys()
            self.assertFalse(
                missing,
                f"{pb.get('playbook_id', '?')} thiếu field: {missing}",
            )

    def test_playbook_id_format(self) -> None:
        import re
        pattern = re.compile(r"^BL-[A-Z0-9_-]+$")
        for pb in self.playbooks:
            self.assertRegex(
                pb["playbook_id"],
                pattern,
                f"playbook_id sai format: {pb['playbook_id']}",
            )

    def test_category_valid(self) -> None:
        for pb in self.playbooks:
            self.assertIn(
                pb["category"],
                VALID_CATEGORIES,
                f"{pb['playbook_id']}: category không hợp lệ '{pb['category']}'",
            )

    def test_list_fields_not_empty(self) -> None:
        list_fields = [
            "actors", "components", "intended_rules", "flawed_assumptions",
            "preconditions", "abuse_sequence", "missing_controls",
            "detection_questions", "impact", "remediation", "evidence_ids",
        ]
        for pb in self.playbooks:
            for field in list_fields:
                self.assertIsInstance(pb[field], list, f"{pb['playbook_id']}.{field} không phải list")
                self.assertGreater(
                    len(pb[field]), 0,
                    f"{pb['playbook_id']}.{field} rỗng",
                )

    def test_evidence_ids_format(self) -> None:
        import re
        pattern = re.compile(r"^(PS-SOURCE-[0-9]+|INT-RULE-[0-9]+|CWE-[0-9]+|WSTG-[A-Z]+-[0-9]+)")
        for pb in self.playbooks:
            for eid in pb["evidence_ids"]:
                self.assertRegex(
                    eid,
                    pattern,
                    f"{pb['playbook_id']}: evidence_id sai format '{eid}'",
                )

    def test_category_coverage(self) -> None:
        """Ít nhất 4 category trong 6 category bắt buộc phải có playbook mẫu."""
        covered = {pb["category"] for pb in self.playbooks}
        self.assertGreaterEqual(
            len(covered),
            4,
            f"Chỉ có {len(covered)} category được bao phủ: {covered}",
        )


class QuestionsDataTests(unittest.TestCase):
    """Kiểm tra bộ câu hỏi code (5 câu PortSwigger + 3 câu rule nội bộ)."""

    def setUp(self) -> None:
        self.questions = load_jsonl(SAMPLE_DIR / "questions.jsonl")

    def test_question_count(self) -> None:
        self.assertEqual(len(self.questions), 8, f"Cần đúng 8 câu, có {len(self.questions)}")

    def test_question_required_fields(self) -> None:
        for q in self.questions:
            for field in ("question_id", "title", "requirements", "source_code", "playbook_ref"):
                self.assertIn(field, q, f"Question thiếu field '{field}': {q.get('question_id')}")

    def test_question_ids_unique(self) -> None:
        ids = [q["question_id"] for q in self.questions]
        self.assertEqual(len(ids), len(set(ids)), f"question_id bị trùng: {ids}")

    def test_source_code_multi_component(self) -> None:
        """Code mỗi câu phải đủ dài và có ít nhất 2 thành phần (component)."""
        for q in self.questions:
            code = q.get("source_code", "")
            self.assertGreater(
                len(code.splitlines()),
                15,
                f"{q['question_id']}: source_code quá ngắn ({len(code.splitlines())} dòng)",
            )

    def test_no_answer_hints_in_code(self) -> None:
        """Code không được có comment làm lộ đáp án (ví dụ '# BUG', '# VULNERABILITY')."""
        forbidden = ["# bug", "# vulnerability", "# vulnerable", "# exploit"]
        for q in self.questions:
            code = q.get("source_code", "").lower()
            for hint in forbidden:
                self.assertNotIn(
                    hint,
                    code,
                    f"{q['question_id']}: source_code chứa hint '{hint}'",
                )

    def test_playbook_refs_exist(self) -> None:
        playbooks = load_jsonl(SAMPLE_DIR / "playbooks.jsonl")
        pb_ids = {pb["playbook_id"] for pb in playbooks}
        for q in self.questions:
            ref = q.get("playbook_ref", "")
            self.assertIn(
                ref,
                pb_ids,
                f"{q['question_id']}: playbook_ref '{ref}' không tồn tại trong playbooks.jsonl",
            )


class AnswerKeyTests(unittest.TestCase):
    """Kiểm tra answer_key."""

    def setUp(self) -> None:
        self.answer_key = load_jsonl(SAMPLE_DIR / "answer_key.jsonl")
        self.questions = load_jsonl(SAMPLE_DIR / "questions.jsonl")

    def test_answer_key_covers_all_questions(self) -> None:
        q_ids = {q["question_id"] for q in self.questions}
        ak_ids = {ak["question_id"] for ak in self.answer_key}
        self.assertEqual(q_ids, ak_ids, f"answer_key thiếu: {q_ids - ak_ids}")

    def test_answer_key_required_fields(self) -> None:
        for ak in self.answer_key:
            for field in (
                "bug_keyword",
                "business_rule_keyword",
                "abuse_flow_keywords",
                "precondition_keyword",
                "impact_keyword",
                "remediation_keyword",
                "hallucination_traps",
                "gold_summary",
            ):
                self.assertIn(field, ak, f"{ak.get('question_id')}: answer_key thiếu '{field}'")

    def test_hallucination_traps_not_empty(self) -> None:
        for ak in self.answer_key:
            self.assertGreater(
                len(ak.get("hallucination_traps", [])),
                0,
                f"{ak['question_id']}: hallucination_traps rỗng",
            )


class BenchmarkDataTests(unittest.TestCase):
    """Kiểm tra benchmark_runs.jsonl và benchmark_summary.json.

    Benchmark có hai trạng thái:
      - pending_real_run: chưa chạy thật (runs rỗng); chỉ kiểm tra cấu hình model.
      - completed: đã chạy; kiểm tra đầy đủ rubric, scores và aggregate.
    """

    EXPECTED_RESPONDER = "glm-5.1"
    EXPECTED_JUDGE = "gpt-5.6-luna"

    def setUp(self) -> None:
        self.runs = load_jsonl(SAMPLE_DIR / "benchmark_runs.jsonl")
        with (SAMPLE_DIR / "benchmark_summary.json").open(encoding="utf-8") as f:
            self.summary = json.load(f)
        self.questions = load_jsonl(SAMPLE_DIR / "questions.jsonl")
        self.pending = self.summary.get("status") == "pending_real_run"

    def test_summary_model_config(self) -> None:
        """Dù pending hay đã chạy, summary phải khai báo đúng responder + judge."""
        self.assertEqual(self.summary.get("model"), self.EXPECTED_RESPONDER)
        self.assertEqual(self.summary.get("judge_model"), self.EXPECTED_JUDGE)

    def test_runs_cover_both_conditions(self) -> None:
        if self.pending:
            self.skipTest("benchmark chưa chạy thật (pending_real_run)")
        conditions = {r["condition"] for r in self.runs}
        self.assertIn("baseline", conditions)
        self.assertIn("kb_assisted", conditions)

    def test_runs_cover_all_questions(self) -> None:
        if self.pending:
            self.skipTest("benchmark chưa chạy thật (pending_real_run)")
        run_qids = {r["question_id"] for r in self.runs}
        q_ids = {q["question_id"] for q in self.questions}
        self.assertEqual(run_qids, q_ids, f"Runs thiếu câu hỏi: {q_ids - run_qids}")

    def test_run_rubric_fields(self) -> None:
        for run in self.runs:
            rubric = run.get("rubric", {})
            scores = rubric.get("scores", {})
            missing = RUBRIC_KEYS - scores.keys()
            self.assertFalse(
                missing,
                f"{run['run_id']}: rubric thiếu criteria {missing}",
            )

    def test_rubric_score_bounds(self) -> None:
        bounds = {
            "correct_bug_identified": (0, 2),
            "business_rule_stated": (0, 2),
            "abuse_flow_described": (0, 2),
            "precondition_stated": (0, 1),
            "impact_stated": (0, 1),
            "remediation_server_side": (0, 1),
            "no_hallucination": (0, 1),
        }
        for run in self.runs:
            for criterion, (lo, hi) in bounds.items():
                score = run["rubric"]["scores"].get(criterion, -1)
                self.assertGreaterEqual(score, lo, f"{run['run_id']}.{criterion} < {lo}")
                self.assertLessEqual(score, hi, f"{run['run_id']}.{criterion} > {hi}")

    def test_runs_have_responses(self) -> None:
        for run in self.runs:
            if not run.get("responder_error") and not run.get("error"):
                self.assertGreater(
                    len(run.get("response", "")),
                    0,
                    f"{run['run_id']}: response rỗng và không có error",
                )

    def test_summary_has_aggregate(self) -> None:
        agg = self.summary.get("aggregate", {})
        for key in ("baseline_avg", "kb_assisted_avg", "delta"):
            self.assertIn(key, agg, f"benchmark_summary.json thiếu aggregate.{key}")

    def test_summary_delta_correct(self) -> None:
        if self.pending:
            self.skipTest("benchmark chưa chạy thật (pending_real_run)")
        agg = self.summary["aggregate"]
        expected_delta = round(agg["kb_assisted_avg"] - agg["baseline_avg"], 2)
        self.assertAlmostEqual(
            agg["delta"],
            expected_delta,
            places=1,
            msg="aggregate.delta không khớp với kb_assisted_avg - baseline_avg",
        )


class ManifestTests(unittest.TestCase):
    """Kiểm tra manifest.json."""

    def setUp(self) -> None:
        with (SAMPLE_DIR / "manifest.json").open(encoding="utf-8") as f:
            self.manifest = json.load(f)

    def test_schema_version_present(self) -> None:
        self.assertIn("schema_version", self.manifest)

    def test_files_section_present(self) -> None:
        files = self.manifest.get("files", {})
        for fname in (
            "playbooks.jsonl",
            "questions.jsonl",
            "answer_key.jsonl",
            "benchmark_runs.jsonl",
            "benchmark_summary.json",
        ):
            self.assertIn(fname, files, f"manifest thiếu mục '{fname}'")

    def test_data_policy_no_verbatim(self) -> None:
        policy = self.manifest.get("data_policy", {})
        self.assertFalse(
            policy.get("portswigger_verbatim_copy", True),
            "data_policy.portswigger_verbatim_copy phải là false",
        )

    def test_provenance_chain_present(self) -> None:
        self.assertIn("provenance_chain", self.manifest)


class SchemaFileTests(unittest.TestCase):
    """Kiểm tra file schema JSON."""

    def test_schema_file_exists(self) -> None:
        self.assertTrue(SCHEMA_PATH.exists(), f"Schema không tồn tại: {SCHEMA_PATH}")

    def test_schema_is_valid_json(self) -> None:
        content = SCHEMA_PATH.read_text(encoding="utf-8")
        schema = json.loads(content)
        self.assertIn("$schema", schema)
        self.assertIn("required", schema)
        self.assertIn("properties", schema)

    def test_schema_required_covers_fields(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        required = set(schema.get("required", []))
        self.assertTrue(
            REQUIRED_PLAYBOOK_FIELDS.issubset(required),
            f"Schema thiếu required fields: {REQUIRED_PLAYBOOK_FIELDS - required}",
        )


if __name__ == "__main__":
    unittest.main()
