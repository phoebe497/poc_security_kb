from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


class GeneratedKnowledgeBaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        manifest = ROOT / "data" / "processed" / "knowledge_base" / "manifest.json"
        if not manifest.exists():
            raise unittest.SkipTest("Chưa chạy transform_to_kb.py")
        cls.records = [
            json.loads(line)
            for line in (
                ROOT
                / "data"
                / "processed"
                / "knowledge_base"
                / "knowledge_base.jsonl"
            )
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip()
        ]

    def test_sample_json_shape_is_preserved(self) -> None:
        required = {
            "id",
            "title",
            "category",
            "tags",
            "severity",
            "content",
            "references",
            "source_type",
            "source_url",
            "crawled_at",
        }
        self.assertGreater(len(self.records), 0)
        for record in self.records[:3]:
            self.assertTrue(required.issubset(record))
            self.assertIsInstance(record["content"], str)

    def test_markdown_frontmatter_contains_only_schema_fields(self) -> None:
        entry = next(
            (ROOT / "data" / "processed" / "knowledge_base" / "entries").glob("*.md")
        )
        text = entry.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("---\n"))
        _, frontmatter, _ = text.split("---", 2)
        value = yaml.safe_load(frontmatter)
        for field in (
            "id",
            "source_type",
            "title",
            "summary",
            "summary_vi",
            "file_path",
            "severity",
        ):
            self.assertIn(field, value)
        self.assertNotIn("content", value)


if __name__ == "__main__":
    unittest.main()
