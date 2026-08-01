from __future__ import annotations

import sys
import urllib.error
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from crawl_codeql_models import (
    extract_documentation_model_examples,
    normalize_rows,
)
from kb_common import HttpClient, extract_poc_sections, parse_github_reference


class GitHubReferenceTests(unittest.TestCase):
    def test_parse_commit(self) -> None:
        value = parse_github_reference(
            "https://github.com/example/project/commit/abcdef1234"
        )
        self.assertIsNotNone(value)
        assert value is not None
        self.assertEqual(value.owner, "example")
        self.assertEqual(value.repo, "project")
        self.assertEqual(value.kind, "commit")
        self.assertEqual(value.identifier, "abcdef1234")

    def test_non_github_url_is_ignored(self) -> None:
        self.assertIsNone(parse_github_reference("https://example.com/a"))

    def test_patch_suffix_is_normalized(self) -> None:
        value = parse_github_reference(
            "https://github.com/example/project/commit/abcdef.patch"
        )
        self.assertIsNotNone(value)
        assert value is not None
        self.assertEqual(value.identifier, "abcdef")


class PocExtractionTests(unittest.TestCase):
    def test_extract_poc_section_only(self) -> None:
        text = """# Summary
Text.

## Proof of Concept
```python
print("do not execute")
```

## Impact
Impact text.
"""
        sections = extract_poc_sections(text)
        self.assertEqual(len(sections), 1)
        self.assertEqual(sections[0]["title"], "Proof of Concept")
        self.assertIn("do not execute", sections[0]["body"])
        self.assertNotIn("Impact text", sections[0]["body"])
        self.assertTrue(sections[0]["body"].startswith("\n"))


class HttpClientTests(unittest.TestCase):
    def test_dead_url_is_bounded_error(self) -> None:
        error = urllib.error.HTTPError(
            "https://example.test/dead",
            404,
            "not found",
            {},
            None,
        )
        with patch("urllib.request.urlopen", side_effect=error):
            with self.assertRaises(RuntimeError):
                HttpClient(retries=0).get_bytes("https://example.test/dead")


class CodeqlNormalizationTests(unittest.TestCase):
    def test_malformed_model_root_is_skipped_as_runtime_error(self) -> None:
        with self.assertRaises(RuntimeError):
            normalize_rows(
                language="python",
                file_info={"name": "bad.model.yml"},
                yaml_value=["not", "a", "mapping"],
                raw_path=Path("raw/bad.model.yml"),
                raw_bytes=b"[]",
                response_metadata={},
            )

    def test_extract_official_documentation_barrier_yaml(self) -> None:
        rst = """
.. code-block:: yaml

  extensions:
    - addsTo:
        pack: codeql/javascript-all
        extensible: barrierModel
      data:
        - ["global", "Member[encode].ReturnValue", "html-injection"]
        """
        examples = extract_documentation_model_examples(rst)
        self.assertEqual(len(examples), 1)
        extension = examples[0]["yaml_value"]["extensions"][0]
        self.assertEqual(
            extension["addsTo"]["extensible"], "barrierModel"
        )

    def test_barrier_is_mapped_without_losing_predicate(self) -> None:
        yaml_value = {
            "extensions": [
                {
                    "addsTo": {
                        "pack": "codeql/python-all",
                        "extensible": "barrierModel",
                    },
                    "data": [["pkg.Type", "Member[clean]", "sql-injection"]],
                }
            ]
        }
        rows = normalize_rows(
            language="python",
            file_info={
                "name": "pkg.model.yml",
                "sha": "123",
                "html_url": "https://github.com/github/codeql",
                "download_url": "https://raw.githubusercontent.com/a",
            },
            yaml_value=yaml_value,
            raw_path=Path("raw/pkg.model.yml"),
            raw_bytes=b"test",
            response_metadata={},
        )
        self.assertEqual(rows[0]["model_group"], "sanitizer_or_barrier")
        self.assertEqual(rows[0]["codeql_predicate"], "barrierModel")
        self.assertTrue(rows[0]["semantics"]["is_sanitizer_or_barrier"])


if __name__ == "__main__":
    unittest.main()
