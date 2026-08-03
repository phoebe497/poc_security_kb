from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from crawl_library_versions import (  # noqa: E402
    LIBRARIES,
    crawl_osv_matrix,
    crawl_pypi,
    sanitize_for_committed_sample,
)
from query_version_kb import fixed_versions  # noqa: E402


class FakeClient:
    def __init__(self) -> None:
        self.last_payload: dict[str, Any] | None = None

    def get_bytes(self, url: str, **_: Any) -> tuple[bytes, dict[str, str]]:
        payload = {
            "releases": {
                "1.0": [
                    {
                        "filename": "Django-1.0.tar.gz",
                        "packagetype": "sdist",
                        "url": "https://files.example/Django-1.0.tar.gz",
                        "size": 12,
                        "digests": {"sha256": "abc"},
                        "upload_time_iso_8601": "2008-09-03T00:00:00Z",
                        "yanked": False,
                        "yanked_reason": None,
                    }
                ]
            }
        }
        return json.dumps(payload).encode(), {"final_url": url}

    def post_json(
        self,
        url: str,
        payload: dict[str, Any],
        **_: Any,
    ) -> tuple[dict[str, Any], bytes, dict[str, str]]:
        self.last_payload = payload
        response = {
            "results": [
                {"vulns": [{"id": "GHSA-test"}]},
            ]
        }
        raw = json.dumps(response).encode()
        return response, raw, {"final_url": url}


class LibraryVersionCrawlerTests(unittest.TestCase):
    def test_pypi_release_inventory_preserves_artifact_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            records, _ = crawl_pypi(
                FakeClient(),
                LIBRARIES["django"],
                Path(directory),
            )
        self.assertEqual(records[0]["version"], "1.0")
        self.assertEqual(records[0]["artifacts"][0]["sha256"], "abc")
        self.assertEqual(records[0]["package"]["ecosystem"], "PyPI")

    def test_osv_query_uses_exact_ecosystem_package_and_version(self) -> None:
        client = FakeClient()
        releases = [
            {
                "version": "1.0",
                "published_at": None,
                "package": {
                    "ecosystem": "PyPI",
                    "name": "Django",
                    "purl": "pkg:pypi/django",
                },
            }
        ]
        with tempfile.TemporaryDirectory() as directory:
            matrix, counts, _, errors = crawl_osv_matrix(
                client,
                LIBRARIES["django"],
                releases,
                Path(directory),
                100,
            )
        assert client.last_payload is not None
        query = client.last_payload["queries"][0]
        self.assertEqual(query["version"], "1.0")
        self.assertEqual(query["package"], {"ecosystem": "PyPI", "name": "Django"})
        self.assertEqual(matrix[0]["status"], "known_affected")
        self.assertEqual(counts["GHSA-test"], 1)
        self.assertEqual(errors, [])

    def test_committed_sample_replaces_absolute_raw_path(self) -> None:
        root = Path("C:/workspace/project")
        value = {"source": {"raw_path": "C:/workspace/project/data/raw/a.json"}}
        sanitized = sanitize_for_committed_sample(value, root)
        self.assertNotIn("raw_path", sanitized["source"])
        self.assertEqual(sanitized["source"]["raw_artifact"], "data/raw/a.json")

    def test_fixed_versions_are_filtered_by_library_package(self) -> None:
        advisory = {
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "django"},
                    "ranges": [
                        {"events": [{"introduced": "0"}, {"fixed": "5.2.8"}]}
                    ],
                },
                {
                    "package": {"ecosystem": "Maven", "name": "other:package"},
                    "ranges": [{"events": [{"fixed": "99.0"}]}],
                },
            ]
        }
        self.assertEqual(fixed_versions(advisory, "django"), ["5.2.8"])


if __name__ == "__main__":
    unittest.main()
