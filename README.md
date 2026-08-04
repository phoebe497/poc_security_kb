# Security Knowledge Base cho multi-agent SAST

PoC xây dựng Knowledge Base có provenance để V-LLM kiểm tra finding SAST bằng
bằng chứng lưu offline. Repo được chia theo sprint để mentor có thể đọc mục tiêu,
code, dữ liệu mẫu và report của từng giai đoạn độc lập.

## Mentor nên xem gì trước?

1. [Bản đồ tài liệu](docs/README.md).
2. [Sprint 3: KB theo phiên bản thư viện](docs/sprints/sprint-03-version-aware-kb/README.md).
3. [Mentor summary: phương pháp và kết quả kiểm chứng](docs/sprints/sprint-03-version-aware-kb/mentor-summary.md).
4. [Schema version-aware](docs/sprints/sprint-03-version-aware-kb/version-kb-schema.md).
5. [Cách dùng Django và Log4j](docs/sprints/sprint-03-version-aware-kb/usage-guide.md).
6. `data/samples/sprint-03-version-aware-kb/` để kiểm tra dữ liệu thật.
7. `scripts/crawl_library_versions.py` để kiểm tra cách tái lập kết quả.

## Các sprint

| Sprint | Câu hỏi cần trả lời | Deliverable chính | Trạng thái |
|---|---|---|---|
| 01 — Foundation | KB/RAG cần tri thức gì để giảm False Positive? | GHSA sample và báo cáo nền tảng | Hoàn thành |
| 02 — Evidence enrichment | Lấy patch diff, PoC, source/sink/sanitizer thế nào? | GitHub evidence, CodeQL model, patch sample | Hoàn thành |
| 03 — Version-aware KB | Một phiên bản Django/Log4j cụ thể có tri thức bảo mật gì? | Release inventory, exact-version security matrix, OSV snapshot | PoC đã triển khai |

## Cấu trúc repo

```text
.
├── README.md
├── docs/
│   ├── README.md
│   ├── reference/
│   └── sprints/
│       ├── sprint-01-foundation/
│       ├── sprint-02-evidence-enrichment/
│       └── sprint-03-version-aware-kb/
├── scripts/
│   ├── crawl_ghsa.py
│   ├── crawl_github_evidence.py
│   ├── crawl_codeql_models.py
│   ├── crawl_library_versions.py
│   ├── transform_to_kb.py
│   └── export_samples.py
├── data/
│   ├── samples/       # Dataset nhỏ được commit để mentor chấm
│   ├── raw/           # Snapshot đầy đủ, chỉ giữ local
│   └── processed/     # Dataset sinh tự động, chỉ giữ local
└── tests/
```

Chi tiết vai trò từng thư mục nằm tại
[repository-layout.md](docs/reference/repository-layout.md).

## Cài đặt và test

```powershell
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Crawler chỉ tải text/JSON/patch để phân tích, không chạy PoC hoặc code tải về.

## Chạy Sprint 3 — Django và Log4j

```powershell
python scripts/crawl_library_versions.py `
  --libraries django,log4j `
  --max-versions 0 `
  --max-advisories 40
```

Pipeline thực hiện:

1. Lấy inventory release Django từ PyPI và Log4j Core từ Maven Central.
2. Gửi các cặp `ecosystem + package + version` qua OSV `querybatch`.
3. Tạo trạng thái `known_affected`, `no_known_vulnerability` hoặc `query_error`.
4. Tải snapshot advisory đầy đủ cho các lỗ hổng ưu tiên.
5. Lưu raw response cùng SHA-256 ở local và xuất sample không chứa absolute path.

Tra cứu nhanh một version sau khi crawl:

```powershell
python scripts/query_version_kb.py --library django --version 5.2.1
python scripts/query_version_kb.py --library log4j --version 2.14.1
```

Output local đầy đủ:

```text
data/processed/version_kb/
├── library_releases.jsonl
├── version_security_matrix.jsonl
├── advisories.jsonl
├── patch_diffs.jsonl
└── manifest.json
```

Output nhỏ có thể push/chấm:

```text
data/samples/sprint-03-version-aware-kb/
├── library_releases.jsonl
├── version_security_matrix.jsonl
├── advisories.jsonl
├── patch_diffs.jsonl
└── manifest.json
```

`no_known_vulnerability` chỉ có nghĩa là OSV không trả advisory đã biết tại thời
điểm crawl; tuyệt đối không được đổi nhãn này thành `safe`.

## Chạy lại Sprint 1 và Sprint 2

```powershell
python scripts/crawl_ghsa.py --limit 5
python scripts/crawl_github_evidence.py --limit 5 --max-github-artifacts 10
python scripts/crawl_codeql_models.py --languages python,java --max-files-per-language 25
python scripts/transform_to_kb.py
python scripts/export_samples.py
```

Có thể đặt `GITHUB_TOKEN` trong environment để tăng rate limit. Không ghi token
vào source, `.env` hoặc dataset.

## Chính sách dữ liệu

| Loại | Có commit? | Lý do |
|---|---|---|
| Code, test, docs, schema | Có | Tái lập và review được |
| `data/samples/` | Có | Nhỏ, đã loại đường dẫn local, đủ để mentor chấm |
| `data/raw/` | Không | Có thể rất lớn và chứa snapshot upstream |
| `data/processed/` | Không | Sinh lại được, thay đổi nhiều giữa các lần crawl |
| Tài liệu mentor nội bộ | Không | Chỉ dùng đối chiếu local |
| Token, virtualenv, cache | Không | Tránh lộ secret và file phụ thuộc máy |

Danh sách nguồn và mức độ tin cậy được mô tả tại
[data-sources.md](docs/reference/data-sources.md).
