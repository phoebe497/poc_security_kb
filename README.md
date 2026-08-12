# Security Knowledge Base cho multi-agent SAST

Proof-of-concept xây dựng một **Knowledge Base (KB) có provenance** giúp V-LLM xác minh
lại các finding của công cụ SAST bằng bằng chứng lưu offline, qua đó **giảm false
positive**. Toàn bộ dữ liệu đều truy ngược được về nguồn gốc (advisory, patch, lab,
release…) nên kết quả có thể tái lập và kiểm chứng.

Dự án phát triển theo từng sprint. Mỗi sprint trả lời một câu hỏi nghiên cứu độc lập và
đi kèm code, dữ liệu mẫu và một báo cáo `report_sprintXX.md`.

## Tổng quan các sprint

| Sprint | Mục tiêu | Deliverable chính | Trạng thái |
|---|---|---|---|
| 01 — Foundation | KB/RAG cần tri thức gì để giảm false positive? | GHSA sample + báo cáo nền tảng | Hoàn thành |
| 02 — Evidence enrichment | Lấy patch diff, PoC, source/sink/sanitizer thế nào? | GitHub evidence, CodeQL model, patch sample | Hoàn thành |
| 03 — Version-aware KB | Một phiên bản Django/Log4j cụ thể có tri thức bảo mật gì? | Release inventory, exact-version security matrix, OSV snapshot | Hoàn thành |
| 04 — CVE enrichment | Bổ sung source/sink, precondition, PoC bằng cách nào? | Report so sánh phương pháp + đề xuất PoC | Hoàn thành |
| 05 — Business Logic KB | KB business logic có giúp LLM tìm bug tốt hơn không? | Playbook PortSwigger + rule nội bộ, bộ câu hỏi, benchmark có/không KB | Hoàn thành |

## Cấu trúc repo

```text
.
├── docs/                       # Tài liệu
│   ├── README.md               # Bản đồ tài liệu
│   ├── reference/              # Nguồn dữ liệu, layout repo
│   └── sprints/                # Báo cáo từng sprint (report_sprintXX.md)
├── schemas/                    # JSON schema cho các loại record trong KB
├── scripts/                    # Crawler, transform, benchmark
├── data/
│   ├── samples/                # Dataset nhỏ, được commit để review/tái lập
│   ├── raw/                    # Snapshot upstream đầy đủ (giữ local / Git LFS)
│   └── processed/              # Dataset sinh tự động (giữ local)
└── tests/                      # Unit test
```

Chi tiết vai trò từng thư mục: [docs/reference/repository-layout.md](docs/reference/repository-layout.md).

## Bắt đầu nhanh

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Các crawler chỉ tải text/JSON/patch để phân tích, **không** chạy PoC hay code tải về.

## Chạy các pipeline

### Sprint 03 — KB theo phiên bản (Django, Log4j)

```bash
python scripts/crawl_library_versions.py \
  --libraries django,log4j \
  --max-versions 0 \
  --max-advisories 40
```

Pipeline sẽ: lấy inventory release từ PyPI/Maven Central → query OSV `querybatch` cho
từng `ecosystem + package + version` → gán trạng thái (`known_affected`,
`no_known_vulnerability`, `query_error`) → tải snapshot advisory cho lỗ hổng ưu tiên →
lưu raw kèm SHA-256 và xuất sample không chứa absolute path.

Tra cứu nhanh một version sau khi crawl:

```bash
python scripts/query_version_kb.py --library django --version 5.2.1
python scripts/query_version_kb.py --library log4j --version 2.14.1
```

> `no_known_vulnerability` chỉ nghĩa là OSV không trả advisory đã biết tại thời điểm
> crawl — **không** được diễn giải thành `safe`.

### Sprint 01 & 02 — Advisory và evidence

```bash
python scripts/crawl_ghsa.py --limit 5
python scripts/crawl_github_evidence.py --limit 5 --max-github-artifacts 10
python scripts/crawl_codeql_models.py --languages python,java --max-files-per-language 25
python scripts/transform_to_kb.py
python scripts/export_samples.py
```

Có thể đặt `GITHUB_TOKEN` trong environment để tăng rate limit. Không ghi token vào
source, `.env` hay dataset.

### Sprint 05 — Business Logic KB và benchmark

```bash
# 1. Crawl PortSwigger và dựng playbook
python scripts/crawl_portswigger_logic.py
python scripts/transform_business_logic_kb.py --export-real

# 2. Benchmark LLM có KB vs không KB (LLM-as-Judge)
cp .env.example .env          # đặt OPENCODE_API_KEY trong .env
python scripts/run_business_logic_benchmark.py
```

Benchmark dùng OpenCode Zen (OpenAI-compatible); mặc định responder `glm-5.1`, judge
`gpt-5.6-luna`. Kết quả lưu tại `data/samples/sprint-05-business-logic-kb/`
(`benchmark_runs.jsonl`, `benchmark_summary.json`). Xem
[report_sprint05.md](docs/sprints/sprint-05-business-logic-kb/report_sprint05.md).

## Chính sách dữ liệu

| Loại | Commit? | Lý do |
|---|---|---|
| Code, test, docs, schema | Có | Tái lập và review được |
| `data/samples/` | Có | Nhỏ, đã loại đường dẫn local |
| `data/raw/` (HTML crawl) | Git LFS | Snapshot lớn, dùng LFS để không phình repo |
| `data/processed/` | Không | Sinh lại được, thay đổi giữa các lần crawl |
| Token, `.env`, virtualenv, cache | Không | Tránh lộ secret và file phụ thuộc máy |

Danh sách nguồn dữ liệu và mức độ tin cậy: [docs/reference/data-sources.md](docs/reference/data-sources.md).

## Tài liệu

- [Bản đồ tài liệu](docs/README.md)
- Báo cáo từng sprint: `docs/sprints/sprint-0X-*/report_sprint0X.md`
