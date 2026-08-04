# Mentor summary — PoC crawl knowledge theo library version

## 1. Yêu cầu

Mentor yêu cầu tìm cách crawl knowledge theo **library và exact version**, thử trước
với Django và Apache Log4j, để V-LLM có thể đối chiếu dependency trong code với advisory,
phiên bản đã vá và patch chính thức thay vì chỉ dựa vào mã GHSA hoặc một URL sống.

## 2. Cách tiếp cận đã triển khai

```text
PyPI/Maven → inventory release
OSV querybatch → advisory theo exact ecosystem/package/version
Upstream reference → patch chính thức được advisory dẫn trực tiếp
Snapshot + SHA-256 → bằng chứng dùng offline và có thể audit
```

Pipeline dùng package key canonical (`PyPI:Django` và
`Maven:org.apache.logging.log4j:log4j-core`), batch nhiều version trong một request,
lưu raw response và hash, sau đó xuất JSONL nhỏ để ingestion/RAG.

## 3. Vì sao cách này hiệu quả

- Ưu tiên API/registry và OSV thay vì scrape HTML, nên ít phụ thuộc layout trang.
- `querybatch` giảm số request khi cần kiểm tra toàn bộ lịch sử release.
- Snapshot advisory/patch giúp KB vẫn truy vấn được khi URL upstream thay đổi hoặc chết.
- Exact version và canonical package key ngăn trộn dữ liệu giữa các release hoặc giữa
  `log4j-core` và artifact Log4j khác.
- Chỉ lấy patch có reference trực tiếp trong advisory; không tự đoán commit sửa lỗi.

## 4. Kết quả crawl thật

| Chỉ số | Kết quả |
|---|---:|
| Django releases | 438 |
| Log4j Core releases | 76 |
| Version matrix records | 514 |
| Version có ít nhất một advisory | 505 |
| Vulnerability ID duy nhất | 317 |
| Advisory snapshot chi tiết | 40 |
| Patch diff upstream | 20 (19 Django, 1 Log4j) |
| Crawl errors | 0 |

Dataset kiểm chứng nằm tại `data/samples/sprint-03-version-aware-kb/`:

- `library_releases.jsonl`: inventory release từ PyPI/Maven Central.
- `version_security_matrix.jsonl`: status và advisory ID cho từng exact version.
- `advisories.jsonl`: summary/details, affected ranges, fixed versions và references.
- `patch_diffs.jsonl`: diff upstream snapshot có commit SHA và hash.
- `manifest.json`: nguồn, thời điểm, thống kê, hash và semantics.

## 5. Kiểm chứng tiêu biểu

| Library | Version | Kết quả mong đợi | Kết quả thực tế |
|---|---|---|---|
| Django | `5.2.1` | Có advisory đúng version | **Pass** — `known_affected`, 57 vulnerability IDs, 11 patch snapshot khớp |
| Log4j Core | `2.14.1` | Có Log4Shell (CVE-2021-44228) | **Pass** — `known_affected`, 7 IDs, gồm `GHSA-jfh8-c2jp-5v3q`, fixed `2.15.0/2.3.1/2.12.2` |
| Log4j Core | `2.17.1` | Không gán nhầm Log4Shell vào version đã vá | **Pass** — không có `GHSA-jfh8-c2jp-5v3q`; còn 3 advisory khác thuộc các lỗi/range khác |

Có thể tái chạy:

```powershell
python scripts/query_version_kb.py --library django --version 5.2.1
python scripts/query_version_kb.py --library log4j --version 2.14.1
python scripts/query_version_kb.py --library log4j --version 2.17.1
```

## 6. Ý nghĩa đối với KB/RAG và giới hạn

Luồng sử dụng là `SBOM/dependency → canonical package + version → version matrix →
advisory/fixed range → patch/evidence → verdict`. Sprint 03 đã chứng minh phần
release/advisory/patch theo version; đây là lớp tri thức giúp V-LLM không verdict chỉ
từ tên thư viện hoặc GHSA.

PoC chưa trích xuất đầy đủ symbol, source, sink, sanitizer, guard, call path và điều
kiện khai thác từ source diff. `known_affected` là tín hiệu package-level, không phải
kết luận code đang scan exploitable. Snapshot advisory hiện giới hạn 40 bản ghi chi
tiết (các ID còn lại vẫn có trong matrix); có thể chạy lại với `--max-advisories 0`
khi cần mở rộng.

Sprint 04 (đang để `draft`) là hướng tiếp theo: nối version/advisory/patch với symbol,
source/sink/sanitizer/guard, release notes và điều kiện khai thác để tạo evidence-level
verdict.

