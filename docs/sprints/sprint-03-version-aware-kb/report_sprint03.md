# Sprint 03 — Version-aware Knowledge Base

**Thời điểm chạy:** `2026-08-03T09:32:21.832559+00:00`

## Mục lục

1. [Câu hỏi và kết luận thiết kế](#1-câu-hỏi-và-kết luận-thiết-kế)
2. [Kết quả crawl](#2-kết-quả-crawl)
3. [Phương pháp và lý do lựa chọn](#3-phương-pháp-và-lý-do-lựa-chọn)
4. [Kiểm chứng tiêu biểu](#4-kiểm-chứng-tiêu-biểu)
5. [Ý nghĩa đối với KB/RAG và giới hạn](#5-ý-nghĩa-đối-với-kbrag-và-giới-hạn)
6. [Definition of Done](#6-definition-of-done)
7. [Các bước tiếp theo](#7-các-bước-tiếp-theo)

---

## 1. Câu hỏi và kết luận thiết kế

**Câu hỏi mentor:** Làm thế nào crawl knowledge hiệu quả cho từng phiên bản library,
thử trước với Django và Apache Log4j?

**Kết luận:** Không tạo một file Markdown cho mỗi version. Dữ liệu máy đọc được lưu
thành bốn bảng JSONL liên kết bằng `library_id + ecosystem + package + version`:

| Bảng | Nội dung |
|---|---|
| `library_releases.jsonl` | Inventory phiên bản từ PyPI/Maven Central |
| `version_security_matrix.jsonl` | Kết quả OSV `querybatch` cho đúng từng exact version |
| `advisories.jsonl` | Nội dung advisory đầy đủ, affected ranges và references |
| `patch_diffs.jsonl` | Unified diff offline của commit upstream được advisory tham chiếu trực tiếp |

Markdown chỉ dùng cho research/report; JSONL dùng cho ingestion, filter và RAG.

**Schema chi tiết:** [version-kb-schema.md](version-kb-schema.md)  
**Hướng dẫn crawl/query:** [usage-guide.md](usage-guide.md)  
**Kế hoạch nghiên cứu:** [research-plan.md](research-plan.md)

---

## 2. Kết quả crawl

| Library | Ecosystem/package | Số phiên bản | Phiên bản có advisory |
|---|---|---:|---:|
| Django | `PyPI:Django` | 438 | 431 |
| Apache Log4j Core | `Maven:org.apache.logging.log4j:log4j-core` | 76 | 74 |

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

Số advisory snapshot giới hạn ở 40 bản ghi chi tiết; các ID còn lại vẫn có trong
matrix. Chạy lại với `--max-advisories 0` khi cần mở rộng.

Số version affected cao vì inventory gồm toàn bộ lịch sử release — đây không phải tỷ
lệ rủi ro của các bản đang được hỗ trợ.

**Cách đọc status:**

- `known_affected`: OSV trả advisory cho đúng package + version.
- `no_known_vulnerability`: không tìm thấy advisory đã biết; **không được hiểu là an
  toàn**.
- `query_error`: thiếu bằng chứng, không được tự suy diễn verdict.

---

## 3. Phương pháp và lý do lựa chọn

```text
PyPI/Maven → inventory release
OSV querybatch → advisory theo exact ecosystem/package/version
Upstream reference → patch chính thức được advisory dẫn trực tiếp
Snapshot + SHA-256 → bằng chứng dùng offline và có thể audit
```

Pipeline dùng package key canonical (`PyPI:Django` và
`Maven:org.apache.logging.log4j:log4j-core`), batch nhiều version trong một request,
lưu raw response và hash, sau đó xuất JSONL nhỏ để ingestion/RAG.

**Lý do hiệu quả:**

- Ưu tiên API/registry và OSV thay vì scrape HTML, ít phụ thuộc layout trang.
- `querybatch` giảm số request khi cần kiểm tra toàn bộ lịch sử release.
- Snapshot advisory/patch giúp KB vẫn truy vấn được khi URL upstream thay đổi hoặc chết.
- Exact version và canonical package key ngăn trộn dữ liệu giữa các release hoặc giữa
  `log4j-core` và artifact Log4j khác.
- Chỉ lấy patch có reference trực tiếp trong advisory; không tự đoán commit sửa lỗi.

---

## 4. Kiểm chứng tiêu biểu

| Library | Version | Kết quả mong đợi | Kết quả thực tế |
|---|---|---|---|
| Django | `5.2.1` | Có advisory đúng version | **Pass** — `known_affected`, 57 vulnerability IDs, 11 patch snapshot khớp |
| Log4j Core | `2.14.1` | Có Log4Shell (CVE-2021-44228) | **Pass** — `known_affected`, 7 IDs, gồm `GHSA-jfh8-c2jp-5v3q`, fixed `2.15.0/2.3.1/2.12.2` |
| Log4j Core | `2.17.1` | Không gán nhầm Log4Shell vào version đã vá | **Pass** — không có `GHSA-jfh8-c2jp-5v3q`; còn 3 advisory khác thuộc range khác |

Tái chạy kiểm chứng:

```powershell
python scripts/query_version_kb.py --library django --version 5.2.1
python scripts/query_version_kb.py --library log4j --version 2.14.1
python scripts/query_version_kb.py --library log4j --version 2.17.1
```

---

## 5. Ý nghĩa đối với KB/RAG và giới hạn

Luồng sử dụng: `SBOM/dependency → canonical package + version → version matrix →
advisory/fixed range → patch/evidence → verdict`.

Sprint 03 đã chứng minh phần release/advisory/patch theo version — đây là lớp tri thức
giúp V-LLM không verdict chỉ từ tên thư viện hoặc GHSA.

**Giới hạn hiện tại:** PoC chưa trích xuất đầy đủ symbol, source, sink, sanitizer,
guard, call path và điều kiện khai thác từ source diff. `known_affected` là tín hiệu
package-level, không phải kết luận code đang scan exploitable.

---

## 6. Definition of Done

- Có inventory thật từ PyPI và Maven Central.
- Mỗi version được query theo đúng ecosystem bằng OSV `querybatch`.
- Không gắn nhãn `safe` khi không có advisory.
- Advisory được snapshot nội dung, không chỉ lưu URL.
- Có patch diff upstream thật cho các advisory ưu tiên, không tự nhận patch từ fork.
- Raw response có hash và thời điểm crawl.
- Sample commit không chứa absolute path local.
- Unit test cũ và mới đều pass.

---

## 7. Các bước tiếp theo

PoC hiện giải quyết package/version/advisory. Giai đoạn kế tiếp cần tải source artifact
hoặc tag tương ứng để tạo `symbol_inventory` và `security_semantic_delta`:

- API/class/method xuất hiện hoặc biến mất giữa hai version.
- Source/sink/sanitizer nào thực sự tồn tại ở version đó.
- Patch thay đổi default/config/validation nào.
- Ánh xạ symbol bị sửa với CWE và điều kiện khai thác.

Các bước này phải là record có cấu trúc, không quay lại mô hình một `.md` cho mỗi
artifact. Sprint 04 nghiên cứu phương pháp enrich CVE thành technical knowledge để
lấp khoảng trống này.
