# Schema KB theo phiên bản thư viện

Schema này là hợp đồng dữ liệu cho pipeline version-aware. Khóa nối chính là
`library_id + ecosystem + package + version`; không dùng URL làm bằng chứng duy nhất.

## 1. `library_releases.jsonl`

Mỗi dòng là một release lấy từ package registry.

| Trường | Kiểu | Ý nghĩa |
|---|---|---|
| `library_id` | string | Tên ổn định trong KB, ví dụ `django`, `log4j` |
| `package` | object | `{ecosystem, name, purl}` là package key canonical |
| `version` | string | Phiên bản chuẩn hóa để query |
| `published_at` | string/null | Thời điểm phát hành nếu registry cung cấp |
| `source` | object | URL, thời điểm lấy, hash và đường dẫn raw artifact |

## 2. `version_security_matrix.jsonl`

Mỗi dòng là kết quả kiểm tra **một exact version** qua OSV `querybatch`.

| Trường | Kiểu | Ý nghĩa |
|---|---|---|
| `library_id` | string | Tên ổn định trong KB |
| `package` | object | `{ecosystem, name, purl}` dùng để query |
| `version` | string | Exact version đã query |
| `status` | enum | `known_affected`, `no_known_vulnerability`, `query_error` |
| `vulnerability_ids` | array | Các advisory OSV khớp version |
| `query_method` | string | `osv_querybatch` |
| `status_semantics` | string | Giải thích chính xác cho status |
| `queried_at` | string | Thời điểm query |

`no_known_vulnerability` không đồng nghĩa với `safe`; `query_error` không được suy
diễn thành verdict. `known_affected` chỉ là tín hiệu package-level, chưa chứng minh
đường đi source → sink có thể khai thác trong code đang scan.

## 3. `advisories.jsonl`

Snapshot nội dung advisory để KB vẫn dùng được khi URL upstream chết.

| Trường | Kiểu | Ý nghĩa |
|---|---|---|
| `id` | string | GHSA/PYSEC hoặc mã OSV |
| `aliases` | array | CVE và mã liên quan |
| `summary`, `details` | string | Mô tả lỗi và tác động |
| `affected` | array | Package, ranges/events và versions bị ảnh hưởng |
| `references` | array | URL/PATCH/COMMIT/REPORT gốc |
| `source` | object | URL snapshot OSV, thời điểm và SHA-256 |

Phiên bản đã vá được lấy từ `affected[].ranges[].events[]` với event `fixed`, nên
không tạo thêm một trường `fixed_versions` có thể lệch khỏi advisory gốc.

## 4. `patch_diffs.jsonl`

Patch diff unified lấy từ commit upstream được advisory tham chiếu trực tiếp.

| Trường | Kiểu | Ý nghĩa |
|---|---|---|
| `library_id` | string | Liên kết patch với package |
| `advisory_ids` | array | Advisory có reference tới cùng commit |
| `commit_sha` | string | Commit upstream bất biến |
| `source` | object | Repository/commit/patch URL, thời điểm và SHA-256 |
| `unified_diff` | string | Nội dung diff dùng offline cho retrieval/evidence |
| `offline_evidence` | boolean | Có evidence patch đã snapshot offline trong dataset raw |

Không tự gán patch từ fork hoặc commit không được advisory dẫn trực tiếp.

## 5. `manifest.json`

Manifest ghi `schema_version`, thời điểm crawl, danh sách library, thống kê record,
nguồn, SHA-256 raw artifact, lỗi và semantics của các status. Đây là file kiểm toán
giúp tái lập kết quả mà không commit toàn bộ raw/processed dataset.

## Luồng sử dụng trong KB/RAG

```text
SBOM/dependency → canonical package + exact version
  → version_security_matrix → advisory snapshot + fixed range
  → patch diff/evidence → (Sprint 4) symbol/source/sink/sanitizer/guard
  → V-LLM verdict có bằng chứng và điều kiện, giảm False Positive
```
