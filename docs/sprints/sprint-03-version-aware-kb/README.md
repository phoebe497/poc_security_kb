# Sprint 03 — Version-aware Knowledge Base

## Câu hỏi mentor đặt ra

Làm thế nào crawl knowledge hiệu quả cho từng phiên bản library, thử trước với
Django và Apache Log4j?

## Kết luận thiết kế

Không tạo một file Markdown cho mỗi version. Dữ liệu máy đọc được lưu thành ba
bảng JSONL liên kết bằng `library_id + ecosystem + package + version`:

1. `library_releases.jsonl`: inventory phiên bản từ package registry.
2. `version_security_matrix.jsonl`: kết quả OSV cho đúng từng version.
3. `advisories.jsonl`: nội dung advisory đầy đủ, affected ranges và references.
4. `patch_diffs.jsonl`: unified diff offline của commit thuộc upstream repo được
   advisory tham chiếu, nối với `advisory_id` và `library_id`.

Markdown chỉ dùng cho research/report; JSONL dùng cho ingestion, filter và RAG.

## Deliverables để mentor chấm

| Deliverable | Vị trí | Cách kiểm tra |
|---|---|---|
| Crawler | `scripts/crawl_library_versions.py` | Chạy command trong README root |
| Schema | [version-kb-schema.md](version-kb-schema.md) | Kiểm tra trạng thái, semantics và provenance |
| Mentor summary | [mentor-summary.md](mentor-summary.md) | Đọc nhanh phương pháp, số liệu và kiểm chứng |
| Research/brainstorm | [research-plan.md](research-plan.md) | Kiểm tra nguồn và roadmap |
| Hướng dẫn sử dụng | [usage-guide.md](usage-guide.md) | Crawl/query Django và Log4j |
| Report lần crawl | [crawl-report.md](crawl-report.md) | Kiểm tra số liệu/lỗi |
| Dataset thật | `data/samples/sprint-03-version-aware-kb/` | Đọc JSONL/manifest |

## Definition of Done cho PoC

- Có inventory thật từ PyPI và Maven Central.
- Mỗi version được query theo đúng ecosystem bằng OSV `querybatch`.
- Không gắn nhãn `safe` khi không có advisory.
- Advisory được snapshot nội dung, không chỉ lưu URL.
- Có patch diff upstream thật cho các advisory ưu tiên, không tự nhận patch từ fork.
- Raw response có hash và thời điểm crawl.
- Sample commit không chứa absolute path local.
- Unit test cũ và mới đều pass.

## Các bước tiếp theo

PoC hiện giải quyết package/version/advisory. Giai đoạn kế tiếp cần tải source
artifact hoặc tag tương ứng để tạo `symbol_inventory` và `security_semantic_delta`:

- API/class/method xuất hiện hoặc biến mất giữa hai version.
- Source/sink/sanitizer nào thực sự tồn tại ở version đó.
- Patch thay đổi default/config/validation nào.
- Ánh xạ symbol bị sửa với CWE và điều kiện khai thác.

Các bước này phải là record có cấu trúc, không quay lại mô hình một `.md` cho mỗi
artifact.
