# Curated Security Evidence Samples

Thư mục này chứa một tập nhỏ dữ liệu thật được xuất từ lần crawl đã kiểm tra,
dùng để reviewer xác nhận deliverable mà không phải commit toàn bộ dataset.

- `github_evidence.jsonl`: patch, pull request, issue và PoC evidence.
- `codeql_models.jsonl`: sample source, sink, propagator, barrier và guard.
- `patches/`: unified patch diff tách riêng để đọc nhanh.
- `manifest.json`: số lượng, loại record và danh sách patch.

Mỗi record giữ URL, hash và provenance cần thiết nhưng loại bỏ đường dẫn tuyệt
đối của máy local. Dữ liệu trong thư mục này chỉ là evidence dạng text; không
được tự động thực thi PoC, exploit hoặc code tải về.

Tái tạo sample sau khi crawl:

```powershell
python export_samples.py
```
