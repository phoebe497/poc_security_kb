# Curated Security Evidence Samples

Dataset nhỏ tại `data/samples/sprint-02-evidence/` được xuất từ lần crawl thật để
reviewer kiểm tra deliverable mà không cần commit toàn bộ raw/full dataset.

- `github_evidence.jsonl`: patch, pull request, issue và PoC evidence.
- `codeql_models.jsonl`: source, sink, propagator, barrier và guard.
- `patches/`: unified patch diff để đọc trực tiếp.
- `manifest.json`: số lượng, loại record và danh sách patch.

Mỗi record giữ URL, hash và provenance nhưng loại bỏ absolute path của máy local.
PoC/exploit chỉ được lưu như text evidence và không được tự động thực thi.

Tái tạo sample sau khi crawl:

```powershell
python scripts/export_samples.py
```
