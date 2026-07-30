# PoC thu thập dữ liệu Security Knowledge Base

PoC này lấy các security advisory đã được GitHub review, chuẩn hóa chúng và xuất
ra ba định dạng:

- `output/ghsa_advisories.json`: dữ liệu có cấu trúc để minh họa KB.
- `output/ghsa_advisories.csv`: bảng dữ liệu có thể mở bằng Excel.
- `output/summary.md`: thống kê để chèn vào phụ lục report.

## Cách chạy

```powershell
python .\poc_security_kb\crawl_ghsa.py --limit 30
```

API public có thể chạy không cần token. Nếu gặp giới hạn request, có thể đặt
biến môi trường `GITHUB_TOKEN` trước khi chạy.

## Phạm vi

Đây là proof of concept cho bước thu thập và chuẩn hóa metadata. Nó chưa crawl
patch diff, PoC, source, sink, sanitizer hoặc negative examples.


