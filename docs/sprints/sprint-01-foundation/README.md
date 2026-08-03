# Sprint 01 — Foundation

## Mục tiêu

Xác định các lớp tri thức cần có để V-LLM không verdict chỉ từ tên rule hoặc mã
GHSA: taxonomy, điều kiện khai thác, affected version, patch, PoC và provenance.

## Deliverables

- [Báo cáo nghiên cứu nền tảng](research-report.md).
- [Báo cáo crawl GHSA mẫu](reports/ghsa-summary.md).
- Dataset mẫu tại `data/samples/sprint-01-advisories/`.
- Crawler tại `scripts/crawl_ghsa.py`.

## Kết quả và giới hạn

Sprint này tạo inventory advisory nhưng chưa đủ kết luận source-to-sink hoặc
exploitability. Đây là input cho Sprint 02, không phải verdict cuối cùng.
