# Sprint 02 — Evidence enrichment

## Mục tiêu

Bổ sung bằng chứng mà advisory thuần metadata còn thiếu: patch diff, nội dung
PoC/reproduction, GitHub issue/PR và mô hình source/sink/propagator/barrier.

## Deliverables

- [Mô tả sample dataset](sample-dataset.md).
- [Report GitHub evidence](reports/github-evidence.md).
- [Report CodeQL models](reports/codeql-models.md).
- Dataset mẫu tại `data/samples/sprint-02-evidence/`.
- Crawler tại `scripts/crawl_github_evidence.py` và
  `scripts/crawl_codeql_models.py`.

## Kết quả và giới hạn

CodeQL model hiện gắn với revision của repository CodeQL, chưa tự ánh xạ chính
xác API nào tồn tại trong từng phiên bản Django/Log4j. Khoảng trống này được
đưa sang Sprint 03.
