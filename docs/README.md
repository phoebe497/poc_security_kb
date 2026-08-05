# Bản đồ tài liệu

Tài liệu được tổ chức theo sprint. Mỗi sprint có một `README.md` mô tả câu hỏi,
deliverable, cách chạy và tiêu chí hoàn thành.

| Sprint | Tài liệu bắt đầu | Nội dung |
|---|---|---|
| 01 | [Foundation](sprints/sprint-01-foundation/README.md) | Nền tảng RAG/KB và advisory |
| 02 | [Evidence enrichment](sprints/sprint-02-evidence-enrichment/README.md) | Patch, PoC và data-flow model |
| 03 | [Version-aware KB](sprints/sprint-03-version-aware-kb/README.md) | Django, Log4j và knowledge theo version |
| 04 | [CVE enrichment research](sprints/sprint-04-cve-enrichment/README.md) | So sánh cách bổ sung source/sink, precondition, PoC và technical evidence |

Tài liệu dùng chung:

- [Cấu trúc repository](reference/repository-layout.md)
- [Nguồn dữ liệu và trust policy](reference/data-sources.md)

Quy ước: report và nghiên cứu nằm trong `docs/`; JSON/JSONL/patch dùng để chấm
nằm trong `data/samples/`; raw/full dataset không commit.
