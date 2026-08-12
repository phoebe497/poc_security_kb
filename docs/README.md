# Bản đồ tài liệu

Mỗi sprint có một file `report_sprintXX.md` mô tả câu hỏi, phương pháp, số liệu và kết
quả. Sprint 03 có thêm tài liệu tham chiếu về schema và hướng dẫn vận hành.

| Sprint | Report | Nội dung |
|---|---|---|
| 01 | [report_sprint01.md](sprints/sprint-01-foundation/report_sprint01.md) | Nền tảng RAG/KB: taxonomy, source/sink, schema và MVP |
| 02 | [report_sprint02.md](sprints/sprint-02-evidence-enrichment/report_sprint02.md) | Patch diff, PoC và CodeQL data-flow model |
| 03 | [report_sprint03.md](sprints/sprint-03-version-aware-kb/report_sprint03.md) | KB theo exact version Django và Log4j |
| 04 | [report_sprint04.md](sprints/sprint-04-cve-enrichment/report_sprint04.md) | So sánh 11 phương pháp enrich CVE thành technical knowledge |
| 05 | [report_sprint05.md](sprints/sprint-05-business-logic-kb/report_sprint05.md) | Business Logic KB và benchmark LLM không KB vs có KB |

Tài liệu tham chiếu Sprint 03:

- [Schema version-aware KB](sprints/sprint-03-version-aware-kb/version-kb-schema.md)
- [Hướng dẫn crawl/query Django và Log4j](sprints/sprint-03-version-aware-kb/usage-guide.md)
- [Kế hoạch nghiên cứu](sprints/sprint-03-version-aware-kb/research-plan.md)

Tài liệu dùng chung:

- [Cấu trúc repository](reference/repository-layout.md)
- [Nguồn dữ liệu và trust policy](reference/data-sources.md)

Quy ước: report nằm trong `docs/sprints/`; JSON/JSONL/patch dùng để chấm nằm trong
`data/samples/`; raw/full dataset không commit.
