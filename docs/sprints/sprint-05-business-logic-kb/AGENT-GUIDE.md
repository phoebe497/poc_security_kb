# Agent Guide — Sprint 05 Business Logic Knowledge Base

## Mục lục

1. [Mục tiêu](#1-mục-tiêu)
2. [Nguyên tắc bắt buộc](#2-nguyên-tắc-bắt-buộc)
3. [Quy trình thực hiện](#3-quy-trình-thực-hiện)
4. [Cấu trúc KB](#4-cấu-trúc-kb)
5. [Bộ câu hỏi và benchmark](#5-bộ-câu-hỏi-và-benchmark)
6. [Deliverables](#6-deliverables)
7. [Quy tắc viết report một trang A4](#7-quy-tắc-viết-report-một-trang-a4)
8. [Definition of Done](#8-definition-of-done)

## 1. Mục tiêu

Crawl các lab và nội dung hướng dẫn chính thức về Business Logic Vulnerabilities từ
PortSwigger, chuyển chúng thành playbook có cấu trúc, rồi kiểm tra liệu KB có giúp một
LLM năng lực thấp tìm business logic bug trong source code tốt hơn hay không.

Luồng xuyên suốt phải là:

```text
PortSwigger source
→ normalized playbook
→ câu hỏi code gắn playbook
→ LLM chạy không KB/có KB
→ chấm cùng rubric
→ kết luận bằng số liệu
```

## 2. Nguyên tắc bắt buộc

- Chỉ crawl phạm vi Business Logic từ nguồn PortSwigger chính thức: overview, examples,
  prevention, lab pages và official solutions được discovery từ trang nguồn.
- Không hardcode số lab; lưu danh sách URL thực tế tại thời điểm crawl.
- Không tự động chạy lab, payload hoặc PoC. Chỉ tải text/HTML để phân tích offline.
- Raw HTML giữ local và bị Git ignore. GitHub chỉ chứa playbook đã chuẩn hóa, paraphrase,
  provenance và sample cần thiết; không sao chép nguyên văn toàn bộ bài viết.
- Mỗi fact phải truy ngược được tới nguồn bằng chuỗi ID:

```text
source_id → playbook_id → question_id → run_id → score
```

- Không tạo các mảng kiến thức rời rạc. Mỗi playbook phải nối business rule với giả
  định sai, abuse flow, component liên quan, missing control và remediation.
- Không thay đổi dataset/crawler Sprint 01–04 nếu không cần thiết.

## 3. Quy trình thực hiện

### 3.1 Crawl

1. Discovery URL từ trang Business Logic chính thức.
2. Tải trang với timeout, retry giới hạn và user-agent rõ ràng.
3. Với mỗi response, lưu `source_id`, URL, final URL, thời điểm crawl, HTTP status,
   content type, SHA-256 và local raw path.
4. Ghi lỗi theo từng URL; một URL lỗi không được dừng toàn bộ run.
5. Không chạy JavaScript, lab hoặc code lấy từ trang.

### 3.2 Normalize

Từ mỗi lab/write-up, trích business context, intended rule, flawed assumption,
precondition, state transition, abuse sequence, missing control, impact, detection
questions và remediation. Nếu nội dung nguồn không đủ, để `unknown`; không suy đoán.

### 3.3 Profile dữ liệu

Thống kê số URL thành công/thất bại, số playbook, dung lượng raw/processed/sample,
distribution theo category, duplicate rate, missing-field rate và coverage của rule,
precondition, abuse sequence, missing control, remediation.

## 4. Cấu trúc KB

Mỗi dòng `playbooks.jsonl` tối thiểu có:

```json
{
  "playbook_id": "BL-WORKFLOW-STEP-BYPASS",
  "title": "Bypass bước bắt buộc trong workflow",
  "category": "workflow_violation",
  "business_context": "Quy trình nhiều bước",
  "actors": ["user", "system"],
  "components": ["controller", "service", "state_store"],
  "intended_rules": ["Bước trước hoàn thành trước bước sau"],
  "flawed_assumptions": ["User luôn đi đúng thứ tự UI"],
  "preconditions": ["Endpoint bước sau gọi trực tiếp được"],
  "state_transitions": ["CREATED -> VERIFIED -> COMPLETED"],
  "abuse_sequence": ["Bỏ qua VERIFY", "Gọi COMPLETE"],
  "missing_controls": ["Không kiểm tra state ở server"],
  "detection_questions": ["Endpoint có kiểm tra state trước đó không?"],
  "false_positive_conditions": ["Service enforce transition nguyên tử"],
  "impact": ["workflow bypass"],
  "remediation": ["Enforce transition server-side"],
  "evidence_ids": ["PS-SOURCE-001"]
}
```

Category tối thiểu nên bao phủ: trust client input, unconventional input, workflow
sequence violation, domain invariant violation, replay/idempotency và policy/authorization
inconsistency. Không bắt buộc source/sink nếu lỗi nằm ở hành vi hoặc trạng thái.

## 5. Bộ câu hỏi và benchmark

### 5.1 Năm câu hỏi code

Tạo đúng 5 câu, mỗi câu khoảng 40–80 dòng và gồm nhiều component như controller,
service, repository, policy hoặc state store:

1. Giá/quantity do client kiểm soát.
2. Coupon vẫn hiệu lực sau khi cart không còn thỏa điều kiện.
3. Bỏ qua bước bắt buộc trong workflow.
4. Refund/replay nhiều lần do thiếu idempotency hoặc state validation.
5. Thiếu policy, approval, separation of duties hoặc transaction limit.

Mỗi câu có `question_id`, requirements, source code và prompt yêu cầu tìm lỗi, abuse
flow, impact, remediation. Gold answer lưu riêng; không viết comment làm lộ đáp án.

### 5.2 Dùng LLM để benchmark

Dùng **cùng một LLM năng lực thấp** ở hai điều kiện:

```text
A — Baseline: question, không có KB
B — KB-assisted: cùng question + toàn bộ playbook KB trong context
```

Giữ nguyên model, system prompt, temperature, max tokens và output format. Đặt
`temperature = 0`; nếu runtime vẫn không deterministic, chạy 3 lần cho mỗi câu và mỗi
điều kiện. Không dùng retrieval ở Sprint này.

### 5.3 Rubric 10 điểm

| Tiêu chí | Điểm |
|---|---:|
| Xác định đúng lỗi | 0–2 |
| Nêu đúng business rule/invariant bị vi phạm | 0–2 |
| Mô tả abuse flow qua các component | 0–2 |
| Precondition | 0–1 |
| Impact | 0–1 |
| Remediation đúng tầng server/business service | 0–1 |
| Không hallucinate/False Positive | 0–1 |

Chấm bằng gold answer và rubric cố định. Có thể dùng script tính tổng, nhưng kết quả
cuối phải được người thực hiện kiểm tra; không dùng một LLM khác làm giám khảo duy nhất.
Lưu toàn bộ response, không cherry-pick output đẹp.

## 6. Deliverables

```text
docs/sprints/sprint-05-business-logic-kb/
├── AGENT-GUIDE.md
└── README.md

scripts/
├── crawl_portswigger_logic.py
├── transform_business_logic_kb.py
└── run_business_logic_benchmark.py

schemas/
└── business_logic_playbook.schema.json

data/samples/sprint-05-business-logic-kb/
├── playbooks.jsonl
├── questions.jsonl
├── answer_key.jsonl
├── benchmark_runs.jsonl
├── benchmark_summary.json
└── manifest.json

tests/
└── test_business_logic_kb.py
```

## 7. Quy tắc viết report một trang A4

Report chính là `docs/sprints/sprint-05-business-logic-kb/README.md` và phải đọc được
như một câu chuyện duy nhất từ nguồn → KB → câu hỏi → benchmark → kết luận.

### Giới hạn hình thức

- Có mục lục với anchor link.
- Khoảng **700–900 từ tiếng Việt**, mục tiêu khi in là một trang A4; không kéo dài bằng
  giải thích thuật ngữ chung.
- Tối đa 6 mục chính và 2 bảng.
- Không tách thêm report Markdown nhỏ.
- Dùng câu ngắn, chủ động, nêu số liệu trước nhận xét.
- Tránh các từ quảng cáo như “toàn diện”, “đột phá”, “rất hiệu quả” nếu không có metric.

### Cấu trúc bắt buộc

```markdown
# Sprint 05 — Business Logic KB

## Mục lục
1. Mục tiêu và kết luận
2. Nguồn và phương pháp
3. KB thu được
4. Benchmark
5. Kết quả
6. Giới hạn và bước tiếp theo
```

### Quy tắc liên kết nội dung

- Phần nguồn phải nói record nào được tạo ra từ nguồn đó.
- Phần KB phải nói playbook nào được dùng để thiết kế từng câu hỏi.
- Phần benchmark phải link `question_id` với `run_id` và rubric.
- Phần kết quả phải dẫn số liệu từ `benchmark_summary.json`, không nhận xét cảm tính.
- Kết luận phải trả lời đúng một câu: **KB giúp model cải thiện ở tiêu chí nào, bao
  nhiêu, và còn giới hạn gì?**
- Mỗi bảng/metric phải có câu trước giải thích mục đích và câu sau giải thích ý nghĩa.
- Không đặt các đoạn taxonomy, schema, benchmark và kết luận cạnh nhau mà không mô tả
  quan hệ giữa chúng.

Report tối thiểu phải nêu:

```text
N nguồn → M playbook → 5 questions → R benchmark runs
Baseline score A/10 → KB-assisted score B/10
False Positive X → Y
```

## 8. Definition of Done

- Discovery và crawl đầy đủ phạm vi PortSwigger Business Logic tại thời điểm chạy.
- Raw snapshot có hash/timestamp; raw content không commit.
- Mỗi playbook nối đủ rule → assumption → abuse → missing control → remediation.
- Có dataset profile và crawl errors.
- Có đúng 5 câu code multi-component và gold answer riêng.
- Benchmark cùng LLM/config ở hai điều kiện, không dùng retrieval.
- Có raw model outputs, rubric scores và summary tái lập được.
- Report một trang A4, có mục lục, số liệu và mạch nội dung liên tục.
- Unit tests, schema validation và `git diff --check` pass.
- Không commit token, cache, binary payload hoặc nội dung PortSwigger nguyên văn dài.

