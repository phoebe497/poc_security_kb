# Sprint 05 — Business Logic KB

**Ngày thực hiện:** 2026-08-12  
**Nguồn KB:** PortSwigger Web Security Academy (21 trang, crawl thật) + 3 business rule nội bộ  
**Benchmark:** LLM-as-Judge qua OpenCode Zen API · temperature=0 · 1 run/condition  
**Responder:** `glm-5.1` · **Judge:** `gpt-5.6-luna`

## Mục lục

1. [Mục tiêu và kết luận](#1-mục-tiêu-và-kết-luận)
2. [Nguồn và phương pháp](#2-nguồn-và-phương-pháp)
3. [KB thu được](#3-kb-thu-được)
4. [Benchmark](#4-benchmark)
5. [Kết quả](#5-kết-quả)
6. [Giới hạn và bước tiếp theo](#6-giới-hạn-và-bước-tiếp-theo)

---

## 1. Mục tiêu và kết luận

**Câu hỏi:** Playbook Business Logic có giúp một LLM năng lực thấp (`glm-5.1`) tìm bug
logic trong source code tốt hơn không?

**Thiết kế:** So sánh cùng một model responder ở hai điều kiện — không có KB (baseline)
và có KB (KB-assisted) — trên cùng bộ câu hỏi, cùng system prompt, cùng temperature=0.
Chấm điểm bằng **LLM-as-Judge**: một model độc lập, khác họ (`gpt-5.6-luna`) đọc câu trả
lời, gold answer và rubric rồi trả về điểm từng tiêu chí kèm lý do. Không dùng keyword
matching; không để model vừa trả lời tự chấm.

**Kết luận (chạy thật, không phải sample):** KB **có giá trị đúng ở nơi cần**. Trên
tổng 8 câu, KB-assisted đạt **10.0/10** so với baseline **9.25/10** (Δ = +0.75), False
Positive **0/0**. Kết quả tách làm hai nhóm rõ rệt:

- **5 câu theo pattern PortSwigger phổ biến (Q01–Q05):** baseline đã đạt 10/10, KB
  không thêm gì (Δ = 0). Model tầm trung **đã học sẵn** loại kiến thức public này.
- **3 câu dựa trên business rule NỘI BỘ (Q06–Q08):** baseline chỉ 8/10 vì model bỏ sót
  đúng cái rule đặc thù mà nó không thể biết trước; KB cung cấp rule → **10/10 (Δ = +2
  mỗi câu)**.

Đây là phát hiện cốt lõi: **KB tạo giá trị biên khi chứa tri thức mà model chưa có
(rule nội bộ/đặc thù domain), chứ không phải khi lặp lại tri thức public model đã học.**

---

## 2. Nguồn và phương pháp

**Nguồn public:** [PortSwigger Web Security Academy — Business Logic Vulnerabilities](https://portswigger.net/web-security/logic-flaws)
và [Race Conditions](https://portswigger.net/web-security/race-conditions).
Crawler (`scripts/crawl_portswigger_logic.py`) discovery URL từ các trang seed, chỉ đi
theo link trong nhóm prefix business-logic/race-condition, tải HTML với timeout/retry và
user-agent rõ ràng, lưu raw HTML kèm SHA-256 qua **Git LFS** tại `data/raw/portswigger/`.
Không chạy JavaScript, lab hoặc payload. 21 trang → 21 playbook.

**Nguồn nội bộ:** 3 business rule đặc thù tổ chức (dual-control refund chéo cost-center,
trần loyalty points + loại trừ promo tier cao, cooling-off wire tới payee mới) được biểu
diễn thành 3 playbook với evidence `INT-RULE-001..003`. Đây là loại tri thức KB thực tế
sẽ chứa mà một LLM public **không thể suy ra** từ pretraining — dùng để kiểm chứng đóng
góp thật của KB.

Mỗi record truy ngược: `source_id → playbook_id → question_id → run_id → score`.
Transform: `scripts/transform_business_logic_kb.py`.

---

## 3. KB thu được

24 playbook (`data/samples/sprint-05-business-logic-kb/playbooks.jsonl`) bao phủ đủ 6
category:

| Category | Số playbook |
|---|---:|
| replay_idempotency | 8 |
| domain_invariant_violation | 4 |
| policy_authorization_inconsistency | 4 |
| workflow_sequence_violation | 4 |
| trust_client_input | 2 |
| unconventional_input | 2 |
| **Tổng** | **24** |

Trong đó 21 playbook từ PortSwigger và 3 playbook rule nội bộ (`BL-POLICY-INT-REFUND-DUAL-CONTROL`,
`BL-DOMAIN-INT-LOYALTY-POINTS-CAP`, `BL-WORKFLOW-INT-WIRE-COOLING-OFF`). Mỗi playbook nối
đủ: `intended_rules → flawed_assumptions → preconditions → abuse_sequence →
missing_controls → false_positive_conditions → remediation`.
Schema: `schemas/business_logic_playbook.schema.json`.

---

## 4. Benchmark

8 câu hỏi code multi-component (không có comment làm lộ đáp án), mỗi câu gắn một playbook:

| Q | Nhóm | Tiêu đề | Playbook gắn |
|---|---|---|---|
| Q01 | public | Giá do client kiểm soát | BL-TRUST-CLIENT-INP-… |
| Q02 | public | Coupon vẫn áp sau khi cart đổi | BL-REPLAY-IDEMPOTEN-INFINITE-MONEY |
| Q03 | public | Bỏ qua bước xác minh registration | BL-WORKFLOW-SEQUENC-… |
| Q04 | public | Refund duplicate thiếu idempotency | BL-REPLAY-IDEMPOTEN-LIMIT-OVERRUN |
| Q05 | public | Thiếu separation of duties | BL-POLICY-AUTHORIZA-… |
| Q06 | **nội bộ** | Refund lớn thiếu dual-control chéo cost-center | BL-POLICY-INT-REFUND-DUAL-CONTROL |
| Q07 | **nội bộ** | Loyalty points vượt trần + promo tier cao | BL-DOMAIN-INT-LOYALTY-POINTS-CAP |
| Q08 | **nội bộ** | Wire tới payee mới thiếu cooling-off/OOB | BL-WORKFLOW-INT-WIRE-COOLING-OFF |

**Hai điều kiện** với cùng model/system prompt/temperature=0:

- **A — Baseline:** câu hỏi + code, không có KB.
- **B — KB-assisted:** câu hỏi + code + toàn bộ playbook trong context (không dùng retrieval).

**Chấm điểm — LLM-as-Judge:** `gpt-5.6-luna` nhận câu hỏi, gold answer (`answer_key.jsonl`),
câu trả lời của responder và rubric 10 điểm cố định (AGENT-GUIDE.md §5.3), trả về JSON
điểm từng tiêu chí kèm lý do.

Runs raw lưu tại `benchmark_runs.jsonl` (Git LFS). Summary: `benchmark_summary.json`.

---

## 5. Kết quả

Số liệu dẫn trực tiếp từ `benchmark_summary.json` (chạy thật 2026-08-12):

| Câu | Nhóm | Baseline | KB-assisted | Δ |
|---|---|---:|---:|---:|
| Q01 — Giá client kiểm soát | public | 10/10 | 10/10 | 0 |
| Q02 — Coupon recheck | public | 10/10 | 10/10 | 0 |
| Q03 — Workflow step bypass | public | 10/10 | 10/10 | 0 |
| Q04 — Refund idempotency | public | 10/10 | 10/10 | 0 |
| Q05 — Separation of duties | public | 10/10 | 10/10 | 0 |
| Q06 — Dual-control refund | **nội bộ** | **8/10** | **10/10** | **+2** |
| Q07 — Loyalty points cap | **nội bộ** | **8/10** | **10/10** | **+2** |
| Q08 — Wire cooling-off | **nội bộ** | **8/10** | **10/10** | **+2** |
| **Trung bình** | | **9.25/10** | **10.0/10** | **+0.75** |

False Positive: **0 → 0** (KB không làm tăng cảnh báo sai).

**Vì sao Δ dồn vào nhóm nội bộ.** Kiểm chứng lý do của judge cho thấy baseline mất điểm
đúng ở hai tiêu chí `correct_bug_identified` và `business_rule_stated` của Q06–Q08:

- Q06: *"Nêu đúng invariant không được hoàn tiền nhiều lần, nhưng không nêu business rule
  về approver khác cost center và cùng fiscal quarter."*
- Q07: *"States inferred tier and percentage rules, but does not state the required
  INT-RULE-002 invariants."*
- Q08: *"States valid positive-amount and daily-limit invariants, but omits INT-RULE-003."*

Nghĩa là không có KB, model **đoán được lỗi chung chung** nhưng **không biết rule đặc
thù**; có KB, model trích đúng rule nội bộ và đạt điểm tối đa. Với nhóm public (Q01–Q05),
model đã kịch trần từ baseline nên KB không còn dư địa — nhưng cũng **không gây hại** (FP
vẫn 0).

---

## 6. Giới hạn và bước tiếp theo

**Giới hạn hiện tại:**

- 3 rule nội bộ là synthetic để minh hoạ cơ chế; cần thay bằng rule thật của tổ chức khi
  triển khai.
- 1 run/condition không đủ đánh giá variance (nên chạy 3 run với temperature=0).
- Benchmark không dùng retrieval — đưa toàn bộ KB vào context không scale khi KB lớn.
- Với nhóm câu hỏi public, benchmark không phân biệt được KB vì model đã học sẵn nguồn đó.

**Bước tiếp theo:**

- Mở rộng tập rule nội bộ/đặc thù domain (approval threshold, chính sách nội bộ thật).
- Chạy benchmark 3 lần/condition và tính confidence interval.
- Sprint 06: thử RAG retrieval thay vì full KB context để đo tác động khi KB lớn, và đo
  hiệu quả khi KB chứa nhiều rule nội bộ.
