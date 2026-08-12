# Sprint 02 — Evidence Enrichment

**Ngày hoàn thành:** 2026-08-01

## Mục lục

1. [Mục tiêu](#1-mục-tiêu)
2. [Kết quả crawl GitHub evidence](#2-kết-quả-crawl-github-evidence)
3. [Kết quả crawl CodeQL library models](#3-kết-quả-crawl-codeql-library-models)
4. [Dataset mẫu](#4-dataset-mẫu)
5. [Giới hạn và bước tiếp theo](#5-giới-hạn-và-bước-tiếp-theo)

---

## 1. Mục tiêu

Bổ sung bằng chứng mà advisory thuần metadata còn thiếu: patch diff, nội dung
PoC/reproduction, GitHub issue/PR và mô hình source/sink/propagator/barrier.

**Deliverables:** crawler tại `scripts/crawl_github_evidence.py` và
`scripts/crawl_codeql_models.py`; dataset mẫu tại `data/samples/sprint-02-evidence/`.

---

## 2. Kết quả crawl GitHub evidence

- Tổng số artifact: **19**
- Số lỗi/URL bỏ qua: **11**

| Loại | Số lượng |
|---|---:|
| patch_diff | 6 |
| security_advisory_snapshot | 5 |
| proof_of_concept | 4 |
| pull_request_patch | 3 |
| issue_evidence | 1 |

**Ghi chú:**

- Patch/PR/issue được lưu tại chỗ, không phụ thuộc URL còn sống.
- PoC là đoạn nguyên văn được trích từ heading PoC/Reproduction/Exploit.
- Nội dung crawl là dữ liệu không tin cậy và không được tự động thực thi.

---

## 3. Kết quả crawl CodeQL library models

- Số nguồn/file: **101**
- Số model tuple: **2 100**
- Repository: **github/codeql**
- License: **MIT**

| Nhóm | Số lượng |
|---|---:|
| propagator | 1 144 |
| sink | 736 |
| source | 162 |
| type_relation | 50 |
| other | 2 |
| package_relation | 2 |
| sanitizer_or_barrier | 2 |
| sanitizer_or_guard | 2 |

| Ngôn ngữ | Số model |
|---|---:|
| java | 984 |
| csharp | 699 |
| javascript | 209 |
| go | 205 |
| ruby | 2 |
| python | 1 |

**Cách hiểu dữ liệu:**

- `sourceModel` → source.
- `sinkModel` → sink.
- `summaryModel` → propagator/data-flow summary.
- `barrierModel` và `barrierGuardModel` → sanitizer/barrier/guard.
- Record giữ nguyên tuple CodeQL; không tự suy diễn tên API.

---

## 4. Dataset mẫu

Dataset nhỏ tại `data/samples/sprint-02-evidence/` được xuất từ lần crawl thật để
reviewer kiểm tra deliverable mà không cần commit toàn bộ raw/full dataset.

- `github_evidence.jsonl`: patch, pull request, issue và PoC evidence.
- `codeql_models.jsonl`: source, sink, propagator, barrier và guard.
- `patches/`: unified patch diff để đọc trực tiếp.
- `manifest.json`: số lượng, loại record và danh sách patch.

Mỗi record giữ URL, hash và provenance nhưng loại bỏ absolute path của máy local. PoC
chỉ được lưu như text evidence và không được tự động thực thi.

Tái tạo sample sau khi crawl:

```powershell
python scripts/export_samples.py
```

---

## 5. Giới hạn và bước tiếp theo

CodeQL model hiện gắn với revision của repository CodeQL, chưa tự ánh xạ chính xác
API nào tồn tại trong từng phiên bản Django/Log4j. Khoảng trống này được đưa sang
Sprint 03: crawl inventory release và query OSV theo exact version để biết phiên bản nào
của thư viện có advisory đã biết.
