# Kết quả crawl CodeQL library models

- Số nguồn/file: **101**
- Số model tuple: **2100**
- Repository: **github/codeql**
- Tài liệu sanitizer: **docs/ trong github/codeql**
- License repository và tài liệu trong repo: **MIT**.

## Nhóm model

| Nhóm | Số lượng |
|---|---:|
| propagator | 1144 |
| sink | 736 |
| source | 162 |
| type_relation | 50 |
| other | 2 |
| package_relation | 2 |
| sanitizer_or_barrier | 2 |
| sanitizer_or_guard | 2 |

## Ngôn ngữ

| Ngôn ngữ | Số lượng model |
|---|---:|
| java | 984 |
| csharp | 699 |
| javascript | 209 |
| go | 205 |
| ruby | 2 |
| python | 1 |

## Cách hiểu dữ liệu

- `sourceModel` → source.
- `sinkModel` → sink.
- `summaryModel` → propagator/data-flow summary.
- `barrierModel` và `barrierGuardModel` → sanitizer/barrier/guard.
- Record giữ nguyên tuple CodeQL; không tự suy diễn tên API.
