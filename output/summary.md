# Tóm tắt PoC thu thập dữ liệu Security KB

- Số advisory đã thu thập: **5**
- Nguồn: **GitHub Advisory Database (reviewed advisories)**
- Thời điểm thu thập: **2026-07-31T08:43:35.179251+00:00**

## Phân bố severity

| Severity | Số lượng |
|---|---:|
| critical | 2 |
| high | 2 |
| low | 1 |

## CWE xuất hiện nhiều nhất

| CWE | Số lượng |
|---|---:|
| CWE-95 | 1 |
| CWE-1188 | 1 |
| CWE-416 | 1 |
| CWE-76 | 1 |
| CWE-918 | 1 |

## Hệ sinh thái package

| Ecosystem | Số lượng |
|---|---:|
| rubygems | 4 |
| npm | 2 |
| pip | 1 |

## Giới hạn của PoC

- Đây là lớp advisory metadata; patch diff, PoC và source/sink/sanitizer
  nằm trong `data/processed`.
- Dùng `crawl_github_evidence.py`, `crawl_codeql_models.py` và
  `transform_to_kb.py` để tạo KB đầy đủ.
