# Kết quả PoC crawl KB theo phiên bản thư viện

Thời điểm chạy: `2026-08-03T09:32:21.832559+00:00`

| Library | Ecosystem/package | Số phiên bản | Phiên bản có advisory |
|---|---|---:|---:|
| Django | `PyPI:Django` | 438 | 431 |
| Apache Log4j Core | `Maven:org.apache.logging.log4j:log4j-core` | 76 | 74 |

Số advisory snapshot chi tiết: **40**.
Số patch diff upstream đã snapshot: **20**.
Số version affected cao vì inventory gồm toàn bộ lịch sử release; đây không phải tỷ lệ rủi ro của các bản đang được hỗ trợ.

## Cách đọc kết quả

- `known_affected`: OSV trả advisory cho đúng package + version.
- `no_known_vulnerability`: không tìm thấy advisory đã biết; không được hiểu là an toàn.
- `query_error`: thiếu bằng chứng, không được tự suy diễn verdict.

## Lỗi/cảnh báo

- Không có.
