# Cấu trúc repository

| Đường dẫn | Mục đích | Có commit? |
|---|---|---|
| `docs/sprints/` | Nghiên cứu/report theo từng task | Có |
| `docs/reference/` | Quy ước dùng chung | Có |
| `scripts/` | Crawler, transform, export | Có |
| `tests/` | Unit test và validation dataset | Có |
| `data/samples/` | Output thật nhưng nhỏ để review | Có |
| `data/raw/` | HTTP/API/source snapshot đầy đủ | Không |
| `data/processed/` | Dataset đầy đủ sinh tự động | Không |

Root chỉ giữ `README.md`, dependency và cấu hình repo. Không đặt report rời rạc ở
root; không tạo hàng nghìn Markdown entry để làm primary KB.
