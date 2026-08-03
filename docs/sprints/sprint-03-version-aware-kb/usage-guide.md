# Hướng dẫn sử dụng Django và Log4j trong Version KB

Hai library ở đây là **đối tượng được crawl và tra cứu**, không phải dependency
cần cài vào crawler. Pipeline không import hoặc thực thi Django/Log4j.

## 1. Canonical identity

| Library | Ecosystem | Package key | Ví dụ version |
|---|---|---|---|
| Django | PyPI | `Django` | `5.2.1` |
| Apache Log4j Core | Maven | `org.apache.logging.log4j:log4j-core` | `2.14.1` |

Phải dùng đúng ecosystem/package. Không dùng CPE hoặc chuỗi `log4j` chung chung vì
Apache có nhiều artifact khác nhau và vulnerability có thể chỉ ảnh hưởng Core.

## 2. Crawl riêng từng library

### Django

```powershell
python scripts/crawl_library_versions.py `
  --libraries django `
  --max-versions 0 `
  --max-advisories 20 `
  --max-patches 10
```

Nguồn inventory là PyPI. Mỗi release giữ artifact filename, SHA-256, upload time,
`requires_python` và yanked state nếu registry cung cấp.

### Log4j Core

```powershell
python scripts/crawl_library_versions.py `
  --libraries log4j `
  --max-versions 0 `
  --max-advisories 20 `
  --max-patches 10
```

Nguồn inventory là Maven Central GAV với group
`org.apache.logging.log4j`, artifact `log4j-core`.

### Crawl cả hai trong cùng một lần

```powershell
python scripts/crawl_library_versions.py `
  --libraries django,log4j `
  --max-versions 0 `
  --max-advisories 40 `
  --max-patches 20
```

`--max-versions 0` lấy toàn bộ inventory. Khi demo nhanh có thể dùng
`--max-versions 30`, nhưng cách đó bỏ qua lịch sử cũ như Log4Shell nên không dùng
để tạo full KB.

## 3. Tra cứu một version

### Django 5.2.1

```powershell
python scripts/query_version_kb.py --library django --version 5.2.1
```

### Log4j Core 2.14.1

```powershell
python scripts/query_version_kb.py --library log4j --version 2.14.1
```

Xuất JSON để tích hợp vào agent/RAG:

```powershell
python scripts/query_version_kb.py `
  --library log4j-core `
  --version 2.14.1 `
  --format json
```

CLI trả về:

- package identity và ngày release;
- `known_affected`, `no_known_vulnerability` hoặc `query_error`;
- vulnerability IDs;
- advisory detail đã snapshot;
- fixed-version events;
- patch commit đã crawl;
- danh sách evidence còn thiếu trong sample.

## 4. Lấy version từ project đang scan

### Python/Django

Đọc version đã resolve từ lockfile hoặc environment, ưu tiên theo thứ tự:

1. `poetry.lock`, `uv.lock`, `Pipfile.lock` hoặc file lock tương đương.
2. `pip freeze`/SBOM của artifact build.
3. `requirements.txt` nếu pin chính xác như `Django==5.2.1`.

Không query trực tiếp range như `Django>=4.2`; cần resolve thành version thực tế
được deploy.

### Maven/Log4j

Đọc version đã resolve từ:

1. CycloneDX/SPDX SBOM của build.
2. Maven dependency tree/effective POM.
3. `pom.xml` nếu version không bị BOM hoặc dependency management ghi đè.

Ví dụ dependency key cần gửi sang KB:

```text
Maven:org.apache.logging.log4j:log4j-core:2.14.1
```

Không nhầm `log4j-core` với `log4j-api`, bridge hoặc BOM.

## 5. Dùng trong multi-agent SAST

```text
dependency/SBOM agent
  -> canonical package + exact version
  -> metadata filter version_security_matrix
  -> retrieve advisory + patch + semantic model
  -> code-flow agent kiểm tra source/sink/sanitizer/guard
  -> verdict agent nêu evidence và phần còn thiếu
```

Quy tắc verdict:

- `known_affected` chỉ là điều kiện package-level, chưa đủ kết luận finding True Positive.
- `no_known_vulnerability` không được chuyển thành `safe`.
- Chỉ kết luận sau khi điều kiện advisory khớp với call path/config của code.
- Nếu `missing_advisory_snapshots` khác rỗng, chạy crawler với
  `--max-advisories 0` hoặc đánh dấu evidence incomplete.

## 6. Ví dụ diễn giải

Nếu project dùng `log4j-core:2.14.1`, query có thể trả nhiều advisory, gồm
Log4Shell. Model vẫn phải kiểm tra ứng dụng có đường dữ liệu attacker-controlled
đến logging/JNDI-relevant behavior và các điều kiện môi trường hay không.

Nếu project dùng `Django==5.2.1`, query trả các advisory package-level tương ứng.
SAST finding SQL injection chỉ được ưu tiên khi patch/advisory sửa đúng API đang
được gọi và dữ liệu attacker-controlled thực sự đến API đó mà không có guard.
