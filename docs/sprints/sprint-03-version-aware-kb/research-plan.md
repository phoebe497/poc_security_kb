# Kế hoạch nghiên cứu và brainstorm

## 1. Tách đúng các lớp knowledge

| Lớp | Câu hỏi | Nguồn ưu tiên | Record |
|---|---|---|---|
| Package identity | Tên package chuẩn là gì? | PyPI/Maven Central | `library_release` |
| Version inventory | Có những release nào, ngày nào, artifact/hash nào? | PyPI/Maven Central | `library_release` |
| Vulnerability status | Version cụ thể có advisory đã biết không? | OSV exact-version query | `library_version_security_status` |
| Advisory detail | Root cause, range, fixed event, reference là gì? | OSV + upstream security page | `library_version_advisory` |
| Patch delta | Code nào thay đổi giữa vulnerable/fixed? | Upstream Git commit/tag | `patch_diff` |
| API semantics | API nào là source/sink/sanitizer ở version này? | Source artifact + CodeQL + review | `versioned_semantic_model` |

## 2. Tại sao không tự parse mọi version range?

PyPI dùng quy tắc version của Python; Maven có quy tắc ordering riêng. Một bộ so
sánh SemVer tự viết dễ đánh dấu sai pre-release hoặc vendor suffix. PoC gửi thẳng
`ecosystem + package + version` cho OSV `querybatch`, để OSV áp dụng đúng logic
của ecosystem. Cách này vừa ít request hơn query tuần tự vừa giảm False Positive.

## 3. Nguồn thử nghiệm

### Django

- PyPI project/index: inventory release, artifact, SHA-256, yanked state.
- OSV ecosystem `PyPI`, package `Django`: trạng thái từng version.
- Django security archive: disclosure và patch theo release branch.
- Repository `django/django`: signed tag và source/patch tương ứng.

### Apache Log4j Core

- Maven Central GAV: inventory `org.apache.logging.log4j:log4j-core`.
- OSV ecosystem `Maven`: trạng thái từng version.
- Apache Logging security page và CycloneDX VDR: affected/fixed versions chính thức.
- Repository `apache/logging-log4j2`: tag, commit và release source.

## 4. Pipeline đề xuất

```text
registry inventory
       |
       v
canonical package + exact versions
       |
       v
OSV querybatch --------> version_security_matrix
       |
       v
full advisory snapshot -> fixed versions / references / affected symbols
       |
       v
upstream tag + patch ---> versioned symbol/security delta
       |
       v
chunk theo record JSONL -> metadata filter -> hybrid retrieval -> V-LLM verdict
```

## 5. Chiến lược crawl hiệu quả

- Cache raw response theo URL/payload hash; chỉ refresh khi ETag/Last-Modified đổi.
- Query version theo batch thay vì một HTTP request cho mỗi version.
- Tách `raw`, `processed`, `samples`; không commit full crawl.
- Incremental crawl dựa trên release mới và advisory `modified` timestamp.
- Dedupe advisory bằng `id + aliases`, không chỉ CVE hoặc GHSA riêng lẻ.
- Snapshot nội dung và SHA-256 để URL chết không làm mất knowledge.
- Chỉ tải source artifact của các version ở biên `introduced/fixed` hoặc version
  được hệ thống thực tế sử dụng, thay vì clone mọi tag.

## 6. Backlog sau PoC

1. Parse Django security archive và Apache CycloneDX VDR để đối chiếu OSV.
2. Resolve version → upstream tag/commit có xác minh hash.
3. Trích public symbol inventory từ wheel/sdist/JAR mà không thực thi package.
4. Diff symbol/config/default giữa version vulnerable và fixed.
5. Gắn CodeQL model vào khoảng version mà symbol thực sự tồn tại.
6. Tạo evaluation set: vulnerable, fixed, unknown và query-error cases.
