# Nguồn dữ liệu và trust policy

| Nguồn | Dữ liệu | Vai trò | Trust |
|---|---|---|---|
| PyPI API | Django releases/artifacts/hash/yanked | Registry inventory | Chính thức |
| Maven Central REST API | Log4j Core GAV releases | Registry inventory | Chính thức |
| OSV API/schema | Exact-version matches và advisory | Vulnerability index | Aggregator có cấu trúc |
| Django security archive | Disclosure/patch theo branch | Upstream verification | Chính thức |
| Apache Logging security/VDR | Affected/fixed versions | Upstream verification | Chính thức |
| Upstream GitHub repo | Tag, commit, patch, source | Code evidence | Chính thức khi đúng org/repo |
| GitHub Advisory Database | GHSA/CVE metadata | Bổ sung advisory | Reviewed tùy record |
| CodeQL repository | Source/sink/flow/barrier model | Semantic seed | Chính thức nhưng cần context |

Nguyên tắc:

- Registry trả lời “version nào tồn tại”, không tự chứng minh version an toàn.
- OSV trả lời “advisory đã biết nào khớp version”, không tự chứng minh finding có
  exploit được trong code đang scan.
- Upstream security page/patch ưu tiên hơn blog tổng hợp khi có xung đột.
- Mỗi response cần thời điểm crawl, URL, hash và snapshot local.
- URL là provenance; KB không được phụ thuộc URL còn sống để đọc nội dung.

Các tài liệu API chính thức được kiểm tra ngày 2026-08-03:

- PyPI JSON/Index API: https://docs.pypi.org/api/
- Maven Central REST API: https://central.sonatype.org/search/rest-api-guide/
- OSV querybatch: https://google.github.io/osv.dev/post-v1-querybatch/
- OSV schema: https://ossf.github.io/osv-schema/
- Django security archive: https://docs.djangoproject.com/en/stable/releases/security/
- Apache Logging security: https://logging.apache.org/security.html
- Apache Log4j version policy: https://logging.apache.org/log4j/2.x/versioning.html
