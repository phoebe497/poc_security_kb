# Security Knowledge Base PoC cho multi-agent SAST

Repo này là một PoC thu thập và chuẩn hóa evidence bảo mật để V-LLM có
thể verdict finding SAST dựa trên bằng chứng lưu offline, thay vì chỉ dựa
vào một mã GHSA hoặc một URL có thể bị die.

## Mục tiêu

PoC bổ sung bốn lớp dữ liệu:

1. **Advisory:** GHSA, CVE, CWE, severity, CVSS, package và version range.
2. **Patch evidence:** commit, pull request và unified patch diff.
3. **PoC evidence:** reproduction steps, proof of concept, exploit/demonstration
   section được giữ nguyên văn khi xuất hiện trong advisory, PR hoặc issue.
4. **Data-flow models:** source, sink, propagator từ CodeQL library model;
   barrier/guard (sanitizer/validator) từ ví dụ tài liệu CodeQL chính thức.

Raw response được lưu tại chỗ. Vì vậy việc một URL hết hạn hoặc không truy cập
được sau này không làm mất bằng chứng đã crawl.

## Deliverables cho yêu cầu mentor

| Yêu cầu | Dataset đầy đủ giữ local | Sample được push lên GitHub |
|---|---|---|
| Patch diff thật | `data/raw/github/commits/`, `data/raw/github/pulls/` | `samples/patches/`, `samples/github_evidence.jsonl` |
| PoC thật | `data/processed/github_evidence.jsonl` | `samples/github_evidence.jsonl` |
| Source/sink/sanitizer | `data/processed/codeql_models.jsonl` | `samples/codeql_models.jsonl` |
| KB theo schema | `data/processed/knowledge_base/` | `output/` và report tổng hợp |
| Provenance/lỗi crawl | `data/processed/*manifest.json`, `*_errors.json` | `samples/manifest.json`, `data/reports/` |

Code tạo ra các deliverable gồm `crawl_ghsa.py`,
`crawl_github_evidence.py`, `crawl_codeql_models.py`, `transform_to_kb.py`,
`export_samples.py` và các tiện ích/test đi kèm.

## Tài liệu tham chiếu nội bộ

Repo có thể được sử dụng cùng một bộ tài liệu tham chiếu do mentor cung cấp.
Bộ tài liệu này dùng để đối chiếu dữ liệu đầu vào, cấu trúc KB và kết quả
chuyển đổi mẫu; crawler không sửa, xóa hoặc phụ thuộc cứng vào nội dung của
chúng. Đây là tài liệu nội bộ, được giữ ở máy local và không commit lên
GitHub.

Transformer tuân theo quy ước schema đã thống nhất, gồm metadata nhận diện,
phân loại lỗ hổng, tóm tắt, provenance, phần mềm/phiên bản ảnh hưởng và nội
dung Markdown chi tiết.

## Nguồn dữ liệu và repo được crawl

### 1. GitHub Advisory Database

Script gọi endpoint public:

```text
https://api.github.com/advisories
```

Mặc định chỉ lấy advisory có `type=reviewed`. Các trường lấy gồm:

- GHSA ID và CVE ID.
- Summary và full description.
- CWE.
- Severity và CVSS.
- Package ecosystem/name.
- Vulnerable version range.
- First patched version.
- Vulnerable functions.
- References và thời gian publish/update.

### 2. Repository references trong advisory

Từ `references` và URL trong description, crawler nhận diện các URL GitHub
thuộc dạng:

- `github.com/<owner>/<repo>/commit/<sha>`
- `github.com/<owner>/<repo>/pull/<number>`
- `github.com/<owner>/<repo>/issues/<number>`

Với commit, crawler lấy:

- Commit message.
- Commit SHA và parent SHA.
- Danh sách file thay đổi.
- Additions/deletions/changes.
- Patch từng file nếu API cung cấp.
- Unified diff đầy đủ từ endpoint `.patch`.

Với pull request, crawler lấy:

- Title, body, state, merged status.
- Base/head SHA.
- Merge commit SHA.
- Unified diff đầy đủ.

Với issue, crawler lấy:

- Title, body, labels.
- State, created/updated time.

Crawler cũng lấy repository metadata, gồm default branch, trạng thái archived,
visibility và SPDX license nếu GitHub cung cấp.

### 3. CodeQL library models

Nguồn thứ hai là repository chính thức:

```text
https://github.com/github/codeql
```

PoC crawl các thư mục `ql/lib/ext` của:

- `python/ql/lib/ext`
- `javascript/ql/lib/ext`
- `java/ql/lib/ext`
- `csharp/ql/lib/ext`
- `go/ql/lib/ext`
- `ruby/ql/lib/ext`
- `rust/ql/lib/ext`

Ngôn ngữ nào không có path tương ứng tại thời điểm crawl sẽ được ghi lỗi vào
manifest, không làm dừng toàn bộ pipeline.

Do các file library model đã crawl chưa chứa tuple barrier, crawler còn lấy
ví dụ sanitizer/validator thật từ tài liệu chính thức nằm trong chính repo
`github/codeql`, đồng thời lưu nguyên RST để không phụ thuộc URL:

- `docs/codeql/codeql-language-guides/customizing-library-models-for-javascript.rst`
- `docs/codeql/codeql-language-guides/customizing-library-models-for-ruby.rst`

Các record từ tài liệu có
`knowledge_type=codeql_documentation_model_example` và
`example_status=official_documentation_example_not_repo_runtime_model`, giúp
phân biệt rõ ví dụ hướng dẫn với model đang có sẵn trong repository.

`source.repository_commit_sha` là commit SHA đã resolve; `source.git_blob_sha`
(nếu có) là blob SHA của từng file, không gán nhầm hai loại SHA.

Các predicate CodeQL được giữ nguyên và ánh xạ như sau:

| CodeQL predicate | Nhóm KB | Ý nghĩa |
|---|---|---|
| `sourceModel` | `source` | Nguồn dữ liệu có thể bị taint |
| `sinkModel` | `sink` | Vị trí dữ liệu có thể gây security impact |
| `summaryModel` | `propagator` | Luồng dữ liệu qua hàm/API |
| `barrierModel` | `sanitizer_or_barrier` | Barrier ngăn taint |
| `barrierGuardModel` | `sanitizer_or_guard` | Barrier phụ thuộc điều kiện |
| `neutralModel` | `neutral` | Model trung tính |

Tuple gốc luôn được lưu lại. `barrierModel` không được hiểu là sanitizer an
toàn cho mọi vulnerability; record có cờ `requires_human_interpretation=true`.

## Cấu trúc thư mục output

```text
output/
├── ghsa_advisories.json
├── ghsa_advisories.csv
└── summary.md

data/
├── raw/
│   ├── github/
│   │   ├── advisories/
│   │   ├── commits/
│   │   ├── pulls/
│   │   ├── issues/
│   │   └── repositories/
│   └── codeql/
│       ├── python/, javascript/, java/, csharp/, go/, ruby/, rust/
│       └── documentation/*.rst
├── processed/
│   ├── github_evidence.jsonl
│   ├── github_evidence_errors.json
│   ├── github_evidence_manifest.json
│   ├── codeql_models.jsonl
│   ├── codeql_model_manifest.json
│   └── knowledge_base/
│       ├── entries/*.md
│       ├── knowledge_base.jsonl
│       └── manifest.json
└── reports/
    ├── github_evidence.md
    └── codeql_models.md
```

### Ý nghĩa các loại record

- `security_advisory_snapshot`: advisory đã chuẩn hóa và snapshot offline.
- `patch_diff`: commit và patch diff.
- `pull_request_patch`: PR body và patch diff.
- `issue_evidence`: issue body/labels có thể chứa reproduction detail.
- `proof_of_concept`: section PoC được trích nguyên văn từ một artifact cha.
- `codeql_library_model`: tuple source/sink/propagator/barrier.
- `codeql_documentation_model_example`: tuple sanitizer/barrier/guard trích
  từ tài liệu trong repo `github/codeql`; đây là ví dụ, không phải runtime
  model.

Mỗi evidence record có `artifact_id` ổn định, `advisory_ids`,
`source.url`, `source.api_url`, `retrieved_at`, `content_sha256`,
`local_paths`, `trust_level` và provenance của repository.

## Chính sách file khi push GitHub

Repository Git chỉ lưu source code, tài liệu hướng dẫn và output mẫu nhỏ.
Raw cache và KB sinh tự động được giữ local vì chúng thay đổi thường xuyên,
có thể chứa nội dung từ repository bên thứ ba và sẽ làm lịch sử Git phình to.

| Nhóm | Chính sách | Lý do |
|---|---|---|
| Crawler, transformer, test, `requirements.txt` | Push | Cần để tái lập pipeline |
| `README.md`, report và `data/reports/` | Push | Tài liệu và số liệu tổng hợp nhỏ |
| `samples/` | Push | Tập dữ liệu thật đã tuyển chọn, đủ patch/PoC/source/sink/sanitizer |
| `output/` | Push | Dataset advisory mẫu nhỏ để chạy PoC nhanh |
| Tài liệu tham chiếu nội bộ | Giữ local | Không phân phối tài liệu mentor |
| `data/raw/` | Giữ local | Cache nguồn, patch và snapshot có thể tăng nhanh |
| `data/processed/` | Giữ local | JSONL/Markdown được sinh lại từ crawler |
| `_bmad-output/` | Giữ local | Artifact workflow nội bộ, không cần cho runtime |
| Token, `.env`, virtualenv, cache Python | Giữ local | Tránh lộ secret và file phụ thuộc máy |

Trong lần kiểm tra hiện tại, file lớn nhất là
`data/processed/knowledge_base/knowledge_base.jsonl` khoảng **8,3 MB**;
`data/processed/codeql_models.jsonl` khoảng **2,8 MB**. Chúng chưa chạm giới
hạn 100 MiB/file của GitHub, nhưng không nên đưa vào Git history vì mỗi lần
crawl sẽ tạo diff lớn với hàng nghìn entry. Nếu cần phân phối dataset đầy đủ,
hãy đóng gói thành release artifact, object storage hoặc Git LFS.

Các pattern tương ứng đã được khai báo trong `.gitignore`. Nếu một file đã
được stage/track trước khi thêm ignore, cần bỏ khỏi index bằng
`git restore --staged <path>` hoặc `git rm --cached <path>`; file local không
bị xóa.

## Cài đặt và chạy

Chạy từ thư mục `poc_security_kb`:

```powershell
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

### Bước 1: Crawl GHSA metadata

```powershell
python crawl_ghsa.py --limit 5
```

`--limit` nên nhỏ khi dùng API không token. Có thể dùng token GitHub để tăng
rate limit, nhưng không ghi token vào file hoặc commit:

```powershell
$env:GITHUB_TOKEN = "<TOKEN_CHI_DUNG_O_MAY_LOCAL>"
python crawl_ghsa.py --limit 30
```

### Bước 2: Crawl patch, PR/issue và PoC

```powershell
python crawl_github_evidence.py `
  --limit 5 `
  --max-github-artifacts 10
```

Các option này giới hạn số advisory và số reference để tránh vượt API rate
limit. Lỗi 404, URL hết hạn, response quá lớn hoặc malformed source được ghi
vào `data/processed/github_evidence_errors.json`; crawler vẫn tiếp tục các
record khác.

### Bước 3: Crawl CodeQL source/sink/propagator/sanitizer models

```powershell
python crawl_codeql_models.py `
  --languages python,javascript,java,ruby,go,csharp,rust `
  --max-files-per-language 25 `
  --repository-commit <CODEQL_COMMIT_SHA>
```

Đặt `--max-files-per-language 0` nếu muốn lấy toàn bộ file ở thư mục `ext`
cấp đầu. Tăng scope này sẽ làm số request và dung lượng tăng. Mặc định crawler
cũng lấy các ví dụ barrier/guard từ tài liệu CodeQL; dùng
`--skip-documentation-examples` nếu chỉ muốn lấy file trong repository.
Nếu không truyền `--repository-commit`, crawler cố resolve `main`; khi API
listing lỗi, nó giữ lại model cache local của run trước và ghi lỗi vào
manifest.

### Bước 4: Transform sang KB theo schema mentor

```powershell
python transform_to_kb.py
```

Kết quả gồm Markdown entry để đọc thủ công và JSONL để nạp vào pipeline RAG.
JSONL giữ nguyên trường `content` theo quy ước wrapper tham chiếu; Markdown
chỉ đưa các field frontmatter thuộc schema đã thống nhất.

## Kết quả crawl mẫu đã kiểm tra

Lần chạy PoC hiện tại đã tạo:

- 5 GHSA advisory snapshot.
- 19 GitHub evidence artifact.
- 6 commit patch diff.
- 3 pull request patch.
- 1 issue evidence.
- 4 PoC section.
- 99 CodeQL `.model.yml` file và 2 tài liệu mô hình hóa chính thức.
- 2.100 CodeQL model tuple, gồm:
  - 162 source.
  - 736 sink.
  - 1.144 propagator.
  - 2 sanitizer/barrier.
  - 2 sanitizer/guard.
  - 54 relation/other.
- 2.105 Markdown/JSON KB entries.

Manifest ghi lỗi nguồn (ví dụ path không tồn tại hoặc GitHub API rate limit);
run vẫn giữ cache/raw local và hiển thị `error_count`. Hai ví dụ Ruby
barrier/guard vẫn được crawl từ tài liệu chính thức trong `github/codeql`.
Ở lần chạy kiểm tra này, evidence manifest ghi **11** lỗi GitHub API nhưng
vẫn giữ **19** artifact; CodeQL manifest ghi **7** lỗi listing nhưng vẫn giữ
**2.100** tuple từ cache/raw local. Khi có token hoặc rate limit reset, chạy
lại đúng các lệnh trên để refresh phần lỗi.

Các con số này phụ thuộc `--limit` và `--max-*`, không phải kích thước cố
định của Knowledge Base production.

## An toàn và provenance

- Không có crawler nào thực thi code, shell command, PoC hay exploit tải về.
- Tải xuống có timeout, retry giới hạn và giới hạn kích thước response.
- PoC được lưu như text evidence, không phải lệnh để chạy tự động.
- Raw content được hash SHA-256.
- `raw_kind` phân biệt snapshot API gốc (`github_api_payload`) với snapshot
  normalized input được giữ lại khi API tạm thời bị rate limit.
- Patch mang license của repository nguồn; cần kiểm tra license trước khi
  phân phối lại ra ngoài công ty.
- `github/codeql` là repository MIT; CodeQL tuple vẫn giữ link và commit SHA.
- RST tài liệu CodeQL trong repo được lưu nguyên bản; provenance ghi commit SHA
  của `github/codeql`, không phụ thuộc URL `main` còn trỏ tới revision nào.
- GHSA/reference content phải tuân thủ điều khoản GitHub và license của nguồn.
- URL chỉ là provenance; dữ liệu dùng cho KB phải đọc từ local artifact.

## Giới hạn hiện tại

1. GHSA metadata không tự chứng minh source-to-sink exploitability.
2. PoC extraction hiện chỉ nhận diện heading như `PoC`, `Proof of Concept`,
   `Reproduction`, `Steps to Reproduce` hoặc `Exploit`.
3. CodeQL model là semantic model có cấu trúc, nhưng cần kết hợp với AST,
   CFG, call graph và data-flow của code đang scan.
4. `barrierModel`/`barrierGuardModel` thu từ docs là ví dụ chính thức, không
   được tự động coi là sanitizer của codebase đang scan hay hợp lệ trong mọi
   context.
5. Crawler chưa tự chạy PoC, chưa tự đánh giá exploitability và chưa crawl
   private repository.
6. Không tự dịch summary kỹ thuật bằng LLM để tránh tạo thêm hallucination;
   `summary_vi` hiện là nhãn tiếng Việt kèm nội dung nguồn.
7. Crawler hiện ưu tiên GitHub Advisory Database, GitHub references và CodeQL.
   Blog/PoC repository ngoài các reference đã công khai cần được duyệt nguồn
   trước khi thêm vào pipeline.

## Tái lập và kiểm tra sau khi crawl

Sau mỗi lần chạy, kiểm tra:

```powershell
python -m unittest discover -s tests -v
Get-Content .\data\reports\github_evidence.md
Get-Content .\data\reports\codeql_models.md
Get-Content .\data\processed\knowledge_base\manifest.json
```

Không commit `GITHUB_TOKEN`, file `.env`, hoặc dữ liệu private vào repository.
