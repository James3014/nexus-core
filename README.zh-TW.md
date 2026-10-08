# Nexus Core

[English](https://github.com/James3014/nexus-core/blob/main/README.md) | **繁體中文**

[![PyPI version](https://img.shields.io/pypi/v/nexus-certify.svg)](https://pypi.org/project/nexus-certify/)
[![Python versions](https://img.shields.io/pypi/pyversions/nexus-certify.svg)](https://pypi.org/project/nexus-certify/)
[![CI](https://github.com/James3014/nexus-core/actions/workflows/ci.yml/badge.svg)](https://github.com/James3014/nexus-core/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/James3014/nexus-core/blob/main/LICENSE)

**只有當你事先宣告的驗收檢查，針對確切的程式樹（tree）全部通過，而且任何人都能驗證收據時，Agent 的變更才算完成。**

這個工具是名為 **`nexus-certify`** 的 Python 套件。它可以在一般 Git repository 中使用。本機指令不需要帳號、API key，也不需要任何網路服務。

## 目錄

- [安裝](#安裝)
- [5 分鐘開始（本機）](#5-分鐘開始本機)
- [管控 Agent 的 pull request](#管控-agent-的-pull-request)
- [設定檔參考](#設定檔參考)
- [收據](#收據)
- [VERIFIED 的意思](#verified-的意思)
- [安全模型](#安全模型)
- [開發](#開發)
- [授權](#授權)

## 安裝

需要 Python 3.11 以上與 Git。建議使用虛擬環境。

```bash
python -m venv .venv
source .venv/bin/activate    # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install nexus-certify
nexus-certify --help
```

PyPI：https://pypi.org/project/nexus-certify/

PyPI 上的版本是 `0.1.3`。`main` 分支已包含下文所述較新的受信任設定檔、隔離與簽章收據功能，之後會發布新版。在那之前，若需要這些功能，請從固定的 commit 安裝：

```bash
python -m pip install "git+https://github.com/James3014/nexus-core.git@d26204c394adae5b0d344f1cf06fd80c55d1a8a7"
```

## 5 分鐘開始（本機）

請在你要檢查的 Git repository 中執行。請先在分支上完成你的修改。`check` 會把你的工作與基準分支比較，若沒有任何變更就會失敗。

```bash
nexus-certify init \
  --base-ref main \
  --allow 'src/**' \
  --allow 'tests/**' \
  --verifier python -m pytest -q

nexus-certify doctor
nexus-certify check
```

- `init` 會寫入 `.nexus-core/config.toml`。請依你的 repository 調整 `--allow` 樣式。`--verifier` 必須是該行最後一個選項。
- `doctor` 只讀取、不寫入。它會告訴你缺少什麼。
- `check` 會在確切程式樹的乾淨副本上執行你的 verifier，並在 `.nexus-core/receipts/` 下寫入一份收據。

正常的輸出如下：

```text
verification: VERIFIED (not CERTIFIED)
config: untrusted (not committed on main)
receipt: .nexus-core/receipts/...
```

在你把 `.nexus-core/config.toml` commit 到基準分支之前，出現 `config: untrusted` 是正常的。下一節會說明為什麼這很重要。

在下列情況，`check` 會失敗，而且不會輸出 `VERIFIED`：

- 設定檔遺失或無效；
- 找不到基準 ref；
- 相對於基準沒有任何變更；
- 變更的路徑不在你的 `--allow` 樣式內；
- 有檔案被刪除，而刪除被禁止（預設即禁止）；
- verifier 不存在、逾時或以非零狀態結束；
- verifier 執行期間檔案發生變動。

你的 verifier 是真正的程式碼。它以你的權限執行，並且不經過 shell 直接啟動。請只設定你信任的指令。

## 管控 Agent 的 pull request

這是主要用途：Agent（或人）送出的 pull request，必須先有一項檢查證明變更通過了在工作開始前就已固定的驗收檢查，才能合併。

### 1. 先把設定檔 commit 到 main

先把 `.nexus-core/config.toml` 合併進你的基準分支。在 CI 中，設定檔是從基準分支讀取，絕不從 pull request 讀取。Agent 無法靠修改自己分支裡的設定檔來放寬檢查。

### 2. 開一個帶標記的 Issue

Issue 就是這項工作的合約。它必須包含一行指名確切設定檔的標記：

```bash
nexus-certify markers
```

```text
Issue body: <!-- NEXUS_CORE_EVIDENCE_UNIVERSE: sha256:<config hash> -->
```

把這行標記貼進 Issue 內文。這個指令是唯讀的。如果設定檔還沒 commit 到基準分支，它會在 stderr 印出警告，因為 commit 之後雜湊值會改變。

### 3. 開一個帶標記的 pull request

Pull request 內文必須剛好包含一個指名該 Issue 的標記：

```bash
nexus-certify markers --issue 42
```

```text
Issue body: <!-- NEXUS_CORE_EVIDENCE_UNIVERSE: sha256:<config hash> -->
PR body:    <!-- NEXUS_CORE_ISSUE: 42 -->
```

把 `PR body` 那一行貼進 pull request 描述。加上 `--json` 可取得機器可讀的輸出，欄位為 `config_hash`、`config_source`、`issue_marker` 與 `pr_marker`。

你也可以先在本機試試 Issue 綁定：

```bash
nexus-certify issue-init --issue 42
nexus-certify issue-check --issue 42 --require-trusted-config
```

`issue-init` 會凍結目前開啟中的 Issue 文字。如果 Issue 沒有證據標記，它會印出提示，指向 `nexus-certify markers`。`issue-check` 會重新讀取 Issue，若文字自綁定後已改變就會失敗。

### 4. 加入兩個 job 的 workflow

把 [`docs/examples/github-repository-check.yml`](docs/examples/github-repository-check.yml) 複製到 `.github/workflows/`。把 `expected-identity` 中的 `OWNER/REPO` 換成你的 repository，並讓 workflow 檔名保持一致。範例把兩個 action 都固定在這個 commit：

```text
d26204c394adae5b0d344f1cf06fd80c55d1a8a7
```

一律固定到完整的 40 字元 commit，不要使用 tag 或分支。

這個 workflow 有兩個 job：

- **`run`** 使用 `James3014/nexus-core/.github/actions/issue-gate@<sha>`。它先安裝固定版本的工具，接著在容器內執行基準分支設定檔所指定的 verifier。然後以 Sigstore keyless 簽章簽署收據並上傳。它需要 `id-token: write`。
- **`verify`** 使用 `James3014/nexus-core/.github/actions/receipt-verify@<sha>`。它沒有寫入權限，也看不到 pull request 的程式碼。它會檢查簽章，再檢查收據是否符合這個確切的 head、這份基準設定檔與這個 Issue。

這個 workflow 必須在 `pull_request_target` 上執行，並且會略過來自 fork 的 pull request。完整說明：[`docs/GITHUB_REPOSITORY_CHECK.md`](docs/GITHUB_REPOSITORY_CHECK.md)。

在 GitHub-hosted runner 上，你的設定檔需要啟用容器隔離。請見[設定檔參考](#設定檔參考)。

### 5. 設為必要檢查

在你的 branch protection 或 ruleset 中，把名為 **`Nexus Core issue completion`** 的狀態檢查（也就是 `verify` job）設為必要。它的意思是：

> 由這個 repository 的 main 分支 workflow 身分簽署的收據，描述的正是這個 head、這份基準設定檔、這個 Issue，並且結果為 VERIFIED。

對 workflow、action 釘選版本或設定檔的變更，會依舊規則檢查，並且只有在經過一般審查合併後才會生效。

## 設定檔參考

`nexus-certify init` 會寫入版本 1 的設定檔。本機使用已經足夠：

```toml
version = 1
base_ref = "main"
allowed_patterns = ["src/**", "tests/**"]
deletion_policy = "FORBID"
verifier_command = ["python", "-m", "pytest", "-q"]
timeout_seconds = 300
```

| 欄位 | 意思 |
| --- | --- |
| `base_ref` | 用來與你的變更比較的分支。受信任的設定檔從這裡讀取。 |
| `allowed_patterns` | 變更可以碰觸的路徑。其他路徑會使檢查失敗。 |
| `deletion_policy` | `FORBID`（預設）或 `ALLOW`。 |
| `verifier_command` | 要執行的指令，以清單表示。不會經過 shell。結束碼 0 代表通過。 |
| `timeout_seconds` | 超過這段時間 verifier 會被終止。 |

### 版本 2：多個具名檢查

版本 2 讓你可以要求多項各自獨立的證據、設定環境，並在容器中執行。你需要手寫：

```toml
version = 2
base_ref = "main"
allowed_patterns = ["src/**", "tests/**"]
deletion_policy = "FORBID"
universe_generation = 1
materials = []
env_passthrough = ["MY_TEST_FLAG"]

[[verifiers]]
id = "tests"
command = ["uv", "run", "pytest", "-q"]
timeout_seconds = 300
logical_subject_id = "app/tests"
evidence_kind = "test-result"
requirement_mode = "REQUIRED"
applicability = "APPLICABLE"

[isolation]
mode = "container"
image = "ghcr.io/astral-sh/uv:python3.11-bookworm@sha256:<64 hex digits>"
network = "bridge"
```

- **`[[verifiers]]`**：每個項目是一項必要檢查，有自己的 id 與結果。缺少或失敗的必要檢查，就不會得到 `VERIFIED`。
- **`materials`**：選用的指令，用來記錄外部相依項目的確切身分，例如解析後的修訂版本。請見 [`docs/MULTI_EVIDENCE_GOLDEN_PATH.md`](docs/MULTI_EVIDENCE_GOLDEN_PATH.md)。
- **`universe_generation`**：當你修改必要檢查的清單時，要調高的數字。
- **`env_passthrough`**：verifier 可以看到的環境變數名稱。預設它只看得到 `PATH`、`LANG`/`LC_ALL`、`PYTHONDONTWRITEBYTECODE`、`PYTEST_ADDOPTS`，以及私有的 `HOME` 與 `TMPDIR`。除非你列出，否則 token 與雲端憑證都不可見。收據只記錄名稱，絕不記錄值。
- **`[isolation]`**：
  - `mode`：`process`（預設）或 `container`。對於你不完全信任的 Agent，請使用 `container`。它需要 `docker`。若找不到 `docker`，執行會以 `ISOLATION_UNAVAILABLE` 失敗。
  - `image`：必須以 digest（`@sha256:...`）固定。只有 sandbox 目錄會被掛載進容器。
  - `network`：`bridge`（預設）或 `none`。

### 受信任的設定檔來源

`check` 與 `issue-check` 只會讀取 worktree 中的設定檔來得知 `base_ref`，接著使用已 commit 在該基準 ref 上的設定檔。輸出會告訴你用的是哪一份：

```text
config: trusted (main@<commit>)
config: untrusted (not committed on main)
```

若要拒絕未受信任的情況，請加上 `--require-trusted-config`（或設定 `NEXUS_CERTIFY_REQUIRE_TRUSTED_CONFIG=1`）。此時執行會以 `CONFIG_UNTRUSTED` 失敗。

```bash
nexus-certify check --require-trusted-config
```

更多資訊：[`docs/LOCAL_GOLDEN_PATH.zh-TW.md`](docs/LOCAL_GOLDEN_PATH.zh-TW.md)（[English](docs/LOCAL_GOLDEN_PATH.md)）。

## 收據

每次執行都會在 `.nexus-core/receipts/` 下寫入一份 JSON 收據。收據記錄工具版本、基準與 head 的 commit、檔案清單、設定檔及其來源、每個 verifier 指令與其結束碼和輸出、結果，以及涵蓋以上全部內容的雜湊值。重新驗證收據即可偵測任何修改。

把收據綁定到某個確切對象的欄位：

| 欄位 | 意思 |
| --- | --- |
| `subject_head` | 被檢查的 commit（`git-commit:<sha>`）。 |
| `subject_head_tree` | 該 commit 的 tree（`git-tree:<sha>`）。 |
| `subject_clean` | 被檢查的 tree 等於該 commit 的 tree 時為 true，代表沒有納入任何未 commit 的內容。 |
| `config_source` | 設定檔的來源：`base-ref`（附 commit 與 blob）或 `worktree`。 |

不重新執行 verifier，也能檢查收據：

```bash
nexus-certify receipt-check --receipt .nexus-core/receipts/<receipt>.json
```

加上期望條件可使檢查更嚴格。不符時會以結束碼 2 退出，並指出原因：

| 旗標 | 不符時的原因碼 |
| --- | --- |
| `--expect-status VERIFIED` | `STATUS_MISMATCH` |
| `--expect-subject-head <40-hex>` | `SUBJECT_HEAD_MISMATCH` |
| `--expect-target-tree <40-hex>` | `TARGET_TREE_MISMATCH` |
| `--expect-config-commit <40-hex>` | `CONFIG_SOURCE_MISMATCH` |
| `--expect-issue <N>` | `ISSUE_BINDING_MISMATCH` |
| `--expect-github-repository owner/name` | `ISSUE_BINDING_MISMATCH` |
| `--require-clean-subject` | `SUBJECT_NOT_CLEAN` |
| `--require-trusted-config` | `CONFIG_UNTRUSTED` |

磁碟上的收據可以被任何有檔案存取權的人取代。CI 中產生的收據，則由 workflow 身分以 Sigstore keyless 簽章（`sigstore==4.5.0`）簽署：

```text
https://github.com/OWNER/REPO/.github/workflows/<file>.yml@refs/heads/main
```

若要手動驗證，請從 workflow 執行中下載 `nexus-core-receipts-<head-sha>` artifact。其中包含 `<receipt>.json` 與 `<receipt>.json.sigstore.json`。接著執行：

```bash
uvx --from "sigstore==4.5.0" sigstore verify github \
  --cert-identity "https://github.com/OWNER/REPO/.github/workflows/<file>.yml@refs/heads/main" \
  --repository OWNER/REPO \
  --bundle <receipt>.json.sigstore.json \
  <receipt>.json

TREE=$(git rev-parse '<head-sha>^{tree}')
nexus-certify receipt-check --receipt <receipt>.json \
  --expect-status VERIFIED \
  --expect-subject-head <head-sha> \
  --expect-target-tree "$TREE" \
  --expect-config-commit <base-sha> \
  --expect-issue <N> \
  --expect-github-repository OWNER/REPO \
  --require-clean-subject \
  --require-trusted-config
```

只要改動收據的任何一個位元組，`sigstore verify` 就會失敗。簽章也會記錄在公開的 Rekor 透明度日誌中。

## VERIFIED 的意思

`VERIFIED` 的意思是：基準分支設定檔中宣告的檢查，在設定的隔離環境內，針對這個確切的程式樹全部通過。輸出刻意一律註明 `(not CERTIFIED)`。

它不代表：

- Issue 真的完成了（測試全綠只證明測試有檢查到的內容）；
- 程式碼正確、安全或沒有漏洞；
- 變更已被核准、合併、發布或部署；
- verifier 是在完美的 sandbox 中執行；
- 相依套件是安全的。

你仍然需要審查變更並決定是否合併。`VERIFIED` 是供你做決定的證據，不是決定本身。

## 安全模型

- Verifier 是可執行的程式碼。在 `process` 模式下，它擁有你的使用者權限，而且不是作業系統層級的 sandbox。對於你不信任的 Agent，請使用 `container` 模式。
- Verifier 在沒有 remote 的 detached clone 中執行，因此無法透過 Git 回頭存取你的 repository。
- 在 CI 中，設定檔來自基準分支；工具在 runner 上出現任何 pull request 程式碼之前就已安裝；runner 也絕不在容器之外安裝或建置 pull request 的程式碼。
- 來自 fork 的 pull request 不在此 gate 的涵蓋範圍內。
- 本機指令不會上傳任何東西。

威脅模型、信任邊界與漏洞回報方式：[`SECURITY.md`](SECURITY.md)。

## 開發

```bash
uv sync
uv run pytest -q tests/product
uv run ruff check product tests
uv run pyright product
uv run nexus-certify --help
```

其他文件：

- [`docs/GITHUB_REPOSITORY_CHECK.md`](docs/GITHUB_REPOSITORY_CHECK.md)：完整的 pull request gate 說明，並附有新 repository 的六步驟檢查清單。
- [`docs/RUNTIME_HANDOFF.md`](docs/RUNTIME_HANDOFF.md)：檢查程式碼是否在實際執行環境中運行（`handoff-init`、`handoff-check`、`handoff-status`）。
- [`docs/COEXISTENCE.md`](docs/COEXISTENCE.md)：與 `nexus-legacy` 並存使用。

## 授權

Apache License 2.0。請見 [LICENSE](https://github.com/James3014/nexus-core/blob/main/LICENSE)。Wheel 與原始碼發行檔都包含完整的授權檔。
