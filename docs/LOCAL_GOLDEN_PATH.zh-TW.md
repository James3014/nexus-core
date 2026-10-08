# Local Golden Path Contract（G0/G1）— 繁體中文

[English](https://github.com/James3014/nexus-core/blob/main/docs/LOCAL_GOLDEN_PATH.md) | **繁體中文**

這是提供一般 Python Git repository 外部使用者的 frozen contract。

使用者只需要安裝 Nexus Core 的 distribution：`nexus-certify`。Nexus-new、DevSpace、nexus-runtime、nexus-learning、nexus-open-swe-runtime、model routing，以及任何特定的人類或 agent author，都不是這條流程的必要組成。

product shell 會取得真實的 Git facts 與 verifier output，再建立既有 canonical `AcceptanceContract`、`ChangeSet`、`VerificationPlan` 與 `EvidenceBundle`。既有 generic verification adapter 是唯一的 factual verification authority。shell 不會建立第二套 verifier、policy、receipt、execution、routing、merge 或 certification authority。

## 第一次使用的完整流程

distribution identity 是 `nexus-certify`。支援的 public registry 安裝方式是：

```bash
python -m pip install nexus-certify
```

第一個公開版本 `nexus-certify==0.1.0` 已從 PyPI 安裝到全新環境，external-repository Golden Path 也已在 [Issue #36](https://github.com/James3014/nexus-core/issues/36) 驗收。

`nexus-certify==0.1.1` 後續也從公開 PyPI artifact 重新安裝並跑過 release acceptance，包括 LICENSE packaging、正向 `VERIFIED` 與 fail-closed negative case；release evidence 保存在 [PR #44](https://github.com/James3014/nexus-core/pull/44)。

在外部 repository 中，第一次使用流程是：

```bash
nexus-certify init \
  --base-ref main \
  --allow 'src/**' \
  --allow 'tests/**' \
  --verifier python -m pytest -q

nexus-certify doctor
nexus-certify check
```

如果 repository 希望共用 policy，可以 commit `.nexus-core/config.toml`。如果本機 verification records 不應 commit，則可忽略 `.nexus-core/receipts/`。

`init` 不會覆蓋既有 config；只有明確使用 `--force` 才會 override。由於 verifier arguments 可能以 `-` 開頭，因此 `--verifier` 與它後面的 argv 必須是 `init` 最後一組參數。

`doctor` 是唯讀。它會檢查：

- Git repository 是否可存取；
- config 是否有效；
- base ref 是否可解析；
- base 是否在目前 `HEAD` ancestry 中；
- Python / verifier 是否可用；
- repository cleanliness；
- Git 是否能發現變更。

`doctor` 不會 materialize tree，也不會執行 verifier。

`check` 不需要本機 HTTP service、bearer token 或 ledger。它會：

1. 把設定的 base 解析成 commit，要求它是目前 `HEAD` 的 ancestor，並解析 source tree；
2. 使用 isolated temporary Git index，把目前真實 worktree state materialize 成 target state，包含 committed、staged、unstaged 與 untracked changes，同時不修改 caller 的 HEAD、一般 index 或 worktree；
3. 從真實 Git object 推導 source-tree-to-target-tree manifest；
4. 把 allowed path glob 投影成 exact changed paths，再放入 canonical `AcceptanceContract`；
5. 直接執行設定的 argv（不透過 shell），擷取 exit code 與 output hash，並把 artifact hash 綁定到 canonical `EvidenceBundle`；
6. 呼叫既有 generic Core adapter，並在 `.nexus-core/receipts/` 寫入本機 verification receipt。

人類可讀 verdict 只會是：

```text
VERIFIED (not CERTIFIED)
```

或：

```text
FAILED_VERIFICATION (not CERTIFIED)
```

本機 verification receipt 是 inputs 與 Core response 的 durable、可重新計算紀錄。它不是 Completion Certification receipt，也不是 Candidate acceptance、merge approval、release approval 或 production claim。

## 最小 deterministic config

```toml
version = 1
base_ref = "main"
allowed_patterns = ["src/**", "tests/**"]
deletion_policy = "FORBID"
verifier_command = ["python", "-m", "pytest", "-q"]
timeout_seconds = 300
```

這份 config 故意不包含 executor、worker、model、route、approval、merge 或 certification identity。

config hash 會綁定 normalized config。path pattern 只屬於 product-shell acquisition policy；在 admitted run 中，它們會被投影成 exact changed paths，交給既有 canonical contract。

## 受信任的 config 來源

`check` 與 `issue-check` 只會讀取 worktree 的 config 來得知 `base_ref`，
實際生效的 config 則從 `base_ref` commit 讀取
（`git show <base>:.nexus-core/config.toml`）。其 `base_ref` 必須與 worktree
一致，否則以 `CONFIG_BASE_REF_MISMATCH` 失敗。Receipt 會記錄 `config_source`
（`{"kind": "base-ref", "commit": ..., "blob": ...}`）、worktree config hash
與 `config_drift`。因此在 worktree 放寬 `allowed_patterns` 不會產生任何效果。

若 base commit 沒有 config，會改用 worktree config，receipt 記錄
`config_source.kind = "worktree"`，CLI 會印出以下其中一行：

```text
config: trusted (<ref>@<sha>)
config: untrusted (not committed on <base_ref>)
```

若要拒絕 untrusted 情況，請加上 `--require-trusted-config`（或設定
`NEXUS_CERTIFY_REQUIRE_TRUSTED_CONFIG=1`），此時會以 `CONFIG_UNTRUSTED` fail closed：

```bash
nexus-certify check --repo . --require-trusted-config
nexus-certify issue-check --repo . --issue <NUMBER> --require-trusted-config
```

Config 的變更只有在合併進 base ref 之後才會生效（第 N 代在舊 config 下驗證，
第 N+1 代才使用新 config）。

## 隔離模式

Verifier 一律在 detached clone 中執行：沒有 remote、沒有 alternates
（`execution_subject.mode = isolated_detached_clone`），環境變數採 allowlist
（`PATH`、`LANG`/`LC_ALL`、`PYTHONDONTWRITEBYTECODE`、`PYTEST_ADDOPTS`，以及
sandbox 專用的 `HOME`/`TMPDIR`），並在獨立 process group 中執行，timeout 時整組終止。
可用 `env_passthrough` 額外開放變數名稱；receipt 只記錄名稱。除非明確列出，
`GITHUB_TOKEN` 與雲端憑證不會被 verifier 看到。

對於惡意或遭 injection 的 agent，建議使用 container 模式：

```toml
version = 2
base_ref = "origin/main"
allowed_patterns = ["src/**", "tests/**"]
deletion_policy = "FORBID"
env_passthrough = ["MY_TEST_FLAG"]   # names only; recorded in the receipt

[[verifiers]]
id = "tests"
command = ["uv", "run", "pytest", "-q"]
timeout_seconds = 300

[isolation]
mode = "container"          # "process" (default) | "container"
image = "ghcr.io/astral-sh/uv:python3.11-bookworm@sha256:<digest>"  # digest pin required
network = "bridge"          # "none" | "bridge" (default "bridge")
```

Container 模式以 `docker run --rm --network <network> --user <uid>:<gid>
-v <sandbox>:/work -w /work` 執行 verifier，只傳入 allowlist 環境變數，
sandbox 是唯一的 mount。Image 必須以 digest 固定；找不到 `docker` 時以
`ISOLATION_UNAVAILABLE` fail closed，非 digest image 則為 `INVALID_CONFIG`。
Receipt 會記錄 mode、image 與 network。`process` 模式無法限制呼叫者的 OS 權限。

## Fail-closed negative controls

遇到以下任何情況，`check` 都不會產生 `VERIFIED`：

- 不是 Git repository；
- 缺少或無效 config；
- base ref 無法解析；
- base commit 不在目前 `HEAD` ancestry；
- 相對 base 沒有任何變更；
- changed path 不符合任何 allowed pattern；
- `deletion_policy = "FORBID"` 時發生刪除；
- verifier 不存在、launch 失敗、timeout 或回傳非零 exit code；
- verifier 執行期間 target state 發生改變；
- canonical input malformed、cross-bound、stale、mismatched 或遭竄改；
- `CONFIG_UNTRUSTED`（使用 `--require-trusted-config` 但 base ref 上沒有已提交的 config）、`CONFIG_BASE_REF_MISMATCH`（base-ref config 與 worktree config 的 base ref 不一致），或 `ISOLATION_UNAVAILABLE`（要求 container 模式但 `docker` 不可用）；
- canonical Core 回傳任何非 `VERIFIED` 結果。

一般 verifier 的 result contract 刻意保持簡單：process 必須成功啟動、在 timeout 前完成，且 exit code 0 代表 `PASS`。

stdout / stderr 是 evidence bytes，不是第二套要被 parser 解讀的 result protocol。非零 exit code 是 canonical `FAILED_VERIFICATION`，不是 transport error。

## Durable receipt contract

repository-local receipt 包含：

- 已安裝的 product version 與 receipt schema version；
- UTC timestamp；
- exact source commit/tree 與 target tree；
- normalized config 與 config hash；
- physical manifest 與 manifest hash；
- verifier argv、exit code、captured output、hash 與 artifact hash；
- 完整 canonical request；
- 完整 Core response。

envelope hash 會涵蓋 envelope hash 自己以外的所有欄位。

保存的 request 可以在獨立流程中重新送回 generic adapter。

receipt validation 會重新計算 config、manifest、verifier artifact、envelope 與 Core response；如果 referenced Git objects 仍存在，也可以把 receipt 中的 manifest 與 repository 的真實 Git objects 再次比較。

## Published-artifact fresh-environment canary contract

只有在全新 temporary environment 中觀察到以下條件，G4 才能宣稱 fresh-environment canary 成立。環境中不得預先存在其他 Nexus sibling repository 或 Nexus service state。

1. 建立一般 Python Git repository，包含 base commit 與 feature change；
2. 建立全新 virtual environment，只安裝 candidate `nexus-certify` wheel 與外部 repository 自己宣告的 verifier dependencies；
3. 確認 import 與 executable path 都來自該環境，而不是 source checkout 或 sibling repository；
4. 完整執行文件中的 `init`、`doctor`、`check`；
5. 實際觀察 verifier 執行，並取得 canonical `VERIFIED`、非 certified 的 Core response；
6. 在新的 process 中重新讀取 receipt，重新計算 preserved hash、Core response 與 physical Git manifest；
7. 執行 forbidden path、forbidden deletion、verifier failure、tampered receipt 等 negative canary，全部都必須以文件定義的 typed reason fail closed；
8. 確認 acquisition 與 receipt validation 不會修改 HEAD、一般 Git index 或既有 worktree bytes。

這份 contract 已在 Issue #36 closure 對公開的 `nexus-certify==0.1.0` artifact 完整執行。

後續 `nexus-certify==0.1.1` 也重新做過公開 artifact install 與 bounded release acceptance。未來版本仍應重新執行相同類型的 regression checks；不能只因為前一版通過，就自動繼承 published-artifact canary 的結論。

## 三層治理階梯與交付就緒（Issue #83）

Nexus Core 明確規範三層治理階梯，各階梯之間嚴禁任何隱式自動晉升：

```text
Level 1: 程式碼變更驗證              VERIFIED / READY
                  |
                  | (明確的 runtime handoff verifier + 行程身份綁定)
                  v
Level 2: 人工測試交付就緒            HANDOFF_READY
                  |
                  | (Owner 人工審批 / 外部部署管線決策)
                  v
Level 3: 生產發布與部署              RELEASE / DEPLOY / PRODUCTION
```

### 1. Level 1 — Repository & Issue 驗證 (`VERIFIED` / `READY`)
- 指令：`nexus-certify check`, `nexus-certify issue-check`, `nexus-certify gate`
- Claim Ceiling: `REPOSITORY_VERIFIED_NOT_RELEASED` / `ISSUE_VERIFIED_NOT_RELEASED`
- 語意：靜態與自動化測試在乾淨的目標 Git 樹上全數通過，無範圍越界。
- 邊界：**`VERIFIED ≠ HANDOFF_READY`**。單元測試綠燈絕不代表 live 執行期服務已啟動、正確綁定或可供人工測試。

### 2. Level 2 — 執行期與人工測試交付就緒 (`HANDOFF_READY`)
- 指令：`nexus-certify handoff-init`, `nexus-certify handoff-check`, `nexus-certify handoff-status`
- Claim Ceiling: `MANUAL_TEST_HANDOFF_READY_NOT_RELEASED`
- Non-claims (封頂聲明):
  - `NO_CANDIDATE_ACCEPTANCE`
  - `NO_MERGE_AUTHORIZATION`
  - `NO_DEPLOYMENT_TRUTH`
  - `NO_OUTCOME_TRUTH`
  - `NO_PRODUCTION_READINESS`
  - `NO_SEMANTIC_BUG_FREEDOM`
- 語意：證明當前 exact verified code（`target_commit` / `target_tree`）確實運行於 live runtime 服務中，宣告的端點可連通、已配置的行程身份可取得且完成綁定，並且 consumer 自定義的 handoff verifier 成功退出（code 0）。若要求 prerequisite repository verification，該 repository receipt 必須能被獨立重新驗證，且其 target tree 必須等於目前 handoff 的 product tree；僅有舊的或遭竄改但文字仍寫著 `VERIFIED` 的 receipt 不足以成立。
- Config 綁定：normalized handoff config 會以 hash 綁入每張 handoff receipt。handoff ID、verifier command、timeout、prerequisite policy 或宣告服務任一變更，都會使先前 readiness receipt 失效。
- 行程身份：若 service 明確配置 `pid_file`，卻無法解析出仍存活的 PID，必須 fail-closed；不得靜默降級成只驗證 endpoint。
- 鮮度與失效語意（Fail-closed）：Git HEAD 漂移、工作區髒掉、handoff config 改變、行程重啟/更換 PID，或後續任一次 handoff 驗證失敗，前一次的 PASS receipt 立即失效；即使兩次嘗試發生在同一 wall-clock second，也不允許舊 PASS 冒充 current。
- 邊界：**`HANDOFF_READY ≠ RELEASE / DEPLOY / PRODUCTION`**。僅代表已就緒供 Owner 手動測試，不代表核准合併或部署生產。

### 3. Level 3 — 生產發布、部署與核准
- 僅由 Human Owner 或外部生產部署管線裁決。
- Core 絕不提供自動升級至 Level 3 的機制。
