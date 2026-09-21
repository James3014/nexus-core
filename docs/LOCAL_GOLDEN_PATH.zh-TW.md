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
