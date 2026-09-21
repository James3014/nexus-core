# Nexus Core

[English](https://github.com/James3014/nexus-core/blob/main/README.md) | **繁體中文**

[![PyPI version](https://img.shields.io/pypi/v/nexus-certify.svg)](https://pypi.org/project/nexus-certify/)
[![Python versions](https://img.shields.io/pypi/pyversions/nexus-certify.svg)](https://pypi.org/project/nexus-certify/)
[![CI](https://github.com/James3014/nexus-core/actions/workflows/ci.yml/badge.svg)](https://github.com/James3014/nexus-core/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/James3014/nexus-core/blob/main/LICENSE)

**Nexus Core 會在你相信人類或 AI Agent 說「完成了」之前，先確認這次程式變更真的有對應到真實、最新，而且可重新驗證的證據。**

可獨立安裝的套件名稱是 **`nexus-certify`**。在本機 Golden Path 中，它可以直接用在一般 Git repository，不需要 Nexus-new、DevSpace、其他 Nexus 服務、模型供應商，也不需要 API token。

## 為什麼要用它

不論是 AI coding agent 或人類，都可能說某個修改「已完成」。Nexus Core 不直接相信這句話，而是檢查實際 repository 狀態與驗證證據。

在本機 repository 中，`nexus-certify check` 會：

1. 讀取真實的 Git source 與目前 worktree 狀態；
2. 強制套用你設定的允許路徑與刪除政策；
3. 執行你指定的真實 verifier，例如 `python -m pytest -q`；
4. 把 verifier 證據綁定到實際被檢查的 Git 狀態；
5. 交由 canonical Core verifier 產生事實性的驗證結果；以及
6. 寫入之後可以重新檢查的 durable receipt。

成功的本機驗證會顯示：

```text
VERIFIED (not CERTIFIED)
```

這個字樣是刻意區分的。**`VERIFIED` 不代表已核准、已合併、已發布、已部署、production-ready，也不代表 `CERTIFIED`。**

## 安裝

### 系統需求

- Python **3.11+**
- Git
- 你希望 Nexus Core 執行的 verifier，例如 `pytest`

建議使用 virtual environment。

```bash
python -m venv .venv

# macOS / Linux
source .venv/bin/activate

# Windows PowerShell
# .venv\Scripts\Activate.ps1

python -m pip install nexus-certify
nexus-certify --help
```

若要固定安裝目前這個公開版本：

```bash
python -m pip install nexus-certify==0.1.1
```

如果你要使用下方的 pytest 範例，請確認同一個環境中也有安裝 pytest：

```bash
python -m pip install pytest
```

PyPI：https://pypi.org/project/nexus-certify/

## 2 分鐘開始

請在你想驗證的 Git repository 根目錄執行：

```bash
nexus-certify init \
  --base-ref main \
  --allow 'src/**' \
  --allow 'tests/**' \
  --verifier python -m pytest -q

nexus-certify doctor
nexus-certify check
```

請依你的 repository 調整 `--allow` 規則。`--verifier` 與它後面的 argv 必須是 `init` 的最後一組參數。

正常情況下會看到類似：

```text
doctor: OK
verification: VERIFIED (not CERTIFIED)
receipt: .nexus-core/receipts/...
```

### 它會在你的 repository 裡寫入什麼

- `nexus-certify init` 會建立 `.nexus-core/config.toml`。
- `nexus-certify doctor` 是唯讀。
- `nexus-certify check` 會在 `.nexus-core/receipts/` 寫入驗證 receipt。

Nexus Core 會使用隔離的 temporary Git index 來 materialize 目標 Git 狀態。它的 acquisition path 不會 commit、checkout、merge、改寫 source file，也不會把檔案 stage 到你平常使用的 Git index。

你設定的 verifier 仍然是真實可執行程式，會以你目前 shell 使用者的權限執行。Nexus Core 直接呼叫設定好的 argv，不透過 shell，但你仍應只設定你信任的 verifier 指令。

## 安全性與隱私

針對本機 Golden Path（`init`、`doctor`、`check`）：

- 不需要 Nexus 帳號、API key、bearer token 或遠端 Nexus service；
- 本機驗證流程不會把 repository 內容或 verification receipt 上傳到 Nexus service；
- `doctor` 是唯讀；
- Git acquisition 使用 isolated temporary index，不會 stage 到一般 Git index；
- 除了你自己的 verifier 可能產生的檔案外，`check` 只會額外寫入自己的 receipt directory。

verifier 指令完全由你控制。它會在本機以你的使用者權限執行，所以應像審查其他測試或 build command 一樣先確認內容。

Nexus Core 使用 Apache-2.0 開源授權。套件相依性宣告在 [`pyproject.toml`](https://github.com/James3014/nexus-core/blob/main/pyproject.toml)，CI 會建立 wheel/sdist，並在乾淨環境執行 wheel installation smoke test。

關於完整的威脅模型、信任邊界、`VERIFIED` 宣告上限與安全漏洞回報流程，請參閱 [`SECURITY.md`](SECURITY.md)。

### 可選的安裝後檢查

```bash
python -m pip show nexus-certify
python -m pip check
nexus-certify --help
```

這些指令可以先確認套件名稱、依賴一致性與 CLI entry point，再開始對 repository 執行驗證。

## Nexus Core 會檢查什麼

當遇到以下情況，本機流程會採 fail-closed，不會回傳 `VERIFIED`：

- 缺少或無效的設定；
- base ref 無法解析，或不是目前 `HEAD` 的 ancestor；
- 有變更超出設定的 allow-list；
- deletion policy 禁止刪除時卻出現刪除；
- verifier 不存在、timeout 或回傳非零 exit code；
- 驗證期間 target state 發生變化；
- canonical input 或 receipt malformed、stale、mismatched 或遭竄改；
- canonical Core 結果不是 `VERIFIED`。

receipt 會綁定已安裝的 Nexus Core 版本、Git source/target identity、manifest、verifier evidence、canonical request、Core response 與完整性 hash。

精確行為與 negative controls 請看 [Local Golden Path Contract（繁中）](https://github.com/James3014/nexus-core/blob/main/docs/LOCAL_GOLDEN_PATH.zh-TW.md)。

## 為什麼你可以獨立評估它

Nexus Core 的設計目標，是讓「信任」不依賴修改程式的人自己說「有通過」。

- **Physical Git binding** — 驗證會綁定真實 Git commit/tree 與 deterministic manifest。
- **Real verifier evidence** — 設定的 verifier 會真的執行。
- **Freshness checks** — 已經不適用於最終內容的舊證據會被拒絕。
- **Tamper detection** — receipt 與 canonical input 都有 hash binding，可以重新檢查。
- **Fail-closed behavior** — 缺少或互相矛盾的證據不會被轉成綠燈。
- **Authority separation** — verification 不會偷偷變成 approval、merge、release 或 deployment authority。

公開的 `nexus-certify==0.1.1` 已從 PyPI 安裝到全新的環境，並對一般外部 repository 實際跑過正常與 fail-closed negative case。完整驗收紀錄可在 [PR #44](https://github.com/James3014/nexus-core/pull/44) 與 [Issue #36](https://github.com/James3014/nexus-core/issues/36) 查到。

## 目前成熟度

- **公開套件：** `nexus-certify`
- **目前 source release version：** `0.1.1`
- **Local Golden Path：** 已通過 published-artifact external-repository canary
- **License：** Apache-2.0
- **Python：** 3.11+
- **Generic HTTP ChangeSet interface：** experimental
- **Public protocol Stable：** 尚未宣稱

Local Golden Path 是外部使用者目前最簡單、最建議的入口。下方 HTTP/protocol 介面主要提供進階整合，目前仍屬 experimental，除非文件另外明確說明。

## 架構責任範圍

Nexus Core 擁有兩個 truth authorities：

- **Evidence Trust Core（證據信任核心）** — 負責 execution evidence 的 ingestion、normalization、verification、freshness 與 tamper detection。
- **Completion Core（完成判定核心）** — 負責 ChangeSet certification、deterministic verification reduction、evidence applicability 與 disposition enforcement。

acquisition、runtime、clients、ledger、adapters、benchmark instrumentation 等 carrying layers，不會因此變成額外 truth authority。

Nexus Core **不負責** agent execution、model routing、Workforce admission、merge approval、release approval、deployment 或 production authority。

## Generic ChangeSet Verification（experimental）

loopback HTTP runtime 提供 transport-neutral、非 GitHub 綁定的驗證介面，供 DevSpace、Open SWE 等 bounded consumer 使用：

- `GET /v1/protocol/generic-verification` — 回傳 authenticated protocol descriptor、JSON schemas、canonicalization rules、schema-bundle hash 與 cross-language conformance vectors。
- `POST /v1/changesets/verify` — 執行 deterministic `AcceptanceContract + ChangeSet + VerificationPlan + EvidenceBundle` verification。只有 caller 明確提供 policy facts 時，certification 才是可選的後續步驟。

Generic revision identity 使用 `git-commit:<40-lowercase-hex>` 或 `git-tree:<40-lowercase-hex>`。因此尚未 commit 的 managed change，也可以綁到 deterministic Git tree 後進行 verification，而不需要先建立 commit。generic `diff_hash` 綁定 canonical source-tree-to-target-tree manifest，而不是 pretty patch formatting。

`verification=VERIFIED` 不代表 `CERTIFIED`、Candidate acceptance、merge authorization、release、deployment 或 production readiness。這個介面也不負責選擇 execution lane、worker、model、route 或 workspace。

## Completion Evidence Applicability and Freshness Contract

`product.completion` 會把 completion claim 綁定到它聲稱完成的精確 source/artifact state，再判斷 verification evidence 是否真的適用於最終狀態。它是 deterministic、model-independent、advisory 的；completion claim 的 `asserted_by` 不會產生 authority，certification 仍由 `product.kernel.certify` 負責。

它會推導三個明確 semantic state：

- `CLAIMS_COMPLETE` — completion claim 的 revision 與 change set 的 `target_revision` 一致，且每個已變更、未刪除的 path 都有 claimed final content hash。
- `VERIFICATION_APPLIES` — 每個 required verifier 都有 evidence observation 綁定到變更 path、觀察到 claimed final content hash，且結果為 `PASS`。
- `CLAIMS_VERIFIED` — 上述兩個條件再加上既有 deterministic `verify()` reduction 的 conjunction。

每個 verifier 的 `EvidenceDisposition`（`ACCEPTED`、`REJECTED_STALE`、`REJECTED_IRRELEVANT`、`REJECTED_MISSING`、`REJECTED_CONTRADICTORY`、`REJECTED_FAILED`）會說明哪些 evidence 被接受或拒絕。

```python
from product.completion import analyze_completion_evidence, validate_completion_evidence_analysis

analysis = analyze_completion_evidence(claim, contract, change_set, plan, evidence)
assert analysis.claims_verified
assert validate_completion_evidence_analysis(analysis, claim, contract, change_set, plan, evidence)
```

freshness 是由 content hash comparison 推導，不是依賴 wall-clock timestamp。可參考 `tests/product/test_completion_evidence_applicability.py` 中的 `modify -> test PASS -> modify again` 與 irrelevant-verification regression。

## GitHub repository integration

若是 trusted same-repository GitHub `push` / `pull_request` event 且使用 self-hosted runner，請看 [GitHub Repository Golden Path](https://github.com/James3014/nexus-core/blob/main/docs/GITHUB_REPOSITORY_CHECK.md)。

這條路徑目前明確不支援 fork PR 與 GitHub-hosted runner。

## 開發

```bash
uv sync
uv run pytest -q tests/product
uv run pytest -q tests/benchmark
uv run ruff check product tests
uv run pyright product
uv run nexus-certify --help
```

## 相容性與共存

`nexus-core` 與 `Nexus-new` 裡目前的 `nexus-legacy` 套件，擁有不同的 package 與 console-script ownership：

- Nexus Core 對外 distribution 是 `nexus-certify`，內部仍擁有 `product` Python package 與 `nexus-certify` console script。
- `nexus-legacy` 擁有 `nexus`、`scripts` package 與 `nexus` console script。

由於兩個 repository 的 dependency set 與 operational role 不同，正常開發與測試應使用不同 virtual environment。

## 授權

Nexus Core（包含 `nexus-certify` distribution）採用 Apache License, Version 2.0。完整內容請看 [Apache-2.0 LICENSE](https://github.com/James3014/nexus-core/blob/main/LICENSE)。

從 `0.1.1` 起，wheel 與 source distribution 都會實際包含完整 Apache-2.0 `LICENSE`，CI 也會驗證這個 packaging invariant。
