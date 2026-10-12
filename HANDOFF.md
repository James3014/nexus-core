# HANDOFF

更新：2026-10-13 · by Claude · HEAD `cfcf147`
<!-- 規則見 AGENTS.md「Handoff」。上限 150 行；過期內容移到 docs/archive/HANDOFF-YYYY-MM.md。 -->

## ▶ 下一步（只放一件，必須帶 #Issue）
#243 issue gate 診斷改善：`BASE_REF_NOT_ANCESTOR` 要用最新 base 還是 merge-base，等 Owner 決定；之後讓錯誤訊息直接印出 rebase 目標與正確的 evidence-universe marker。

## 進行中
- 無工程中項目。

## 待確認（沒有 Issue 號）
- Nexus Verify 的 Sigstore 驗證沒有做成 `[verify]` extra：改 `uv.lock` 會破壞 `python-oci-pytest-v1` 的鎖定 digest。要加 extra 必須同時重新釘選該 profile。

## 卡住 / 注意
- #231 已完成（PR #242）：Nexus Verify 只有在 receipt 的 Sigstore bundle 驗證通過時才回 APPLIES/VERIFIED（簽署者：subject repo 的 `nexus-core-issue-completion.yml@refs/heads/main`），否則回 UNVERIFIABLE（`RECEIPT_NOT_AUTHENTICATED` / `RECEIPT_AUTHENTICATION_UNAVAILABLE`）。沒有安裝 `sigstore` 時一律 fail-closed。schema 升為 v2。
- #238 已完成（PR #239）：本機 `check` / `issue-check` 新增 `--expect-config-commit`；沒有釘選的 base-ref 標成 `base-ref, unpinned`，不再標 `trusted`。屬安全邊界變更，Owner 已同意（記錄在 #238）。
- Golden Behavior Corpus（#236、#240）：56 個案例全部有測試覆蓋，沒有剩下的 finding。執行方式：`uv run python scripts/golden_behavior_eval.py`。
- `test_verifier_timeout_kills_backgrounded_grandchildren` 會掃整台機器的 `sleep 31.7`。如果別的行程的 argv 剛好含這段文字，測試會誤判失敗。
- #233 剩下的「政策條件」部分（runtime 把 authority/approval/signing 寫死為 True）：等 Nexus-new#1750 的 authority 來源設計定案再做，Owner 已決定先不動。
- strict pyright：`product/` 下每個模組都要有 `# pyright: strict` 檔頭，新增模組也要加。全域 `typeCheckingMode` 刻意維持 `basic`。
- #46、#47、#51、#65 是產品、法務、發佈層級的 P1，涉及公開宣稱或 release，需要 Owner 決定。
- 本 repo 只擁有 Evidence Trust 與 Completion；其他 carrying layer 不是額外的真相權威。
