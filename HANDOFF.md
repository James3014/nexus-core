# HANDOFF

更新：2026-11-15 · by Codex · HEAD `c877378`
<!-- 規則見 AGENTS.md「Handoff」。上限 150 行；過期內容移到 docs/archive/HANDOFF-YYYY-MM.md。 -->

## ▶ 下一步（只放一件，必須帶 #Issue）
#233 等 Nexus-new#1750 的 authority 來源設計定案後，再處理 runtime 將 authority/approval/signing 寫死為 True 的剩餘部分。

## 進行中
- 無。

## 待確認（沒有 Issue 號）
- trusted Git structural fix (PR #317 follow-up): shared guard scans nested `.git` entries, allows only known local config keys case-insensitively, permits only `GIT_INDEX_FILE` from caller extras, and pins commit-graph off after caller config. Python interpreter lookup rejects all `env` paths and prevents versioned interpreter names from resolving through PATH. Regression set: `tests/product/test_trusted_git_structure.py` 103 passed. Six-file core set: 541 passed, 2 skipped, 38 architecture fixture errors because loopback binds are denied (`PermissionError: [Errno 1] Operation not permitted`). The new regression subset was red against the original guard (54 failed, 4 passed), then green after the fix. `git diff --check` clean. No repository Issue supplied; issue-init / issue-check not run.

## 完成
- #243 已完成（PR #249）：local Golden Path 以 trusted base tip 綁定 config，使用唯一 merge-base 作為 source revision。
- #250 已完成（PR #253）：run 開始時 PR 已關閉回傳中性 `PR_ALREADY_CLOSED_SKIPPED`，不是 PASS。
- #231 已完成（PR #242）：receipt Sigstore bundle 驗證未通過時回 UNVERIFIABLE；schema v2。
- #238 已完成（PR #239）：本機 `check` / `issue-check` 支援 `--expect-config-commit`，未釘選的 base-ref 不標為 trusted。
- Golden Behavior Corpus（#236、#240）：56 個案例有測試覆蓋；執行方式：`uv run python scripts/golden_behavior_eval.py`。
- `test_verifier_timeout_kills_backgrounded_grandchildren` 會掃整台機器的 `sleep 31.7`；其他行程 argv 若含此字串，測試可能誤判。
- #46、#47、#51、#65 涉及產品、法務或發佈層級宣稱；需要 Owner 決定。
- nexus-core 只擁有 Evidence Trust 與 Completion；其他 carrying layer 不是額外真相權威。
