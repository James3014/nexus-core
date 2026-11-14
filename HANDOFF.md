# HANDOFF

更新：2026-11-15 · by Codex · HEAD `9ef81b3`
<!-- 規則見 AGENTS.md「Handoff」。上限 150 行；過期內容移到 docs/archive/HANDOFF-YYYY-MM.md。 -->

## ▶ 下一步（只放一件，必須帶 #Issue）
#233 等 Nexus-new#1750 的 authority 來源設計定案後，再處理 runtime 將 authority/approval/signing 寫死為 True 的剩餘部分。

## 進行中
- 無。

## 待確認（沒有 Issue 號）
- trusted Git 架構修正：acquisition/client 使用各自層級 helper，維持 env allowlist 與 repo-local execution config 防護；五個指定回歸測試通過，三個指定 product modules 259 passed、1 skipped。全套 pytest 單次執行為 2345 passed、6 skipped、1 deselected、14 failed、63 errors；loopback server 測試受 sandbox 拒絕 bind (`PermissionError: [Errno 1] Operation not permitted`)。未提供 repository Issue，未執行 issue-init / issue-check。

## 完成
- #243 已完成（PR #249）：local Golden Path 以 trusted base tip 綁定 config，使用唯一 merge-base 作為 source revision。
- #250 已完成（PR #253）：run 開始時 PR 已關閉回傳中性 `PR_ALREADY_CLOSED_SKIPPED`，不是 PASS。
- #231 已完成（PR #242）：receipt Sigstore bundle 驗證未通過時回 UNVERIFIABLE；schema v2。
- #238 已完成（PR #239）：本機 `check` / `issue-check` 支援 `--expect-config-commit`，未釘選的 base-ref 不標為 trusted。
- Golden Behavior Corpus（#236、#240）：56 個案例有測試覆蓋；執行方式：`uv run python scripts/golden_behavior_eval.py`。
- `test_verifier_timeout_kills_backgrounded_grandchildren` 會掃整台機器的 `sleep 31.7`；其他行程 argv 若含此字串，測試可能誤判。
- #46、#47、#51、#65 涉及產品、法務或發佈層級宣稱；需要 Owner 決定。
- nexus-core 只擁有 Evidence Trust 與 Completion；其他 carrying layer 不是額外真相權威。
