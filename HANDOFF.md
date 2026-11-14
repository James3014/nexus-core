# HANDOFF

更新：2026-11-14 · by Codex · HEAD `83c3b96`
<!-- 規則見 AGENTS.md「Handoff」。上限 150 行；過期內容移到 docs/archive/HANDOFF-YYYY-MM.md。 -->

## ▶ 下一步（只放一件，必須帶 #Issue）
#233 等 Nexus-new#1750 的 authority 來源設計定案後，再處理 runtime 將 authority/approval/signing 寫死為 True 的剩餘部分。

## 進行中
- 無。

## 待確認（沒有 Issue 號）
- trusted Git executable draft 已依 syn12 policy 改為 environment → root-protected admin config → absolute platform defaults；PATH shim 不參與 Git 選擇。helper 驗證 owner、caller write access、SHA-256 與版本，replacement-ref guards 保留；rev11-core 的 verifier 相對 PATH 預檢也按執行 cwd 修正。三個受影響測試模組 255 passed、1 skipped；五個新增 regression tests 在原始 HEAD 全部失敗、修正版全部通過。未提供 repository Issue，因此尚未執行 issue-init / issue-check，也不宣稱 Issue-bound engineering completion。

## 完成
- #243 已完成（PR #249）：local Golden Path 以 trusted base tip 綁定 config，使用唯一 merge-base 作為 source revision。
- #250 已完成（PR #253）：run 開始時 PR 已關閉回傳中性 `PR_ALREADY_CLOSED_SKIPPED`，不是 PASS。
- #231 已完成（PR #242）：receipt Sigstore bundle 驗證未通過時回 UNVERIFIABLE；schema v2。
- #238 已完成（PR #239）：本機 `check` / `issue-check` 支援 `--expect-config-commit`，未釘選的 base-ref 不標為 trusted。
- Golden Behavior Corpus（#236、#240）：56 個案例有測試覆蓋；執行方式：`uv run python scripts/golden_behavior_eval.py`。
- `test_verifier_timeout_kills_backgrounded_grandchildren` 會掃整台機器的 `sleep 31.7`；其他行程 argv 若含此字串，測試可能誤判。
- #46、#47、#51、#65 涉及產品、法務或發佈層級宣稱；需要 Owner 決定。
- nexus-core 只擁有 Evidence Trust 與 Completion；其他 carrying layer 不是額外真相權威。
