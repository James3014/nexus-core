# HANDOFF

更新：2026-10-12 · by Claude · HEAD `8ef9b33`
<!-- 規則見 AGENTS.md「Handoff」。上限 150 行；過期內容移到 docs/archive/HANDOFF-YYYY-MM.md。 -->

## ▶ 下一步（只放一件，必須帶 #Issue）
#233 等 Owner 決定是否動工：runtime `verify_receipt` 改查 ledger 確認來源，政策條件改由 signer/authority 推導（authority 來源設計在 Nexus-new#1750）。目前限制已寫進 SECURITY.md、LEDGER_TRUST_MODEL.md，並有測試固定。

## 進行中
- 無工程中項目。剩下的開放單都在等 Owner 決定（見下）。

## 待確認（沒有 Issue 號）
- 無。

## 卡住 / 注意
- strict pyright 已完成（#173、#219）：`product/` 下除 3 個只有一行 docstring 的 `__init__.py` 外，每個模組都有 `# pyright: strict` 檔頭，strict 全掃 0 錯誤。全域 `pyproject.toml` 的 `typeCheckingMode` 刻意維持 `basic`（逐檔啟用，不動治理輸入）。新增模組請一併加上同一行檔頭。
- #231：Nexus Verify 改成必須驗 Sigstore 簽章才回 APPLIES/VERIFIED，屬公開協定＋安全邊界變更，等 Owner 決定。
- #46、#47、#51、#65 屬於產品、法務、發佈層級的 P1，涉及公開宣稱或 release，需要 Owner 決策。
- 本 repo 只擁有 Evidence Trust 與 Completion；其他 carrying layer 不是額外的真相權威。
