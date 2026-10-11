# HANDOFF

更新：2026-10-11 · by Claude · HEAD `376b15d`
<!-- 規則見 AGENTS.md「Handoff」。上限 150 行；過期內容移到 docs/archive/HANDOFF-YYYY-MM.md。 -->

## ▶ 下一步（只放一件，必須帶 #Issue）
#203 確認 PR #214、#220（已合併）是否已滿足 #203 / #204 的驗收條件（負向測試在 enforcing sink 斷言被拒），符合就關單——兩張單仍開著，PR 用的是 Refs。

## 進行中
- #205：PR #214 刻意沒有改 runtime `verify_receipt`（SECURITY.md 已說明 receipt 未經驗證）；#220 只補了 HTTP e2e 對 FULL 驗證結果的斷言。runtime 部分仍需另外決定。

## 待確認（沒有 Issue 號）
- 無。

## 卡住 / 注意
- strict pyright 已完成（#173、#219）：`product/` 下除 3 個只有一行 docstring 的 `__init__.py` 外，每個模組都有 `# pyright: strict` 檔頭，strict 全掃 0 錯誤。全域 `pyproject.toml` 的 `typeCheckingMode` 刻意維持 `basic`（逐檔啟用，不動治理輸入）。新增模組請一併加上同一行檔頭。
- #148（重複的 freeze helper；benchmark 模組被打包進 wheel）仍開著。
- #46、#47、#51、#65 屬於產品、法務、發佈層級的 P1，涉及公開宣稱或 release，需要 Owner 決策。
- 本 repo 只擁有 Evidence Trust 與 Completion；其他 carrying layer 不是額外的真相權威。
