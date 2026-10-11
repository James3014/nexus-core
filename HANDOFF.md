# HANDOFF

更新：2026-10-11 · by Claude · HEAD `e5234e7`
<!-- 規則見 AGENTS.md「Handoff」。上限 150 行；過期內容移到 docs/archive/HANDOFF-YYYY-MM.md。 -->

## ▶ 下一步（只放一件，必須帶 #Issue）
#203 讓 PR #214（trusted config、Nexus Verify applicability、issue repository 改綁非 candidate 輸入）通過 Core issue gate 並落地——依據：最新活動（10/11）、`bug` 標籤；candidate 可控的 `base_ref` 會讓 `--require-trusted-config` 失效，是 Evidence Trust 的核心 invariant。

## 進行中
- #203、#204、#205 / PR #214：mergeable_state=clean，但「Nexus Core issue completion」「Nexus Core issue run」兩項檢查紅燈。PR 使用 Refs，issue 要等驗證後才關。

## 待確認（沒有 Issue 號）
- #173（strict pyright）已關閉，phase 1–9 都已合併；全域 `typeCheckingMode` 是否已經從 basic 切到 strict，還沒查證。

## 卡住 / 注意
- PR #214 刻意沒有改 #205 的 runtime `verify_receipt` 部分（SECURITY.md 已說明 receipt 沒有經過驗證），所以 #205 可能需要另外決定。
- #148（重複的 freeze helper；benchmark 模組被打包進 wheel）仍開著，10/11 有更新。
- #46、#47、#51、#65 屬於產品、法務、發佈層級的 P1，涉及公開宣稱或 release，需要 Owner 決策。
- 本 repo 只擁有 Evidence Trust 與 Completion；其他 carrying layer 不是額外的真相權威。
