# Mend SAST Path Exclusions 參考清單(PCRE)

> ⚠️ **這不是可上傳的設定檔。** Mend SAST 的 Path Exclusions 依官方文件是在
> Code Scan Config → **Path Exclusions 分頁** 用 UI 逐筆新增,無檔案匯入機制。
> 本檔用途:(1) 從 §A 複製 PCRE 樣式、逐條貼進 UI;(2) 當作你套用了哪些排除、為什麼的存查文件。
>
> **格式:PCRE(Perl 相容正規表示式)路徑比對,不是 glob。** `.` 要跳脫成 `\.`。
>
> **操作位置:** Projects → 你的專案 → Code Scan Config → Path Exclusions 分頁 → 逐筆 Add → 完成後右上 Save。
> (Path Exclusions 不受 Global Config 指派限制,專案層級可自行增減。)

---

## ⚠️ 先讀:Path Exclusion 是雙面刃(套用前必想)

- **被排除的路徑「完全不掃」** → 那裡有真漏洞也永遠看不到。這是漏報,不是降噪。
- **只排除「不會上線、非攻擊面」的程式**:測試、產生碼、vendored 第三方、build 產物。
  應用程式碼、對外入口、部署會帶上的東西,**不要**排除。
- **regex 要盡量窄**:寬鬆的樣式會誤傷應用碼(例如想排 `/tests/` 卻連 `src/mytests_ctrl.py` 一起排掉)。
- **測試碼排除也有代價**:測試裡常藏 hardcoded secrets、危險範例——排掉等於不檢查這類。
- **先看預設清單**:Mend 已預先定義 build/library/test 的排除樣式。**先檢查、別重複**,只補缺的。
- 對「本 lab 的 fixtures/probe」而言,排除它們會**抵消實驗目的**;只在「實驗做完」或「lab 混在真實 repo 裡、不想污染真專案 findings」時才排。

---

## ❓ 兩個我無法從文件確認、你要在 UI 實測的點

1. **路徑字串的錨定基準未知**:文件沒寫 PCRE 比對的是「repo 相對路徑」「絕對路徑」還是「含不含開頭斜線」。
   所以我在 §A 用 `(^|/)` 開頭、盡量對兩種情況都成立。**請先貼一條、看它實際排掉什麼再全面套用。**
2. **全比對 vs 部分比對未知**:多數這類引擎是「路徑中任一處 match 即排除」(search 語意),但我沒有 Mend 的明確依據。
   若它其實是 full-match,下列多數樣式要在前後補 `.*`。**同樣以實測為準。**

---

## §A 可直接複製的 PCRE 樣式(每行一條,逐條貼進 UI)

```
# --- 本 lab 專用(實驗完成後再套用) ---
(^|/)sast-taint-lab/
probe_[^/]*\.py$

# --- 測試碼(先確認未與預設重複) ---
(^|/)tests?/
(^|/)test_[^/]*\.py$
[^/]*_test\.py$
(^|/)conftest\.py$

# --- 產生碼 / migrations ---
(^|/)migrations/
[^/]*\.pb\.py$
[^/]*_pb2\.py$

# --- 第三方 / vendored / 虛擬環境 ---
(^|/)(vendor|third_party|node_modules|site-packages)/
(^|/)\.venv/

# --- build 產物 / 壓縮檔 ---
(^|/)(build|dist|out)/
[^/]*\.min\.js$
```

---

## §B 逐條說明與風險

| PCRE 樣式 | 會排除什麼 | 為什麼 | 風險 / 注意 |
|---|---|---|---|
| `(^|/)sast-taint-lab/` | 整個 lab 目錄 | lab 是刻意留洞的診斷用碼,不該污染真專案 | **套用後 lab 內所有實驗都不再被掃**;做實驗時務必拿掉 |
| `probe_[^/]*\.py$` | `probe_*.py` 診斷探針 | 探針是一次性驗證用,結論拿到後即為噪音 | 只在對應探針實驗結束後套 |
| `(^|/)tests?/` | `test/`、`tests/` 目錄 | 測試碼通常非上線攻擊面 | 可能漏掉測試中的 hardcoded secrets;與預設清單勿重複 |
| `(^|/)test_[^/]*\.py$` | `test_*.py` | pytest 慣例測試檔 | 同上 |
| `[^/]*_test\.py$` | `*_test.py` | 另一種測試命名慣例 | 同上 |
| `(^|/)conftest\.py$` | pytest 設定檔 | 非應用邏輯 | 低 |
| `(^|/)migrations/` | DB migration | 多為框架產生、非手寫入口 | 若你在 migration 內寫了 raw SQL/指令,排除會漏掉 |
| `[^/]*\.pb\.py$` / `[^/]*_pb2\.py$` | protobuf 產生碼 | 機器產生、無人工邏輯 | 低 |
| `(^|/)(vendor\|third_party\|node_modules\|site-packages)/` | 第三方相依 | 非你的碼,應由 SCA 處理而非 SAST | 別把自寫但放這些目錄的碼一起排掉 |
| `(^|/)\.venv/` | 虛擬環境 | 純相依快照 | 低 |
| `(^|/)(build\|dist\|out)/` | build 產物 | 由原始碼產生的副本 | 若產物含手改碼則要留意 |
| `[^/]*\.min\.js$` | 壓縮 JS | 無法有意義分析、噪音高 | 對應原始 `.js` 仍會被掃(正確) |

> 表格內 `\|` 是為了在 Markdown 表格中顯示 `|`;貼進 Mend UI 時請用一般的 `|`(alternation)。
> 例如:`(^|/)(vendor|third_party|node_modules|site-packages)/`

---

## §C 套用後的驗證(一定要做)

1. **先貼一條、單獨套用、重掃**,確認它排掉的正是你要的路徑、沒誤傷應用碼。
2. 確認錨定/比對語意(§❓)後,再批次補上其餘。
3. 每套一條就記錄「樣式 + 理由」到本檔 §B,維持稽核軌跡(跟 FP triage SOP 同一套紀律)。
4. **反向檢查**:排除後,原本在應用碼路徑上的真 findings 數量不應改變;若掉了,代表你的 regex 誤傷了應用碼。
