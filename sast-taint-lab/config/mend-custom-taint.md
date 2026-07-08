# Mend 自訂 Taint 設定對照表

> 設定路徑（依 Mend 官方文件，platform/latest）：
> - **專案層級**：Projects → 選專案 → 左側 Configuration 區 → **Code Scan Config** → **Language-Specific Configuration** 分頁 → 選 **Python**。
> - **全域層級**：右上齒輪 → **Administration** → **Code Scan Config** → Language-Specific Configuration 分頁。
>
> ⚠️ **注意**：若某專案已套用「Global Code Scan Configuration」，該專案能改的只剩
> Custom Sources / Taint Sinks / Taint Sanitizers 與 Path Exclusions；CWE 一律繼承全域設定。
>
> ✅ **已確認欄位**：Custom Taint **Sink** 對話框（見下）。
> ❓ **待你在畫面核對**：Custom **Source** 與 **Sanitizer** 對話框的確切欄位名，官方文件未完整揭露。
> 下方 Source/Sanitizer 的欄位是依「函式名 + 參數」的通用邏輯推得，請以你租戶實際畫面為準。

---

## 建議操作順序（一次驗一個變因）

1. **先跑一次 baseline 掃描，什麼都不加**，記錄 findings。對照 `expected-findings.md`：
   - 應該出現：模組 4 的 CASE 4（真漏洞），可能還有模組 1 的兩個「誤報」。
   - 不應出現卻可能出現：模組 1 的 FP。
   - 應該出現卻沒有：模組 2、模組 3 的漏洞（因為 source/sink 未知）。
2. 加一個設定 → 重掃 → 只比對那一項的差異 → 再加下一個。這樣才知道每個設定各自的效果。

---

## 1. Custom Taint Sanitizer（修 False Positive）

目標：讓模組 1 的兩個誤報消失。

| 要註冊的函式 | 說明 |
|---|---|
| `ensure_allowed_table` | allowlist 驗證，回傳值必為白名單常數 |
| `ensure_safe_region` | 查表重映射，回傳硬編碼機房代碼 |

欄位（依畫面填，通常為）：
- **Function Name**：`ensure_allowed_table`（第二筆再填 `ensure_safe_region`）
- 參數相關欄位：若要求填參數數量/淨化參數位置，兩者皆為 **1 個參數、第 1 個參數**。

> 驗證點：加完重掃，模組 1 的 CWE-89 / CWE-78 應該不再出現；模組 4 的真漏洞**仍在**。
> 若真漏洞也一起消失 → 你的 sanitizer 寫太寬，去看 §Pitfall。

---

## 2. Custom Taint Source（修 False Negative — 未知入口）

目標：讓模組 2 的 SQLi 現形。

- **Function Name**：`payload`（若畫面支援類別限定，填 `MessageContext.payload`）
- 若要指定「哪個回傳/參數帶 taint」：此函式的**回傳值**是 source。

> 驗證點：加完重掃，`fn_custom_source.py` 的 `handle_message` 應冒出 CWE-89。

---

## 3. Custom Taint Sink（修 False Negative — 未知危險函式）✅ 欄位已確認

目標：讓模組 3 的 SQLi 現形。以 `run_raw_sql(conn_name, sql, timeout)` 為例：

| 欄位 | 值 | 備註 |
|---|---|---|
| **Function Name** | `run_raw_sql` | 自訂危險函式名 |
| **Total Number of Parameters** | `3` | 函式預期參數總數 |
| **Vulnerable Parameter** | `2` | 危險參數位置，**從 1 起算**（sql 是第 2 個） |
| **Description** | `Executes raw SQL verbatim; 2nd arg is unsanitized` | 會顯示在 finding 的 data flow 裡 |
| **CWE Type** | `CWE-89`（SQL Injection） | 下拉選單 |

> 所有欄位皆為必填。
> 驗證點：加完重掃，`fn_custom_sink.py` 的 `search` 應冒出 CWE-89，且 data flow 會標到 `run_raw_sql` 的第 2 個參數。

---

## Pitfall（自我檢驗用）

- **Sanitizer 註冊太寬 = 製造漏報**：Pysa 官方也警告 sanitizer 會「移除所有 taint、不限特定規則」。
  若你把一個只對 SQL 安全的函式當成通用 sanitizer，XSS/命令注入的流可能被一起清掉。
  盡量讓 sanitizer 對應到具體的 source/sink 情境，而不是「這函式碰過就乾淨」。
- **Depth Settings**：模組 2、3 的資料流很短，預設深度即可；但真實專案若跨多層函式呼叫，
  Max. Function Depth / Max. Variable Copy 調太低也會造成漏報。這是「掃不到」時要先排除的變因。
