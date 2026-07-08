# Ground Truth：每段程式該不該被報

分兩欄看：**預設掃描（沒加任何自訂設定）** vs **正確結論（真相）**。
兩者不一致的地方，就是你要用自訂設定去修的「誤判」。

| 檔案 : 函式 | 預設掃描會怎樣 | 真相 | 誤判類型 | 用哪個設定修 |
|---|---|---|---|---|
| `fp_custom_sanitizer.py` : `list_records` | 報 CWE-89 | **安全**（allowlist） | False Positive | Custom **Sanitizer** |
| `fp_custom_sanitizer.py` : `ping_region` | 可能報 CWE-78 | **安全**（查表回常數） | False Positive | Custom **Sanitizer** |
| `fn_custom_source.py` : `handle_message` | 不報 | **有 SQLi** | False Negative | Custom **Source** |
| `fn_custom_sink.py` : `search` | 不報 | **有 SQLi** | False Negative | Custom **Sink** |
| `fp_gauntlet.py` : `dump_events` | 可能報 | **安全**（env 為營運者組態，非外部輸入） | False Positive | 判讀 / 例外 |
| `fp_gauntlet.py` : `get_user` | 可能報 CWE-89 | **安全**（`int()` 清 taint） | False Positive | 判讀 / Sanitizer(`int`) |
| `fp_gauntlet.py` : `legacy_export` | 可能報 CWE-78 | **安全**（dead code 不可達） | False Positive | 判讀 |
| `fp_gauntlet.py` : `open_report` | 報 CWE-78 | **真的有 command injection** | **True Positive（要修碼！）** | 不是誤報，改程式 |

> 重點：`open_report` 是唯一「該報且正確」的。做 FP triage 時，最危險的錯誤不是把 FP 當真的，
> 而是「看多了誤報後手滑，把這種真漏洞一起關掉」。


## 如何判讀一筆 finding 是不是 FP —— 五步決策

1. **Source 真的是攻擊者可控嗎？**
   - 環境變數、部署組態、內部常數 → 常是 FP（如 `dump_events`）。
   - HTTP 參數、佇列訊息、檔案內容、CLI 參數 → 是真 source。

2. **實際流到 sink 的『值』是 tainted 本身，還是衍生的常數？**
   - 查表 / 白名單 / 列舉重映射後，到 sink 的往往是常數 → FP（如 `ping_region`）。
   - 看變數名沒用，要看 data flow 面板上「最後進 sink 的那個值」從哪來。

3. **中間有沒有有效淨化，只是掃描器不認得？**
   - `int()`、allowlist、參數化查詢的自家包裝 → 若確實有效就是 FP，補 Custom Sanitizer。

4. **這條 flow 真的可達嗎？**
   - dead code、feature flag 關閉、不可能成立的條件 → FP（如 `legacy_export`）。
   - 但別把「我覺得不會有人這樣呼叫」當成不可達；要有程式上的保證。

5. **淨化是否對應到這個漏洞類型？**
   - HTML escape 擋 XSS，但擋不了 SQLi。淨化型別對不上 sink → 仍是真漏洞，不是 FP。

> 讀 Mend finding 時，直接看它的 **data flow 路徑**：source 那一格、每個 propagate 步驟、
> 到 sink 那一格。FP 幾乎都能在這條路徑上指出「哪一步其實已經安全 / 根本不是外部輸入」。
