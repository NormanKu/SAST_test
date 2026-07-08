# SAST False Positive 判定與客戶說明 SOP

> 用途:遇到 taint 型(注入類)findings 時,快速判定是否為 FP、留下可稽核的判定理由、
> 並產出對客戶的說明。以 `probe_branch_barrier.py:53`(`alnum_only`)為本案範例。
> 適用:Mend SAST Gen2(Python/Java/C#/JS/TS)。其他工具原則相通,欄位名以各自為準。

---

## 0. 快速結論模板(先填這個,再展開)

- **Finding**:`<CWE>` `<類型>`,`<severity>` — `<檔案:行號>`
- **判定**:☐ True Positive(真漏洞) ☐ **False Positive(已驗證)** ☐ Not Exploitable(可利用性低,接受風險)
- **斷在哪一環**:☐ Source ☐ Propagation ☐ **Sanitization** ☐ Sink ☐ Reachability
- **一句話理由**:`<為什麼>`
- **處置**:☐ 註冊 Custom Sanitizer/Source/Sink ☐ 標記狀態 ☐ 改碼 ☐ Path Exclusion

---

## 1. FP 判定五環檢驗表

把每個 finding 拆成 taint 鏈五環,**任一環斷掉就是 FP,斷掉的那環就是「原因」**。

| 環節 | 要問的問題 | 斷掉 = FP 的典型情況 |
|---|---|---|
| 1. Source | 這輸入真的是攻擊者可控嗎? | env 變數/常數/內部設定被當成 source |
| 2. Propagation | 真正流到 sink 的是 tainted 值,還是衍生的常數? | 查表/白名單 → 值被換成常數 |
| 3. Sanitization | 中間有沒有**有效**淨化,只是引擎沒認出? | 自訂淨化(字元過濾、編碼)未被辨識 |
| 4. Sink | 這個 sink 在這情境真的危險嗎?標對參數了嗎? | 標錯 vulnerable parameter / 該函式其實無害 |
| 5. Reachability | 這條路徑真的跑得到嗎? | dead code、被 feature flag 關閉、不可達條件 |

---

## 2. 判定的黃金測試(唯一該用的標準)

> **試著構造一個「能通過每一步、且到 sink 還能造成傷害」的惡意輸入。**
> **舉得出 → 真漏洞;能證明這種輸入不存在 → FP。**

- 不要用「我覺得應該安全」判定 → 會漏掉真漏洞。
- 要用「我舉不出反例」證明 → 可驗證、可寫進報告。
- 關鍵心法:**「驗證(validation)」≠「淨化(sanitization)」。**
  只有當檢查/轉換**把值限縮到不可能是危險形式**時才算淨化。
  - 白名單成員檢查 → 值被限縮成常數 → 是淨化
  - 字元過濾/編碼轉換 → 字元集被限縮 → 是淨化
  - 長度檢查、型別檢查(與危險形式無關) → **不是淨化** → 仍是真漏洞

---

## 3. 本案判定:`probe_branch_barrier.py:53`(`alnum_only`)

### 3.1 結論
**已驗證的 False Positive。** Mend 的 Data Flow **路徑追蹤正確,只有最後「unsanitized」的結論錯誤**。
斷在**第 3 環(Sanitization)**:淨化發生在 `if ch.isalnum()`,但引擎不建模這個述詞對字元集的限縮。

### 3.2 Data Flow 逐節點解讀(對照 Mend 報告)

| # | 節點 | Mend 追蹤 | 判讀 |
|---|---|---|---|
| 1 | `request.args.get("q")` 取得外部輸入 | ✅ 正確,真 source | 環1 成立 |
| 2 | 指派給 `term` | ✅ 正確 | 環2 taint 有傳 |
| 3 | `term` 傳入 `alnum_only` 的參數 `x` | ✅ 正確,跨函式有追到 | — |
| 4 | `for ch in x` 逐字元迭代 | ✅ 正確 | — |
| 5 | `if ch.isalnum()` 過濾 → `"".join(...)` | ⚠️ **走過但沒給 credit** | **斷點:此處字元集被限縮,引擎沒建模** |
| 6 | return → 指派給 `t` | ✅ 追蹤正確,但 taint 標記未清除 | — |
| 7 | `"echo " + t` 字串串接 | ✅ 正確 | — |
| 8 | `os.system(...)` sink | ✅ 是真 sink,但結論「unsanitized」**錯誤** | 環3 已斷,不可利用 |

### 3.3 反例測試(證明不可利用)
`isalnum()` 只讓英數字通過。所有 shell 中繼字元(`;` `|` `` ` `` `$` `&` `(` `)` 空白 換行 …)
皆為非英數字,一律被濾除。故不論輸入為何,進入 `os.system` 的字串只可能是相連的英數字,
`echo` 永遠收到單一無害參數。**舉不出能存活又能執行第二條指令的輸入 → 不可利用 → 真 FP。**

### 3.4 ⚠️ 必記 caveat(措辭邊界)
Python 的 `str.isalnum()` 是 **Unicode-aware**:全形字、上標數字、其他語系字母都算 alnum、會通過。
- 對**本案的 shell sink** 不影響安全(那些字元對 `/bin/sh` 仍非中繼字元)。
- 但這代表 `alnum_only` 的保證是**「輸出無 ASCII shell 中繼字元」**,不是「輸出只有 `[a-zA-Z0-9]`」。
- **不要**把這個安全結論外推到「對特定 Unicode 敏感」的 sink(某些解析器/正規化流程)。
  報告與客戶說明措辭要對得起實際的淨化行為,否則邊界案例會站不住腳。

---

## 4. 客戶說明範本

### 4.1 三原則
1. **不要說「工具錯了/不準」** → 說「工具的保守是設計取捨」:寧可多報也不漏真漏洞。
2. **不要說「忽略就好」** → 展示你**驗證過**:說明為何不可利用 + 處置 + 稽核軌跡。
3. **用詞分清楚**:這是 **False Positive**(根本不是漏洞),不是「接受風險」。前者對客戶信心更好。

### 4.2 口頭版(白話,約 30 秒)
「掃描器把使用者從網址帶進來的輸入,一路追到一個會執行系統指令的函式,所以報了命令注入。
但這段輸入中間會先經過我們的過濾函式,把所有非英數字的符號去掉;能拿來注入指令的符號
(分號、管線、反引號那些)剛好都會被清掉,所以最後那個字串已經無法執行任何額外指令。
掃描器看得到資料流過去,但認不出這個過濾有效,才會誤報。我們已經把這個函式登記成掃描器
認得的淨化器,並把這筆標記為誤報、附上判定理由存查。」

### 4.3 書面版(繁中,可貼進報告/ticket)
> **Finding:** Command Injection (CWE-78), High — `probe_branch_barrier.py:53`
> **判定:** False Positive(已驗證)— 分析引擎未建模有效的輸入淨化。
>
> 掃描器正確追蹤到使用者可控輸入(HTTP 查詢參數 `q`)流經應用程式並進入 `os.system()`,
> 依其保守預設回報潛在命令注入。經檢視,該輸入在到達 shell 前會先通過移除所有非英數字字元
> 的淨化函式。由於輸出字串僅可能包含英數字,無法含有改寫或串接指令所需的任何 shell 中繼字元
> (`;`、`|`、`` ` ``、`$`、空白等),故無論輸入為何皆無法造成指令執行,此發現**不可利用**。
>
> **處置:** 已於 Mend 掃描設定中將該淨化函式註冊為 Custom Taint Sanitizer(Command Injection 類型),
> 使後續掃描能辨識此淨化;本筆標記為 False Positive 並保留上述理由供稽核。
>
> **補充:** 此為靜態分析工具為「降低漏報」而採取的預期行為——即使專案自有淨化,只要資料抵達
> 敏感函式仍會回報。本團隊對每一筆此類發現皆先驗證再處置。

### 4.4 書面版(英文,客戶報告常用;非語音情境才附)
> **Finding:** Command Injection (CWE-78), High — `probe_branch_barrier.py:53`
> **Determination:** False Positive (verified) — the analysis engine did not model an effective input sanitizer.
>
> The scanner correctly traced user-controllable input (HTTP query parameter `q`) flowing into `os.system()` and, following its conservative default, reported a potential command injection. On review, the input passes through a sanitizing function that removes all non-alphanumeric characters before reaching the shell. Because the resulting string can contain only alphanumeric characters, it cannot include any shell metacharacter required to alter or chain commands (`;`, `|`, `` ` ``, `$`, whitespace, etc.); the finding is therefore **not exploitable** for any input.
>
> **Remediation:** The sanitizing function has been registered as a Custom Taint Sanitizer (Command Injection type) in the Mend scan configuration so future scans recognize it; this finding is marked as a False Positive with the above rationale retained for audit.
>
> **Note:** This is expected behavior for a static analysis tool tuned to minimize false negatives — it reports data reaching a sensitive sink even when project-specific sanitization exists. Each such finding is verified before disposition.

---

## 5. 處置與稽核軌跡 Checklist

- ☐ 已用反例測試證明不可利用(而非「感覺安全」)
- ☐ 已在 SOP §0 填好判定摘要
- ☐ 若靠自訂淨化 → 已註冊 Custom Sanitizer,且 **Filtered Parameter 正確**
      (回傳值淨化填 `-1`;原地改參數填該參數位置;Type 選對 vuln 類型)
- ☐ 重掃已驗證:此筆消失、**其他真漏洞仍在**(未過度壓制)
- ☐ finding 狀態已標記 + 判定理由已留存
- ☐ caveat(如 Unicode 邊界)已在措辭中反映,未過度外推
