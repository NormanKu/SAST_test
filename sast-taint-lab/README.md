# SAST Taint Lab — 誤判驗證與自訂規則練習包

用途：在 Mend SAST（或任何 taint 型掃描器）上，親手製造並修正三種「誤判」，
並練習判讀 False Positive。可直接掛進你既有的 fixture / recall 驗證流程。

## ⚠️ 安全聲明
本包**故意包含可注入的漏洞碼**（`fn_custom_source.py`、`fn_custom_sink.py`、
`fp_gauntlet.py` 的 `open_report`），目的是驗證掃描器的漏報/召回。
**僅供本機或隔離環境掃描測試，切勿部署、切勿連到真實資料庫或對外服務。**
所有 DB 連線都用 `:memory:`，不會落地。

## 結構
```
sast-taint-lab/
├── README.md                     ← 你在這
├── expected-findings.md          ← 標準答案：每段該不該報、如何判讀 FP
├── config/
│   └── mend-custom-taint.md       ← 三種自訂規則的實際填法（Sink 欄位已確認）
└── app/
    ├── fp_custom_sanitizer.py     ← 模組1 False Positive（安全卻被報）
    ├── fn_custom_source.py        ← 模組2 False Negative（未知 source 漏報）
    ├── fn_custom_sink.py          ← 模組3 False Negative（未知 sink 漏報）
    ├── fp_gauntlet.py             ← 模組4 FP 判讀練習場（含 1 個真漏洞）
    └── helpers/                   ← 自訂 sanitizer / source / sink 的實作
```

## 建議流程
1. `pip install flask`（只為讓 import 成立；不需真的跑起來，SAST 是靜態分析）。
2. 用 Mend 掃這個資料夾，**先不加任何自訂設定**，存下 baseline findings。
3. 打開 `expected-findings.md` 對照：哪些是誤報、哪些是漏報、哪個是真漏洞。
4. 依 `config/mend-custom-taint.md` **一次加一個**設定、重掃、比對 diff：
   - Custom **Sanitizer** → 模組1 誤報應消失。
   - Custom **Source** → 模組2 漏洞應現形。
   - Custom **Sink** → 模組3 漏洞應現形。
5. 練 `fp_gauntlet.py`：自己判每一筆，再對答案。特別注意別把 `open_report` 當成 FP。

## 一個提醒
不同掃描器的精準度不同。模組1的 `ping_region`、模組4的 `get_user`（int 清 taint）
在 Mend Gen 2 的 Deep profile 下**有可能不會誤報**——那代表引擎夠精準，是好事。
若你要穩定重現誤報以練設定，可改用較保守的 profile，或把淨化寫得更「隱晦」一點。
