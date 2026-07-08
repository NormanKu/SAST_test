"""
模組 1 — FALSE POSITIVE（誤報）
================================
以下兩段程式「實際上是安全的」，但預設掃描會標紅。
修法：把 validators 裡的函式註冊為 Custom Taint Sanitizer，誤報就會消失。
"""
import subprocess
import sqlite3

from flask import request

from app.helpers.validators import ensure_allowed_table, ensure_safe_region

conn = sqlite3.connect(":memory:", check_same_thread=False)


def list_records():
    """
    FP #1 — 疑似 SQL injection (CWE-89)，實際安全。
    table 經過 allowlist 驗證後只可能是三個常數之一。
    掃描器看到 request -> f-string -> execute 就報，但沒認出中間的淨化。
    -> 註冊 ensure_allowed_table 為 Custom Sanitizer 後應消失。
    """
    table = request.args.get("table", "users")
    table = ensure_allowed_table(table)
    query = f"SELECT id, name FROM {table} LIMIT 100"
    return conn.execute(query).fetchall()


def ping_region():
    """
    FP #2 — 疑似 OS command injection (CWE-78)，實際安全。
    ensure_safe_region 用查表回傳硬編碼機房代碼，原始 user 字串沒有流到 subprocess。
    這題重點：真正到 sink 的是常數，不是 tainted 值。
    -> 精準引擎可能自動清 taint；較保守的設定會誤報，需靠 Custom Sanitizer。
    """
    region = request.args.get("region", "tw")
    dc = ensure_safe_region(region)  # 例如 "twn-dc1"，永遠不是 raw input
    out = subprocess.run(["ping", "-c", "1", dc], capture_output=True)
    return out.stdout
