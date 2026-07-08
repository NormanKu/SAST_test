"""
模組 3 — FALSE NEGATIVE（漏報）— 未知的 Taint SINK
==================================================
以下程式「真的有 SQL injection」，但 tainted 資料流進的是自家 wrapper
run_raw_sql()，Mend 不知道它的第 2 個參數是危險 sink，所以預設掃描不會報。
修法：把 run_raw_sql 註冊為 Custom Taint Sink（Vulnerable Parameter = 2）。
"""
from flask import request

from app.helpers.db import run_raw_sql


def search():
    term = request.args.get("q", "")
    # tainted 字串拼進 SQL
    sql = "SELECT * FROM products WHERE name LIKE '%" + term + "%'"
    # 流進未被辨識的 sink；危險參數是第 2 個 (sql)
    return run_raw_sql("primary", sql, 30)
