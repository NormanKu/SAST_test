"""
模組 2 — FALSE NEGATIVE（漏報）— 未知的 Taint SOURCE
====================================================
以下程式「真的有 SQL injection」，但因為輸入來自自家框架的 payload()，
不在 Mend 預設 source 清單裡，所以資料流沒被追蹤，預設掃描不會報。
修法：把 payload 註冊為 Custom Taint Source，漏報就會現形。
"""
import sqlite3

from app.helpers.framework import MessageContext

conn = sqlite3.connect(":memory:", check_same_thread=False)


def handle_message(ctx: MessageContext):
    # ctx.payload() 是真正的 taint source（攻擊者可控），但掃描器不認得
    user_id = ctx.payload("user_id")
    # 真實 SQLi：字串拼接後直接執行
    row = conn.execute(
        "SELECT * FROM users WHERE id = '" + user_id + "'"
    ).fetchone()
    return row
