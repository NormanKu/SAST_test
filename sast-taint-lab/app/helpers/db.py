"""
自家 DB 輔助函式。
run_raw_sql() 的第 2 個參數 (sql) 會被原封不動地執行，
但 Mend 不知道這個 wrapper 是危險 sink -> False Negative。
用來練習註冊 Custom Taint Sink（並示範 Vulnerable Parameter 位置的填法）。
"""
import sqlite3

_POOL = {"primary": sqlite3.connect(":memory:", check_same_thread=False)}


def run_raw_sql(conn_name: str, sql: str, timeout: int = 30):
    """
    參數順序: (conn_name=第1個, sql=第2個, timeout=第3個)
    危險的是第 2 個參數。註冊 Custom Sink 時:
      Total Number of Parameters = 3
      Vulnerable Parameter       = 2
    """
    conn = _POOL[conn_name]
    return conn.execute(sql).fetchall()  # sql 未經處理直接執行
