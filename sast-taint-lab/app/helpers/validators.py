"""
專案自訂的驗證/淨化函式。
這些函式「實際上」讓資料變安全，但預設的 SAST 引擎並不知道它們是 sanitizer，
因此會產生 False Positive。用來練習註冊 Custom Taint Sanitizer。
"""

_ALLOWED_TABLES = {"users", "orders", "products"}


def ensure_allowed_table(name: str) -> str:
    """
    Allowlist 驗證：輸入若不在固定白名單內就直接拋錯。
    回傳值只可能是三個常數字串之一 -> 對 SQL 而言絕對安全。
    掃描器看到 user input 流進來卻不認得這是淨化，會誤報 CWE-89。
    """
    if name not in _ALLOWED_TABLES:
        raise ValueError(f"table not allowed: {name!r}")
    return name


_REGION_TO_DC = {"tw": "twn-dc1", "jp": "jpn-dc1", "sg": "sgp-dc1"}


def ensure_safe_region(region: str) -> str:
    """
    查表重映射：回傳的是硬編碼的機房代碼，原始 user 字串根本沒有流出去。
    真正到達 sink 的是常數，不是 tainted 資料。
    這是「解讀 FP」時最需要看穿的一種：追蹤『實際流到 sink 的值』而非變數名稱。
    """
    try:
        return _REGION_TO_DC[region]
    except KeyError:
        raise ValueError(f"unknown region: {region!r}")
