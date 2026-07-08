"""
模擬一個「自家訊息匯流排框架」。
ctx.payload() 回傳的是從外部佇列拉進來的、攻擊者可控的資料 —— 這是真正的 taint source，
但它不在 Mend 預設的 source 清單裡，所以資料流不會被追蹤 -> False Negative。
用來練習註冊 Custom Taint Source。
"""


class MessageContext:
    def __init__(self, raw: dict):
        # raw 來自外部佇列（Kafka / RabbitMQ 之類），內容不可信
        self._raw = raw

    def payload(self, key: str) -> str:
        """回傳攻擊者可控的欄位值。這一行就是未被辨識的 taint source。"""
        return str(self._raw.get(key, ""))
