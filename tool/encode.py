from urllib.parse import (
    quote,
    quote_from_bytes,
    unquote,
    unquote_to_bytes,
)


class Url:
    @staticmethod
    def encode(data: str | bytes, _all: bool = False) -> str:
        # safe='' 表示尽可能全部编码
        # 默认 urllib 会保留 '/'

        safe = "" if _all else "/"

        if isinstance(data, bytes):
            return quote_from_bytes(data, safe=safe)
        if isinstance(data, str):
            return quote(data, safe=safe)
        return ""


    @staticmethod
    def decode(data: str) -> str:
        return unquote(data)

    @staticmethod
    def decode_to_bytes(data: str) -> bytes:
        return unquote_to_bytes(data)