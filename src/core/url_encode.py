from urllib.parse import quote


def url_encode(text: str) -> str:
    """
    Кодирует строку для использования в URL (percent-encoding).
    """
    return quote(text)
