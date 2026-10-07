"""
Utilities for masking sensitive data in logs.
Prevents accidental exposure of API keys and tokens in debug output.
"""


def mask_api_key(key: str, visible_chars: int = 4) -> str:
    """Mask API key, leaving only last N characters visible."""
    if not key or len(key) <= visible_chars:
        return "***"
    return "*" * (len(key) - visible_chars) + key[-visible_chars:]


def mask_url(url: str) -> str:
    """Mask URL by removing query parameters (where keys may reside)."""
    if "?" in url:
        return url.split("?")[0] + "?..."
    return url