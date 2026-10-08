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
import re

# Degenerate repetition detection for LLM outputs
_TOKEN_RE = re.compile(r"[a-z0-9]+")
_REPEAT_THRESHOLD = {1: 4, 2: 3, 3: 2}  # n-gram size -> min consecutive repeats


def _max_consecutive_repeats(tokens: list, n: int) -> int:
    """Count longest run of immediately repeating n-grams."""
    best = 1
    i = 0
    while i + 2 * n <= len(tokens):
        if tokens[i:i + n] == tokens[i + n:i + 2 * n]:
            run = 2
            j = i + 2 * n
            while j + n <= len(tokens) and tokens[j:j + n] == tokens[i:i + n]:
                run += 1
                j += n
            best = max(best, run)
            i = j
        else:
            i += 1
    return best


def detect_degenerate_repetition(text: str, min_scale: int = 0) -> bool:
    """
    Detect LLM degenerate repetition in the tail of the output.
    Catches repeated unigrams ('health health health'), bigrams
    ('for health for health') and punctuation garbage runs ('......').
    Tokens are punctuation-stripped, so 'health....).' still matches.
    """
    if not text:
        return False

    # Punctuation garbage runs in the last 300 chars
    if re.search(r"(?:[^\w\s]\s*){6,}", text[-300:]):
        return True

    tokens = _TOKEN_RE.findall(text.lower())[-400:]  # tail only
    for n, threshold in _REPEAT_THRESHOLD.items():
        if _max_consecutive_repeats(tokens, n) >= threshold + min_scale:
            return True
    return False


def sanitize_degenerate(content: str) -> str:
    """
    Truncate content at the first degenerate segment (sentence-level scan).
    Returns content unchanged if clean. Export/chat safe.
    """
    if not detect_degenerate_repetition(content):
        return content
    sentences = re.split(r"(?<=[.!?])\s+", content)
    keep = []
    for sent in sentences:
        window = " ".join(keep[-2:] + [sent])
        if detect_degenerate_repetition(window, min_scale=-1):
            break
        keep.append(sent)
    if not keep:
        return "*[Output truncated: degenerate repetition detected]*"
    return " ".join(keep) + "\n\n*[Output truncated: degenerate repetition detected]*"