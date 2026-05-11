import re
import logging

logger = logging.getLogger(__name__)

# PII patterns
PII_PATTERNS = [
    (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[EMAIL REDACTED]'),
    (r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b', '[CARD REDACTED]'),
    (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[PHONE REDACTED]'),
    (r'\b\d{3}-\d{2}-\d{4}\b', '[SSN REDACTED]'),
    (r'password\s*[:=]\s*\S+', '[PASSWORD REDACTED]'),
    (r'passwd\s*[:=]\s*\S+', '[PASSWORD REDACTED]'),
    (r'secret\s*[:=]\s*\S+', '[SECRET REDACTED]'),
    (r'token\s*[:=]\s*\S+', '[TOKEN REDACTED]'),
    (r'api_key\s*[:=]\s*\S+', '[API_KEY REDACTED]'),
    (r'Authorization:\s*Bearer\s+\S+', '[BEARER TOKEN REDACTED]'),
]


def redact_pii(text: str) -> str:
    if not text:
        return text
    for pattern, replacement in PII_PATTERNS:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
    return text


def redact_dict(data: dict) -> dict:
    if not isinstance(data, dict):
        return data
    redacted = {}
    for key, value in data.items():
        if isinstance(value, str):
            redacted[key] = redact_pii(value)
        elif isinstance(value, dict):
            redacted[key] = redact_dict(value)
        elif isinstance(value, list):
            redacted[key] = redact_list(value)
        else:
            redacted[key] = value
    return redacted


def redact_list(data: list) -> list:
    redacted = []
    for item in data:
        if isinstance(item, str):
            redacted.append(redact_pii(item))
        elif isinstance(item, dict):
            redacted.append(redact_dict(item))
        elif isinstance(item, list):
            redacted.append(redact_list(item))
        else:
            redacted.append(item)
    return redacted