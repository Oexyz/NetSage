"""Secret redaction for untrusted device data and audit-safe arguments."""

import re
from collections.abc import Iterable, Mapping, Sequence

REDACTED = "<REDACTED>"

_SENSITIVE_KEYS = {
    "apikey",
    "apitoken",
    "accesstoken",
    "authorization",
    "authtoken",
    "bearertoken",
    "password",
    "privatekey",
    "radiussecret",
    "secret",
    "snmpcommunity",
    "tacacssecret",
    "token",
}

_TEXT_PATTERNS = (
    re.compile(
        r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?"
        r"-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
        re.DOTALL,
    ),
    re.compile(r"(?im)(authorization\s*:\s*(?:bearer|basic)\s+)\S+"),
    re.compile(
        r"(?im)\b(snmp-server\s+community|tacacs(?:-server)?\s+(?:key|secret)|"
        r"radius(?:-server)?\s+(?:key|secret)|enable\s+secret)\s+\S+"
    ),
    re.compile(
        r"(?im)\b(password|api[_-]?key|access[_-]?token|auth[_-]?token|secret)"
        r"(\s*[:=]\s*)\S+"
    ),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
)


def _normalized_key(key: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


class SecretRedactor:
    """Recursively redact known secret fields and token-like text."""

    def __init__(self, *, known_secrets: Iterable[str] = ()) -> None:
        self._known_secrets = tuple(
            sorted((secret for secret in known_secrets if secret), key=len, reverse=True)
        )

    def redact_text(self, value: str) -> str:
        redacted = value
        for index, pattern in enumerate(_TEXT_PATTERNS):
            if index == 1:
                redacted = pattern.sub(rf"\1{REDACTED}", redacted)
            elif index == 2:
                redacted = pattern.sub(rf"\1 {REDACTED}", redacted)
            elif index == 3:
                redacted = pattern.sub(rf"\1\2{REDACTED}", redacted)
            else:
                redacted = pattern.sub(REDACTED, redacted)
        for secret in self._known_secrets:
            redacted = redacted.replace(secret, REDACTED)
        return redacted

    def redact(self, value: object) -> object:
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, Mapping):
            return {
                str(key): REDACTED if _normalized_key(key) in _SENSITIVE_KEYS else self.redact(item)
                for key, item in value.items()
            }
        if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
            return [self.redact(item) for item in value]
        if value is None or isinstance(value, bool | int | float):
            return value
        return "<UNSUPPORTED_VALUE>"
