"""Shared constants and value encoding helpers (PROTOCOL.md section 4)."""

from __future__ import annotations

import base64
import binascii

# --- wire constants (PROTOCOL.md section 2) --------------------------------
FRAME_MAGIC = 0x54594F31  # "TYO1"
PROTOCOL_VERSION = 0x01
HEADER_SIZE = 20
MAX_PAYLOAD = 16 * 1024 * 1024

FLAG_RESPONSE = 0x01
FLAG_ERROR = 0x02

# --- opcodes (PROTOCOL.md section 3) ---------------------------------------
CMD_HELLO = 0
CMD_AUTH = 1
CMD_PING = 2
CMD_SHUTDOWN = 3
CMD_BACKEND_INFO = 10
CMD_SESSION_INFO = 11
CMD_TARGET_OPEN = 20
CMD_TARGET_CLOSE = 21
CMD_TARGET_MAPS = 22
CMD_MEM_READ = 30
CMD_MEM_READV = 31
CMD_MEM_WRITE = 32
CMD_PROCESS_FIND = 40
CMD_PROCESS_LIST = 41
CMD_PROCESS_ALIVE = 42
CMD_MODULE_BASE = 43

DEFAULT_PORT = 52730

# --- map entry flag bits (PROTOCOL.md section 4.7) -------------------------
MAP_READ = 1 << 0
MAP_WRITE = 1 << 1
MAP_EXEC = 1 << 2
MAP_PRIVATE = 1 << 3
MAP_SHARED = 1 << 4
MAP_ANONYMOUS = 1 << 5


class ProtocolError(Exception):
    """Fatal framing/protocol violation; the connection must be dropped."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def hex_u64(value: int) -> str:
    """Encode a u64 as lowercase "0x..." hex string (no leading zeros)."""
    if value < 0:
        raise ValueError(f"u64 value must be non-negative, got {value}")
    return f"0x{value:x}"


def parse_u64(value: str | int, *, field: str = "value") -> int:
    """Parse "0x..." hex string (or int) into a non-negative int."""
    if isinstance(value, bool):
        raise ValueError(f"field {field!r}: bool is not a u64")
    if isinstance(value, int):
        if value < 0:
            raise ValueError(f"field {field!r}: negative int is not a u64")
        return value
    if not isinstance(value, str):
        raise ValueError(f"field {field!r}: expected hex string, got {type(value).__name__}")
    text = value.strip()
    if not text.lower().startswith("0x"):
        raise ValueError(f"field {field!r}: hex string must start with 0x, got {value!r}")
    body = text[2:]
    if not body or len(body) > 16:
        raise ValueError(f"field {field!r}: bad hex length: {value!r}")
    try:
        parsed = int(body, 16)
    except ValueError as exc:
        raise ValueError(f"field {field!r}: invalid hex {value!r}") from exc
    if parsed > 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"field {field!r}: value exceeds u64: {value!r}")
    return parsed


def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64_decode(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"invalid base64 payload: {exc}") from exc


def require_fields(payload: dict, *names: str) -> None:
    missing = [name for name in names if name not in payload]
    if missing:
        raise ValueError(f"missing required field(s): {', '.join(missing)}")
