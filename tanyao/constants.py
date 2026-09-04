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
# v1.2 draft §2: PAYLOAD_BINARY — agent→host responses only; a host request
# carrying this bit is a protocol violation (agent must disconnect).
FLAG_PAYLOAD_BINARY = 0x04

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
# --- v1.1 device-local scan engine + write transaction (PROTOCOL.md §7) ----
CMD_SCAN_START = 50
CMD_SCAN_STATUS = 51
CMD_SCAN_REFINE = 52
CMD_SCAN_RESULTS = 53
CMD_SCAN_CANCEL = 54
CMD_SCAN_CLEAR = 55
CMD_WRITE_TXN = 60
# --- v1.2 draft §3: compute-down ops ---------------------------------------
CMD_SYMBOL_BATCH = 61
CMD_STRINGS_SCAN = 62
CMD_DUMP_START = 63
CMD_DUMP_STATUS = 64
CMD_DUMP_PULL = 65
CMD_APK_INFO = 66
CMD_DISASSEMBLE = 67
CMD_DUMP_CLEANUP = 68

DEFAULT_PORT = 52730

# --- agent-layer capability bits (hello.capabilities; SEPARATE namespace ---
# --- from kernel backend_info.capabilities; PROTOCOL.md §7.1 + v1.2 §1) ----
AGENT_CAP_SCAN = 1 << 0           # cmd 50-55 device-local scan engine
AGENT_CAP_WRITE_TXN = 1 << 1      # cmd 60 single-address write transaction
# bit 2: MODULE_STREAM — REVOKED, permanently reserved, must never be used.
AGENT_CAP_SYMBOL_BATCH = 1 << 3   # cmd 61 device-side dynsym batch parse
AGENT_CAP_BINARY_FRAMES = 1 << 4  # frame flags bit2 PAYLOAD_BINARY
AGENT_CAP_STRINGS = 1 << 5        # cmd 62 device-side strings scan
AGENT_CAP_DUMP_PIPELINE = 1 << 6  # cmd 63/64/65/68 dump to disk + chunked pull
AGENT_CAP_APK_INFO = 1 << 7       # cmd 66 device-side apk metadata (zero-mirror)
AGENT_CAP_DISASSEMBLE = 1 << 8    # cmd 67 device-side capstone disassembly (optional)

AGENT_CAP_TABLE = (
    (AGENT_CAP_SCAN, "scan"),
    (AGENT_CAP_WRITE_TXN, "write_txn"),
    (AGENT_CAP_SYMBOL_BATCH, "symbol_batch"),
    (AGENT_CAP_BINARY_FRAMES, "binary_frames"),
    (AGENT_CAP_STRINGS, "strings"),
    (AGENT_CAP_DUMP_PIPELINE, "dump_pipeline"),
    (AGENT_CAP_APK_INFO, "apk_info"),
    (AGENT_CAP_DISASSEMBLE, "disassemble"),
)


def undeclared_agent_caps(mask: int) -> list[str]:
    """Names of standard v1.2 capabilities the agent did NOT declare (the
    skipped_caps diagnostic field: these ops stay on the host fallback)."""
    return [name for bit, name in AGENT_CAP_TABLE if not mask & bit]

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
