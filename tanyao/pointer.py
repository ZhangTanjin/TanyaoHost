"""Pointer-chain resolution with PAC normalization (CLI `--offset` semantics).

Repeated offsets: each earlier offset dereferences a 64-bit pointer at
(current + offset); the last offset locates the final field (no deref).
"""

from __future__ import annotations

import struct

from .scan import PAC_MASK_DEFAULT, TYPES


class PointerChainError(Exception):
    pass


def resolve_chain(
    read_fn,
    start: int,
    offsets: list[int],
    *,
    vtype: str = "u64",
    strip_pac: bool = True,
    pointer_mask: int | None = None,
) -> dict:
    """Walk a pointer chain. `read_fn(pid, addr, size) -> bytes` is injected so the
    caller (service) supplies the target context.

    Returns {"steps": [...], "final_address": ..., "value": ...}.
    """
    if not offsets:
        raise ValueError("at least one offset required")
    if vtype not in TYPES:
        raise ValueError(f"unsupported type {vtype!r}")
    mask = pointer_mask if pointer_mask is not None else (PAC_MASK_DEFAULT if strip_pac else None)

    steps: list[dict] = []
    current = start
    for depth, off in enumerate(offsets[:-1]):
        addr = current + off
        data = read_fn(addr, 8)
        raw = struct.unpack("<Q", data)[0]
        normalized = (raw & mask) if mask is not None else raw
        steps.append(
            {
                "depth": depth,
                "address": f"0x{addr:x}",
                "raw_pointer": f"0x{raw:x}",
                "normalized": f"0x{normalized:x}",
            }
        )
        if normalized == 0:
            raise PointerChainError(f"null pointer at depth {depth} (address 0x{addr:x})")
        current = normalized

    final_addr = current + offsets[-1]
    fmt, size, _kind = TYPES[vtype]
    data = read_fn(final_addr, size)
    value = struct.unpack(fmt, data)[0]
    steps.append({"depth": len(offsets) - 1, "address": f"0x{final_addr:x}", "read": vtype})
    return {
        "steps": steps,
        "final_address": f"0x{final_addr:x}",
        "value": int(value) if isinstance(value, int) else value,
        "value_hex": f"0x{value:x}" if isinstance(value, int) and vtype in ("u64", "ptr") else None,
    }
