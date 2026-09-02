"""Host-side native binary analysis for RE workflows (zero third-party deps).

- disassemble_a64: length-decoded AArch64 subset decoder (control flow,
  immediates, literal pools). Every A64 instruction is 4 bytes, so length is
  always exact; unrecognised encodings are shown as `.long 0x...` rather than
  guessed.  Full-fidelity decoding stays with objdump/Ghidra (see dump_module).
- extract_strings: bounded printable-ASCII runs over a byte window, offset-annotated.
- parse_apk_manifest: minimal Android binary XML (AXML) reader for the pieces RE
  actually needs: package, versions, activities, launcher entry, permissions.
"""

from __future__ import annotations

import re as _re
import struct
import zipfile

PRINTABLE = set(range(0x20, 0x7F))

COND = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
        "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"]

# Capstone is the primary A64 decoding engine when available (full ISA
# coverage); the built-in subset decoder below is the no-capstone fallback.
try:
    import capstone as _capstone

    _CS = _capstone.Cs(_capstone.CS_ARCH_ARM64, _capstone.CS_MODE_LITTLE_ENDIAN)
    CAPSTONE_OK = True
except Exception:  # pragma: no cover - depends on host env
    _capstone = None
    CAPSTONE_OK = False


def disassemble_a64_ex(data: bytes, vaddr_base: int, *, max_instructions: int = 4096,
                       engine: str = "auto") -> dict:
    """Disassemble A64 code. Returns {"engine": ..., "instructions": [...]}.

    engine: "auto" (capstone when importable, else built-in subset), or an
    explicit "capstone"/"subset" to force one.
    """
    if engine == "auto":
        engine = "capstone" if CAPSTONE_OK else "subset"
    if engine == "capstone" and not CAPSTONE_OK:
        engine = "subset"
    if engine == "capstone":
        return {"engine": "capstone",
                "instructions": _disassemble_capstone(data, vaddr_base, max_instructions)}
    return {"engine": "subset",
            "instructions": disassemble_a64(data, vaddr_base, max_instructions=max_instructions)}


def _disassemble_capstone(data: bytes, vaddr_base: int, max_instructions: int) -> list[dict]:
    out: list[dict] = []
    n = len(data) - (len(data) % 4)
    pos = 0
    while pos < n and len(out) < max_instructions:
        got_any = False
        for ins in _CS.disasm(data[pos:n], vaddr_base + pos):
            out.append({
                "addr": f"0x{ins.address:x}",
                "rva": ins.address - vaddr_base,
                "bytes": bytes(ins.bytes).hex(),
                "text": f"{ins.mnemonic} {ins.op_str}".strip(),
            })
            pos += ins.size
            got_any = True
            if len(out) >= max_instructions:
                break
        if not got_any:
            # stall: emit one raw word and step 4 bytes (objdump-style recovery,
            # keeps alignment through data-in-code / literal pools)
            w = struct.unpack_from("<I", data, pos)[0]
            out.append({
                "addr": f"0x{vaddr_base + pos:x}",
                "rva": pos,
                "bytes": f"{w:08x}",
                "text": f".long 0x{w:08x}",
            })
            pos += 4
    return out


def disassemble_a64(data: bytes, vaddr_base: int, *, max_instructions: int = 4096) -> list[dict]:
    """Built-in length-decoded A64 SUBSET (fallback when capstone is absent).

    Every A64 instruction is 4 bytes, so length is always exact; unrecognised
    encodings surface as `.long 0x...`. Prefer disassemble_a64_ex (capstone).
    """
    out: list[dict] = []
    n = len(data) - (len(data) % 4)
    for i in range(0, n, 4):
        if len(out) >= max_instructions:
            break
        addr = vaddr_base + i
        w = struct.unpack_from("<I", data, i)[0]
        text = _decode_a64(w, addr)
        out.append({
            "addr": f"0x{addr:x}",
            "rva": i,
            "bytes": f"{w:08x}",
            "text": text,
        })
    return out


def _reg(idx: int, sf: bool) -> str:
    return f"x{idx}" if sf else f"w{idx}"


def _sx(value: int, bits: int) -> int:
    if value & (1 << (bits - 1)):
        value -= 1 << bits
    return value


def _decode_a64(w: int, addr: int) -> str:
    top = (w >> 24) & 0xFF

    # exact / trivial
    if w == 0xD65F03C0:
        return "ret"
    if w == 0xD503201F:
        return "nop"

    # b / bl
    if (w & 0x7C000000) == 0x14000000:
        imm = _sx(w & 0x03FFFFFF, 26) * 4
        kind = "bl" if (w >> 31) else "b"
        return f"{kind} 0x{addr + imm:x}"

    # b.cond
    if (w & 0xFF000010) == 0x54000000:
        imm = _sx((w >> 5) & 0x7FFFF, 19) * 4
        return f"b.{COND[w & 0xF]} 0x{addr + imm:x}"

    # cbz / cbnz
    if top in (0x34, 0x35, 0xB4, 0xB5):
        imm = _sx((w >> 5) & 0x7FFFF, 19) * 4
        op = "cbz" if not (w & (1 << 24)) else "cbnz"
        rt = w & 0x1F
        return f"{op} {_reg(rt, top >= 0xB4)}, 0x{addr + imm:x}"

    # tbz / tbnz
    if (w & 0x7E000000) == 0x36000000:
        imm = _sx((w >> 5) & 0x3FFF, 14) * 4
        bit = ((w >> 31) << 5) | ((w >> 19) & 0x1F)
        op = "tbz" if not (w & (1 << 24)) else "tbnz"
        rt = w & 0x1F
        return f"{op} {_reg(rt, bool(w >> 31))}, #{bit}, 0x{addr + imm:x}"

    # adrp / adr
    if (w & 0x9F000000) == 0x90000000:
        immlo = (w >> 29) & 0x3
        immhi = (w >> 5) & 0x7FFFF
        imm = _sx((immhi << 2) | immlo, 21) << 12
        target = ((addr >> 12) << 12) + imm
        return f"adrp {_reg(w & 0x1F, True)}, 0x{target:x}"
    if (w & 0x9F000000) == 0x10000000:
        immlo = (w >> 29) & 0x3
        immhi = (w >> 5) & 0x7FFFF
        imm = _sx((immhi << 2) | immlo, 21)
        return f"adr {_reg(w & 0x1F, True)}, 0x{addr + imm:x}"

    # ldr literal (32/64-bit general + ldrsw)
    if (w & 0xBF000000) == 0x18000000:
        opc = (w >> 30) & 0x3
        if opc == 0:
            imm = _sx((w >> 5) & 0x7FFFF, 19) * 4
            return f"ldr w{w & 0x1F}, 0x{addr + imm:x}  // literal"
        if opc == 1:
            imm = _sx((w >> 5) & 0x7FFFF, 19) * 4
            return f"ldr x{w & 0x1F}, 0x{addr + imm:x}  // literal"
        if opc == 2:
            imm = _sx((w >> 5) & 0x7FFFF, 19) * 4
            return f"ldrsw x{w & 0x1F}, 0x{addr + imm:x}  // literal"

    # movz / movn / movk immediate
    if (w & 0x1F800000) == 0x12800000 or (w & 0x1F800000) == 0x52800000 \
            or (w & 0x1F800000) == 0x72800000:
        opc = (w >> 29) & 0x3
        sf = bool(w >> 31)
        hw = (w >> 21) & 0x3
        imm16 = (w >> 5) & 0xFFFF
        rd = w & 0x1F
        if opc == 2:
            mnem = "mov" if hw == 0 else "movz"   # movz with hw=0 aliases to mov
            suffix = f", lsl #{hw * 16}" if hw else ""
            return f"{mnem} {_reg(rd, sf)}, #0x{imm16:x}{suffix}"
        mnem = {0: "movn", 3: "movk"}.get(opc, "mov?")
        suffix = f", lsl #{hw * 16}" if hw and opc == 0 else (f", lsl #{hw * 16}" if hw else "")
        return f"{mnem} {_reg(rd, sf)}, #0x{imm16:x}{suffix}"

    # add/sub (immediate): sf op S 100010 sh imm12 Rn Rd
    if (w & 0x1F000000) == 0x11000000 and ((w >> 23) & 0x3F) == 0x22:
        sf = bool(w >> 31)
        op = "sub" if (w & (1 << 30)) else "add"
        if w & (1 << 29):
            op += "s"
        imm12 = (w >> 10) & 0xFFF
        rn, rd = (w >> 5) & 0x1F, w & 0x1F
        sflag = bool(w & (1 << 29))
        rtxt = _reg(rn, sf) if rn != 31 else ("xzr" if sflag else "sp")
        dtxt = _reg(rd, sf) if rd != 31 else ("xzr" if sflag else "sp")
        text = f"{op} {dtxt}, {rtxt}, #0x{imm12:x}"
        if w & (1 << 22):
            text += ", lsl #12"
        return text

    # ldr/str (immediate, 32/64-bit general)
    #   unsigned offset: bits29-24 = 111001 (imm12, scaled by size)
    #   unscaled/post/pre: bits29-24 = 111000 (imm9), form by bits11-10
    if (w & 0x3B000000) == 0x39000000 or (w & 0x3B000000) == 0x38000000:
        unsigned = (w & 0x3B000000) == 0x39000000
        l = bool(w & (1 << 22))
        opc = (w >> 22) & 0x3
        rn, rt = (w >> 5) & 0x1F, w & 0x1F
        base = "sp" if rn == 31 else f"x{rn}"
        width8 = bool((w >> 30) & 1)
        rtt = ("xzr" if width8 else "wzr") if rt == 31 else _reg(rt, width8)
        if unsigned:
            off = ((w >> 10) & 0xFFF) * (8 if width8 else 4)
            if opc == 0:
                return f"str {rtt}, [{base}, #{off}]"
            if opc == 1:
                return f"ldr {rtt}, [{base}, #{off}]"
            if opc == 2:
                return f"ldrsw x{rt}, [{base}, #{off * 2}]"
            return f".long 0x{w:08x}  // ldr/str opc=3"
        if opc not in (0, 1):
            return f".long 0x{w:08x}"
        mnem = "ldr" if l else "str"
        imm9 = _sx((w >> 12) & 0x1FF, 9)
        form = (w >> 10) & 0x3
        if form == 0:
            return f"{mnem}ur {rtt}, [{base}, #{imm9}]"
        if form == 1:  # post-index
            return f"{mnem} {rtt}, [{base}], #{imm9}"
        if form == 3:  # pre-index
            return f"{mnem} {rtt}, [{base}, #{imm9}]!"
        return f".long 0x{w:08x}"

    # stp / ldp (64-bit, signed offset / pre-index / post-index)
    if (w >> 25) == 0x54:  # bits31-25 = 1010100 → STP/LDP 64-bit pair family
        l = bool(w & (1 << 22))
        mode = (w >> 23) & 0x3
        mnem = ("ldp" if l else "stp") if mode else ("ldnp" if l else "stnp")
        imm7 = _sx((w >> 15) & 0x7F, 7) * 8
        rt2, rn, rt = (w >> 10) & 0x1F, (w >> 5) & 0x1F, w & 0x1F
        base = "sp" if rn == 31 else f"x{rn}"
        if mode == 1:  # post-index
            body = f"[{base}], #{imm7}"
        elif mode == 3:  # pre-index
            body = f"[{base}, #{imm7}]!"
        else:  # signed offset (mode 0/2; mode 2 is non-temporal, rendered same)
            body = f"[{base}, #{imm7}]"
        return f"{mnem} x{rt}, x{rt2}, {body}"

    # orr (shifted register) + "mov reg" alias
    if (w & 0x7F800000) == 0x2A000000:
        sf = bool(w >> 31)
        shift = (w >> 22) & 0x3
        rm, imm6, rn, rd = (w >> 16) & 0x1F, (w >> 10) & 0x3F, (w >> 5) & 0x1F, w & 0x1F
        if rn == 31 and shift == 0 and imm6 == 0:
            rm_txt = ("xzr" if sf else "wzr") if rm == 31 else _reg(rm, sf)
            return f"mov {_reg(rd, sf)}, {rm_txt}"
        rntxt = ("xzr" if sf else "wzr") if rn == 31 else _reg(rn, sf)
        return f"orr {_reg(rd, sf)}, {rntxt}, {_reg(rm, sf)}"

    # br / blr / ret (register)
    if (w & 0xFFFFFC1F) == 0xD61F0000:
        return f"br x{(w >> 5) & 0x1F}"
    if (w & 0xFFFFFC1F) == 0xD63F0000:
        return f"blr x{(w >> 5) & 0x1F}"
    if (w & 0xFFFFFC1F) == 0xD65F0000:
        rn = (w >> 5) & 0x1F
        return "ret" if rn == 30 else f"ret x{rn}"

    # svc
    if (w & 0xFFE0001F) == 0xD4000001:
        return f"svc #{(w >> 5) & 0xFFFF}"

    return f".long 0x{w:08x}"


def extract_strings(
    data: bytes,
    *,
    offset: int = 0,
    min_length: int = 4,
    limit: int = 4096,
    filter: str | None = None,
) -> list[dict]:
    """Extract runs of printable ASCII (>= min_length) from a byte window.

    Returns [{"offset","length","value"}] where offset is relative to `offset`
    (pass a vaddr/rva to annotate directly). Optional `filter` is a regex on the
    decoded value.
    """
    rx = _re.compile(filter) if filter else None
    out: list[dict] = []
    run_start = None
    n = len(data)

    def flush(end: int) -> None:
        nonlocal run_start
        if run_start is None:
            return
        length = end - run_start
        if length >= min_length:
            value = data[run_start:end].decode("ascii", "replace")
            if rx is None or rx.search(value):
                out.append({"offset": offset + run_start, "length": length, "value": value})
                if len(out) >= limit:
                    raise _LimitReached()
        run_start = None

    class _LimitReached(Exception):
        pass

    run_start = None
    try:
        for i in range(n):
            b = data[i]
            if b in PRINTABLE:
                if run_start is None:
                    run_start = i
            else:
                flush(i)
                if len(out) >= limit:
                    break
        flush(n)
    except _LimitReached:
        pass
    return out


# --- APK (zip + Android binary XML) ----------------------------------------------

class ApkParseError(ValueError):
    pass


def parse_apk_manifest(apk_path: str) -> dict:
    """Read AndroidManifest.xml from an APK (binary AXML) — RE-relevant fields."""
    with zipfile.ZipFile(apk_path) as zf:
        xml = zf.read("AndroidManifest.xml")
    return parse_axml(xml)


def parse_axml(xml: bytes) -> dict:
    if len(xml) < 8 or struct.unpack_from("<HH", xml, 0)[0] != 0x0003:
        raise ApkParseError("not a binary XML chunk (RES_XML_TYPE expected)")

    strings: list[str] = []
    pos = 8
    size_total = struct.unpack_from("<I", xml, 4)[0]
    end = min(len(xml), size_total or len(xml))

    info: dict = {"package": None, "version_name": None, "version_code": None,
                  "activities": [], "launcher_activities": [], "permissions": []}
    stack: list[str] = []
    cur_activity: dict | None = None
    in_intent_filter = False
    has_main = False
    has_launcher = False

    while pos + 8 <= end:
        ctype, _hsize, csize = struct.unpack_from("<HHI", xml, pos)
        if csize < 8 or pos + csize > len(xml):
            break

        if ctype == 0x0001:  # string pool
            strings = _parse_string_pool(xml, pos, csize)
        elif ctype == 0x0102:  # start element
            # node header: type(2) headerSize(2) chunkSize(4) lineNumber(4) comment(4)
            # attrExt at pos+16: ns(4) name(4) attrStart(2) attrSize(2) attrCount(2) ...
            ns, name_idx = struct.unpack_from("<ii", xml, pos + 16)
            attr_start, attr_size, attr_count = struct.unpack_from("<HHH", xml, pos + 24)
            name = _str_at(strings, name_idx)
            attrs = {}
            for k in range(attr_count):
                a = pos + 16 + attr_start + k * attr_size
                if a + 20 > len(xml):
                    break
                aname_idx, _raw = struct.unpack_from("<iI", xml, a + 4)
                dtsize, _res0, dtype, ddata = struct.unpack_from("<HBBI", xml, a + 12)
                aname = _str_at(strings, aname_idx)
                if dtype == 0x03:  # STRING
                    attrs[aname] = _str_at(strings, ddata)
                elif dtype in (0x10, 0x11):  # INT_DEC / INT_HEX
                    attrs[aname] = ddata
                elif dtype == 0x12:  # BOOLEAN
                    attrs[aname] = bool(ddata)
                else:
                    attrs[aname] = ddata

            if name == "manifest":
                info["package"] = attrs.get("package")
                info["version_name"] = attrs.get("versionName")
                info["version_code"] = attrs.get("versionCode")
            elif name == "uses-permission":
                perm = attrs.get("name")
                if perm:
                    info["permissions"].append(perm)
            elif name == "activity":
                cur_activity = {"name": attrs.get("name"), "exported": attrs.get("exported")}
                in_intent_filter = False
            elif name == "intent-filter" and cur_activity is not None:
                in_intent_filter = True
                has_main = False
                has_launcher = False
            elif name == "action" and in_intent_filter:
                if attrs.get("name") == "android.intent.action.MAIN":
                    has_main = True
            elif name == "category" and in_intent_filter:
                if attrs.get("name") == "android.intent.category.LAUNCHER":
                    has_launcher = True
            stack.append(name)

        elif ctype == 0x0103:  # end element
            # headerSize 16: type(2) headerSize(2) size(4) line(4) comment(4)
            # then ns(4) name(4) → name index at pos+20
            name_idx = struct.unpack_from("<i", xml, pos + 20)[0]
            name = _str_at(strings, name_idx)
            if name == "activity" and cur_activity is not None:
                if cur_activity["name"]:
                    info["activities"].append(cur_activity["name"])
                    if has_main and has_launcher:
                        info["launcher_activities"].append(cur_activity["name"])
                cur_activity = None
            elif name == "intent-filter":
                in_intent_filter = False
            if stack and stack[-1] == name:
                stack.pop()

        pos += csize

    return info


def _parse_string_pool(xml: bytes, pos: int, csize: int) -> list[str]:
    if len(xml) < pos + 28:
        return []
    string_count, _style, flags, strings_start = struct.unpack_from("<IIII", xml, pos + 8)
    is_utf8 = bool(flags & (1 << 8))
    offsets_pos = pos + 28
    base = pos + strings_start
    out: list[str] = []
    for i in range(string_count):
        off = struct.unpack_from("<I", xml, offsets_pos + i * 4)[0]
        p = base + off
        if p >= len(xml):
            out.append("")
            continue
        if is_utf8:
            # u16len (possibly 2 bytes), u8len (possibly 2 bytes), then bytes
            _u16len, skip = _axed_len8(xml, p)
            blen, skip2 = _axed_len8(xml, p + skip)
            out.append(xml[p + skip: p + skip + skip2 + blen].decode("utf-8", "replace"))
        else:
            slen, skip = _axed_len16(xml, p)
            out.append(xml[p + skip: p + skip + slen * 2].decode("utf-16-le", "replace"))
    return out


def _axed_len8(buf: bytes, p: int) -> tuple[int, int]:
    if p >= len(buf):
        return 0, 1
    b = buf[p]
    if b & 0x80:
        return ((b & 0x7F) << 8) | buf[p + 1], 2
    return b, 1


def _axed_len16(buf: bytes, p: int) -> tuple[int, int]:
    v = struct.unpack_from("<H", buf, p)[0]
    if v & 0x8000:
        v2 = struct.unpack_from("<H", buf, p + 2)[0]
        return ((v & 0x7FFF) << 16) | v2, 4
    return v, 2


def _str_at(strings: list[str], idx: int) -> str | None:
    if 0 <= idx < len(strings):
        return strings[idx]
    return None


__all__ = [
    "disassemble_a64",
    "extract_strings",
    "parse_apk_manifest",
    "parse_axml",
    "ApkParseError",
]
