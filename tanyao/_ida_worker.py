
import json, os, re, sys, time

def main():
    dump_path, out_dir, max_functions, progress_path, cancel_path = sys.argv[1:6]
    max_functions = int(max_functions)

    import idapro
    rc = idapro.open_database(dump_path, run_auto_analysis=True)
    if rc != 0:
        print(json.dumps({"ok": False, "error": f"open_database rc={rc}"}))
        return 1

    import ida_auto, ida_funcs, ida_hexrays, ida_name, ida_nalt, ida_bytes

    # Write a helper so a function body can be read as raw bytes when the dump
    # has no segments covering it (common for hybrid dumps).
    try:
        ida_auto.auto_wait()
    except Exception:
        pass

    have_hexrays = False
    try:
        have_hexrays = bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        have_hexrays = False

    func_entries = []
    total = ida_funcs.get_func_qty()
    for i in range(total):
        f = ida_funcs.getn_func(i)
        if f is None:
            continue
        func_entries.append((f.start_ea, f.end_ea))

    if max_functions > 0:
        func_entries = func_entries[:max_functions]

    os.makedirs(os.path.join(out_dir, "functions"), exist_ok=True)
    index = []
    combined = []
    aborted = False

    def safe(name):
        s = re.sub(r"[^A-Za-z0-9_.$-]", "_", name or "")
        return s[:120] or "sub"

    for n, (ea, end) in enumerate(func_entries):
        if os.path.exists(cancel_path):
            aborted = True
            break
        try:
            raw_name = ida_funcs.get_func_name(ea) or ("sub_%X" % ea)
        except Exception:
            raw_name = "sub_%X" % ea
        text = None
        if have_hexrays:
            try:
                cf = ida_hexrays.decompile(ea)
                if cf is not None:
                    text = str(cf)
            except Exception:
                text = None
        if text is None:
            # Fall back to disassembly so the file always has content.
            lines = []
            cur = ea
            try:
                while cur < end and len(lines) < 4000:
                    line = ida_funcs.get_func_name(cur)
                    d = ida_bytes.generate_disasm_line(cur, 0) or ""
                    lines.append("  %08X  %s" % (cur, d))
                    nxt = ida_bytes.get_item_end(cur)
                    if nxt <= cur:
                        break
                    cur = nxt
            except Exception:
                pass
            text = "// disassembly fallback (no Hex-Rays)\n" + "\n".join(lines)

        fname = "%04d_%s.c" % (n, safe(raw_name))
        with open(os.path.join(out_dir, "functions", fname), "w", encoding="utf-8") as fh:
            fh.write("// %s @ 0x%x\n" % (raw_name, ea))
            fh.write(text)
            fh.write("\n")
        combined.append("// ---- %s @ 0x%x ----\n%s\n" % (raw_name, ea, text))
        index.append({"name": raw_name, "address": "0x%x" % ea, "file": fname})

        # progress heartbeat, read by the host poller
        tmp = progress_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"done": n + 1, "total": len(func_entries)}, fh)
        os.replace(tmp, progress_path)

    mod = os.path.basename(dump_path)
    with open(os.path.join(out_dir, "index.json"), "w", encoding="utf-8") as fh:
        json.dump({"module": mod, "engine": "ida", "hexrays": have_hexrays,
                   "functions": index, "cancelled": aborted}, fh, indent=2)
    with open(os.path.join(out_dir, mod + ".c"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(combined))

    try:
        idapro.close_database(False)
    except Exception:
        pass
    print(json.dumps({"ok": True, "functions": len(index),
                      "hexrays": have_hexrays, "cancelled": aborted}))
    return 0

if __name__ == "__main__":
    sys.exit(main())
