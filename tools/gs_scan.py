#!/usr/bin/env python3
"""gs_scan.py - how does this code use %gs: (and %fs:)?  (issue #15, G3)

ART on x86_64 keeps art::Thread* in gs (arch_prctl(ARCH_SET_GS)); on
Windows x64 gs is the TEB and cannot be moved. Before deciding how G3
handles it (trampolines, or a patched libart), measure it.

Reads `llvm-objdump -d --no-show-raw-insn FILE` on stdin; argv[1] = a label.
Prints counts only - forms, displacements, the functions that use it most;
no library bytes.
"""
import re
import sys
from collections import Counter

label = sys.argv[1] if len(sys.argv) > 1 else "?"
hdr = re.compile(r"^[0-9a-f]+ <(.+)>:$")
# "addr:<TAB>[raw bytes<TAB>]mnemonic<TAB>operands" - some files (the .oat
# ones) get the raw bytes printed even with --no-show-raw-insn; skip them.
ins = re.compile(r"^\s+[0-9a-f]+:\s+(?:(?:[0-9a-f]{2} )+\s*)?([a-z][a-z0-9.]*)\s*(.*)$")
seg = re.compile(r"%(gs|fs):(-?(?:0x[0-9a-f]+|\d+)?(?:\([^)]*\))?)")

total = Counter()          # gs / fs
forms = {"gs": Counter(), "fs": Counter()}
disps = {"gs": Counter(), "fs": Counter()}
funcs = {"gs": Counter(), "fs": Counter()}
insns = 0
func = "?"
calls = Counter()          # indirect call forms, numbers normalised
mnems = Counter()

for line in sys.stdin:
    m = hdr.match(line)
    if m:
        func = m.group(1)
        continue
    m = ins.match(line)
    if not m:
        continue
    insns += 1
    mnem, ops = m.group(1), m.group(2).split("#")[0].strip()
    mnems[mnem] += 1
    if mnem.startswith("call") and "*" in ops:
        calls[re.sub(r"0x[0-9a-f]+|\b\d+\b", "N", ops)] += 1
    for s, d in seg.findall(ops):
        total[s] += 1
        funcs[s][func] += 1
        disps[s][d if not re.search(r"%r|%e", d) else "(register)"] += 1
        operands = [o.strip() for o in re.split(r",(?![^(]*\))", ops)]
        last = operands[-1] if operands else ""
        if mnem.startswith(("call", "jmp")):
            form = "indirect %s through %s:" % (mnem.rstrip("q"), s)
        elif ("%" + s + ":") in last and len(operands) > 1 and not mnem.startswith(("cmp", "test", "bt")):
            form = "write (%s)" % mnem
        elif mnem.startswith("lea"):
            form = "lea (no access)"
        else:
            form = "read (%s)" % mnem
        forms[s][form] += 1

print("=== %s: %d instructions, %d %%gs: accesses, %d %%fs: accesses" % (label, insns, total["gs"], total["fs"]))
if insns:
    print("--- indirect call forms (how the code reaches the runtime)")
    for f, n in calls.most_common(6):
        print("  %7d  call %s" % (n, f))
    print("--- top mnemonics: " + ", ".join("%s %d" % (k, v) for k, v in mnems.most_common(8)))
for s in ("gs", "fs"):
    if not total[s]:
        continue
    print("--- %%%s: forms" % s)
    for f, n in forms[s].most_common(12):
        print("  %7d  %s" % (n, f))
    print("--- %%%s: displacements (%d distinct)" % (s, len(disps[s])))
    for d, n in disps[s].most_common(12):
        print("  %7d  %s:%s" % (n, s, d))
    print("--- %%%s: functions using it most (%d functions)" % (s, len(funcs[s])))
    for f, n in funcs[s].most_common(10):
        print("  %7d  %s" % (n, f[:110]))
