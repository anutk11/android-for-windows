#!/usr/bin/env python3
"""sg_uses.py - which fields of libc_shared_globals does libc.so use?

Reads `llvm-objdump -d --no-show-raw-insn libc.so` on stdin. For every call
to __loader_shared_globals (through the PLT), prints the function and the
instructions that follow, up to the first call/ret/jmp: the memory operands
based on the returned pointer (rax, then whatever it was copied to) are the
struct's field offsets. A measurement of THIS build, not the AOSP headers'
word - the two are compared before the struct is laid out.

Prints only addresses, mnemonics and offsets (no library bytes).
"""
import re
import sys
from collections import defaultdict

func = None
lines = sys.stdin.read().splitlines()
uses = defaultdict(set)
out = []
i = 0
hdr = re.compile(r"^[0-9a-f]+ <(.+)>:$")
ins = re.compile(r"^\s+([0-9a-f]+):\s+(.*)$")
while i < len(lines):
    m = hdr.match(lines[i])
    if m:
        func = m.group(1)
        i += 1
        continue
    m = ins.match(lines[i])
    if m and "call" in m.group(2) and "__loader_shared_globals" in m.group(2):
        out.append("== %s  (call at 0x%s)" % (func, m.group(1)))
        regs = {"rax"}
        for k in range(i + 1, min(i + 25, len(lines))):
            mm = ins.match(lines[k])
            if not mm:
                break
            text = mm.group(2).split("#")[0].strip()
            out.append("     %s: %s" % (mm.group(1), text))
            for r in list(regs):
                for off in re.findall(r"(0x[0-9a-f]+|)\(%" + r + r"\)", text):
                    uses[int(off, 16) if off else 0].add(func)
            cp = re.match(r"movq?\s+%(\w+),\s*%(\w+)$", text)
            if cp and cp.group(1) in regs:
                regs.add(cp.group(2))
            if re.match(r"(call|ret|jmp)", text):
                break
    i += 1
print("\n".join(out))
print("\n--- field offsets used right after the call (offset: functions)")
for off in sorted(uses):
    fs = sorted(uses[off])
    print("  0x%04x: %s%s" % (off, ", ".join(fs[:6]), " ..." if len(fs) > 6 else ""))
