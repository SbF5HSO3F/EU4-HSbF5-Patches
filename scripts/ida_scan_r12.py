# 在 EffectImpl_CreateGeneral (create_general) 内扫描 r12 的所有写入与使用，确认 r12 在
# 0x140649B2B / 0x140649BF3 两处 CLeader_SetName 调用现场是否仍为"承载文化的结构"。
import idc
import io

out = []
ranges = [(0x1406493F0, 0x140649EC0)]
for (a, b) in ranges:
    h = a
    while h < b:
        d = idc.generate_disasm_line(h, 0) or ''
        out.append("%08x  %s" % (h, d))
        h = idc.next_head(h)

sel = [l for l in out if ('r12' in l) or ('SetName' in l) or ('GenerateMonarch' in l)
       or ('PickNameFromCulture' in l) or l.startswith('140649b') or l.startswith('140649a')]
with io.open(r"%REPO_ROOT%\scripts\_ida_r12.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(sel))
print("written")
