import ida_bytes
import io

lines = []
for name, start, n in [("ctor_1401AF830", 0x1401AF8A0, 0xB0),
                       ("cdtor_1401AFA40", 0x1401AFA40, 0x60),
                       ("key_1401B0C44", 0x1401B0C44, 0x30),
                       ("ins_1401B0DF0", 0x1401B0DF0, 0x40),
                       ("tip_1401AFB30", 0x1401AFB30, 0x20)]:
    d = ida_bytes.get_bytes(start, n)
    lines.append("%s @%x: %s" % (name, start, " ".join("%02X" % b for b in d)))

with io.open(r"%REPO_ROOT%\scripts\_ida_bytes.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(lines))
print("ok")
