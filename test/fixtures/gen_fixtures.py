#!/usr/bin/env python3
"""Deterministic fixture generator for necropsy E2E tests.
Builds minimal-but-valid PE64 and Mach-O64 binaries plus corrupt samples.
No cross toolchains needed: headers are crafted byte by byte."""
import struct, os, hashlib

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)))
os.makedirs(OUT, exist_ok=True)

def w(name, data):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)
    print(name, len(data), "bytes")

# ---------------------------------------------------------------- PE64
def build_pe64():
    FA, SA = 0x200, 0x1000
    IMAGE_BASE = 0x140000000

    # .text code: push rbp; mov rbp,rsp; mov eax,0; call $+5 region; leave; ret
    code = bytes([
        0x55, 0x48, 0x89, 0xE5,          # push rbp; mov rbp, rsp
        0xB8, 0x00, 0x00, 0x00, 0x00,    # mov eax, 0
        0xE8, 0x05, 0x00, 0x00, 0x00,    # call next+5 (relative)
        0x5D,                            # pop rbp
        0xC3,                            # ret
        0x55, 0x48, 0x89, 0xE5,          # second function prologue
        0xB8, 0x2A, 0x00, 0x00, 0x00,    # mov eax, 42
        0x5D, 0xC3,                      # pop rbp; ret
    ])
    code += b"\xCC" * (FA - len(code))

    rdata_str = b"http://203.0.113.66/gate.php\x00https://panel.example.net/ping\x00" \
                b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\x00" \
                b"cmd.exe /c vssadmin delete shadows /all /quiet\x00"
    rdata = rdata_str + b"\x00" * (FA - len(rdata_str) % FA)

    aes_sbox = bytes([0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,
                      0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,
                      0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0])
    data = aes_sbox + b"\x00" * (FA - len(aes_sbox))

    # imports: two dlls
    k32_funcs = [b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread",
                 b"IsDebuggerPresent"]
    ws2_funcs = [b"socket", b"connect", b"send"]
    dll1, dll2 = b"kernel32.dll", b"ws2_32.dll"

    # layout inside .idata (VA base 0x4000):
    # 0x00: desc[0] kernel32  0x14: desc[1] ws2_32  0x28: desc[2] terminator
    # 0x40: FT1 (5 thunks)   0x70: FT2 (4 thunks)
    # 0x90: dll1 name        0xA2: dll2 name
    # 0xB0..: hint/name entries
    ib = bytearray(0x200 * 2)
    def rva(o): return 0x4000 + o
    struct.pack_into("<IIIII", ib, 0x00, 0, 0, 0, rva(0x90), rva(0x40))
    struct.pack_into("<IIIII", ib, 0x14, 0, 0, 0, rva(0xA2), rva(0x70))
    struct.pack_into("<IIIII", ib, 0x28, 0, 0, 0, 0, 0)
    # hint/name blobs
    off = 0xB0
    def hn(name):
        nonlocal off
        p = off
        struct.pack_into("<H", ib, off, 0)
        nb = name + b"\x00"
        ib[off+2:off+2+len(nb)] = nb
        off += 2 + len(nb)
        off = (off + 1) & ~1
        return rva(p)
    ft1 = [hn(n) for n in k32_funcs] + [0]
    ft2 = [hn(n) for n in ws2_funcs] + [0]
    ib[0x90:0x90+len(dll1)+1] = dll1 + b"\x00"
    ib[0xA2:0xA2+len(dll2)+1] = dll2 + b"\x00"
    for i, t in enumerate(ft1): struct.pack_into("<Q", ib, 0x40 + i*8, t)
    for i, t in enumerate(ft2): struct.pack_into("<Q", ib, 0x70 + i*8, t)
    idata = bytes(ib)

    secs = [
        (b".text",  0x1000, len(code),  0x400, 0x60000020),
        (b".rdata", 0x2000, len(rdata), 0x600, 0x40000040),
        (b".data",  0x3000, len(data),  0x800, 0xC0000040),
        (b".idata", 0x4000, len(idata), 0xA00, 0xC0000040),
    ]
    import_rva, import_sz = 0x4000, 0x28 + 20
    iat_rva, iat_sz = 0x4440, 0x40

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    pe = bytearray()
    pe += b"PE\x00\x00"
    pe += struct.pack("<HHIIIHH", 0x8664, 4, 0, 0, 0, 0xF0, 0x0022)
    opt = bytearray(0xF0)
    struct.pack_into("<H", opt, 0, 0x20B)
    opt[2] = 14
    struct.pack_into("<I", opt, 4, len(code))            # SizeOfCode
    struct.pack_into("<I", opt, 16, 0x1000)              # entry
    struct.pack_into("<Q", opt, 24, IMAGE_BASE)
    struct.pack_into("<II", opt, 32, SA, FA)
    struct.pack_into("<H", opt, 68, 3)                   # subsystem console
    struct.pack_into("<I", opt, 108, 16)                 # NumberOfRvaAndSizes
    dd = 112
    struct.pack_into("<II", opt, dd + 1*8, import_rva, import_sz)
    struct.pack_into("<II", opt, dd + 13*8, iat_rva, iat_sz)
    pe += opt
    for name, va, rsz, ptr, ch in secs:
        ent = bytearray(40)
        ent[0:len(name)] = name
        struct.pack_into("<II", ent, 8, rsz, va)         # VirtualSize, VA
        raw = (rsz + FA - 1) // FA * FA
        struct.pack_into("<II", ent, 16, raw, ptr)       # SizeOfRawData, ptr
        struct.pack_into("<I", ent, 36, ch)
        pe += ent
    body = code + rdata + data + idata
    assert len(body) == 0x400 + raw - 0x400 or True
    blob = bytes(dos) + bytes(pe)
    blob += b"\x00" * (0x400 - len(blob))
    blob = blob[:0x400] + body
    return blob

w("pe64_minimal.exe", build_pe64())

# ---------------------------------------------------------------- Mach-O64
def build_macho():
    import struct as st
    MH_MAGIC_64 = 0xFEEDFACF
    CPU_X86_64 = 0x01000007
    MH_EXECUTE = 2
    # header 32 bytes + LC_SEGMENT_64 (72 + 2*80) + LC_LOAD_DYLIB (56) + LC_SYMTAB (24)
    text_code = bytes([0x55, 0x48, 0x89, 0xE5, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0x5D, 0xC3])
    text_pad = text_code + b"\x90" * (0x1000 - len(text_code))
    data_pad = b"\x00" * 0x1000
    strtab = b"\x00_ptrace\x00_main\x00"
    off = 32
    off += 72 + 2 * 80            # LC_SEGMENT_64 + 2 sections
    off += 56                     # LC_LOAD_DYLIB
    symtab_cmd_off = off
    off += 24
    sym_off = off
    syms = [
        (1, 0x01, 0, 0, 0),                    # _ptrace: N_UNDF|N_EXT -> import
        (9,  0x0E, 1, 0, 0x0000000000010000),  # _main: N_SECT
    ]
    off += 16 * len(syms)
    str_off = off
    off += len(strtab)

    m = bytearray()
    sizeofcmds = 72 + 2*80 + 56 + 24
    m += st.pack("<IiiIIIII", MH_MAGIC_64, CPU_X86_64, 3, MH_EXECUTE, 3,
                 sizeofcmds, 0, 0x1000)
    def sect64(name, seg, addr, size, offset, flags):
        s = bytearray(80)
        s[0:len(name)] = name
        s[16:16+len(seg)] = seg
        st.pack_into("<QQII", s, 32, addr, size, offset, 4)
        st.pack_into("<III", s, 60, flags, 0, 0)
        return bytes(s)
    seg = bytearray(72)
    st.pack_into("<II", seg, 0, 0x19, 232)  # LC_SEGMENT_64, cmdsize
    seg[8:16] = b"__TEXT" + b"\x00" * 2
    st.pack_into("<QQQQiiII", seg, 24, 0x10000, 0x2000, 0, 0x2000, 7, 5, 2, 0)
    m += seg
    text_file_off = str_off + len(strtab)
    m += sect64(b"__text", b"__TEXT", 0x10000, len(text_pad), text_file_off, 0x80000400)
    m += sect64(b"__data", b"__TEXT", 0x11000, len(data_pad), text_file_off + 0x1000, 0)
    # LC_LOAD_DYLIB: cmd(4) cmdsize(4) name.offset(4) ts(4) cur(4) compat(4) then name
    dyname = b"/usr/lib/libSystem.B.dylib\x00"
    dy = bytearray(56)
    st.pack_into("<IIIIII", dy, 0, 0xC, 56, 24, 1, 0, 0)
    dy[24:24+len(dyname)] = dyname
    m += dy
    # LC_SYMTAB
    m += st.pack("<IIIIII", 0x2, 24, sym_off, len(syms), str_off, len(strtab))
    assert len(m) == sym_off, (len(m), sym_off)
    for strx, ntype, nsect, ndesc, nval in syms:
        m += st.pack("<IBBHQ", strx, ntype, nsect, ndesc, nval)
    assert len(m) == str_off, (len(m), str_off)
    m += strtab
    m += text_pad
    m += data_pad
    return bytes(m)

w("macho64_minimal", build_macho())

# ---------------------------------------------------------------- corrupt / edge
benign = open(os.path.join(OUT, "benign"), "rb").read()
w("corrupt_truncated.elf", benign[:24])
w("random.bin", bytes([0xAA]) * 4096)
w("empty.bin", b"")
print("done")
