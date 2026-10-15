## ndis_tables.nim — x86-64 opcode tables for the built-in disassembler.
## Subset covering >95% of compiler-emitted code (integer ALU, data movement,
## control flow, common SSE data ops). Unknown opcodes render as .byte.

type
  OpFlag* = enum
    fModrm      # instruction has ModRM
    fImm8
    fImmZ       # imm16/32 depending on operand size (imm32 in 64-bit)
    fImm64      # mov r64, imm64 (B8-BF with REX.W)
    fRel8
    fRel32
    fDstReg     # reg field is destination (else r/m is destination)
    fByte       # 8-bit operation
    fInv64      # invalid in 64-bit mode
    fGrp1       # 80/81/83 group
    fGrp2       # C0/C1/D0-D3 shift group
    fGrp3       # F6/F7 group
    fGrp4       # FE group
    fGrp5       # FF group
    fMoffs      # A0-A3 moffs
    fNoRexW     # REX.W has no effect on operand size (e.g. mov r8)
    fStr        # string op (rep-able, no modrm)

  OpInfo* = object
    mn*: string
    flags*: set[OpFlag]

proc op(mn: string, flags: varargs[OpFlag]): OpInfo =
  result.mn = mn
  for f in flags: result.flags.incl(f)

proc invalid(): OpInfo = op(".byte", fInv64)

const GRP1_NAMES* = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"]
const GRP2_NAMES* = ["rol", "ror", "rcl", "rcr", "shl", "shr", "shl", "sar"]
const GRP3_NAMES8* = ["test", "test", "not", "neg", "mul", "imul", "div", "idiv"]
const CC_NAMES* = ["o", "no", "b", "ae", "e", "ne", "be", "a",
                  "s", "ns", "p", "np", "l", "ge", "le", "g"]

proc buildTable1(): array[256, OpInfo] =
  for i in 0 ..< 256: result[i] = invalid()
  # 00-3D: ALU group add/or/adc/sbb/and/sub/xor/cmp
  const alu = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"]
  var base = 0
  while base < 0x40:
    let ai = base shr 3
    result[base]     = op(alu[ai], fModrm, fByte)              # 00 r/m8, r8
    result[base + 1] = op(alu[ai], fModrm)                     # 01 r/m, r
    result[base + 2] = op(alu[ai], fModrm, fByte, fDstReg)     # 02 r8, r/m8
    result[base + 3] = op(alu[ai], fModrm, fDstReg)            # 03 r, r/m
    result[base + 4] = op(alu[ai], fByte, fImm8)               # 04 AL, imm8
    result[base + 5] = op(alu[ai], fImmZ)                      # 05 eAX, imm32
    inc base, 8
  # 50-57 push r64, 58-5F pop r64
  for i in 0 ..< 8:
    result[0x50 + i] = op("push")
    result[0x58 + i] = op("pop")
  result[0x60] = invalid(); result[0x61] = invalid(); result[0x62] = invalid()
  result[0x63] = op("movsxd", fModrm, fDstReg)
  result[0x64] = invalid(); result[0x65] = invalid()
  result[0x66] = op(".prefix66")  # never reached as opcode (consumed as prefix)
  result[0x67] = op(".prefix67")
  result[0x68] = op("push", fImmZ)
  result[0x69] = op("imul", fModrm, fImmZ, fDstReg)
  result[0x6A] = op("push", fImm8)
  result[0x6B] = op("imul", fModrm, fImm8, fDstReg)
  result[0x6C] = op("insb", fStr); result[0x6D] = op("ins", fStr)
  result[0x6E] = op("outsb", fStr); result[0x6F] = op("outs", fStr)
  for i in 0 ..< 16:
    result[0x70 + i] = op("j" & CC_NAMES[i], fRel8)
  # 80/81/83 group handled via flags
  result[0x80] = op("grp1", fModrm, fGrp1, fByte, fImm8)
  result[0x81] = op("grp1", fModrm, fGrp1, fImmZ)
  result[0x82] = op("grp1", fModrm, fGrp1, fByte, fImm8)  # alias
  result[0x83] = op("grp1", fModrm, fGrp1, fImm8)
  result[0x84] = op("test", fModrm, fByte)
  result[0x85] = op("test", fModrm)
  result[0x86] = op("xchg", fModrm, fByte, fDstReg)
  result[0x87] = op("xchg", fModrm, fDstReg)
  result[0x88] = op("mov", fModrm, fByte)                  # r/m8, r8
  result[0x89] = op("mov", fModrm)                         # r/m, r
  result[0x8A] = op("mov", fModrm, fByte, fDstReg)         # r8, r/m8
  result[0x8B] = op("mov", fModrm, fDstReg)                # r, r/m
  result[0x8C] = op("mov", fModrm, fDstReg)                # r/m, Sreg
  result[0x8D] = op("lea", fModrm, fDstReg)
  result[0x8E] = op("mov", fModrm, fByte)                  # Sreg, r/m
  result[0x8F] = op("pop", fModrm, fGrp5)
  result[0x90] = op("nop")
  for i in 1 ..< 8: result[0x90 + i] = op("xchg")
  result[0x98] = op("cdqe")
  result[0x99] = op("cqo")
  result[0x9A] = invalid()
  result[0x9B] = op("fwait")
  result[0x9C] = op("pushfq")
  result[0x9D] = op("popfq")
  result[0x9E] = op("sahf")
  result[0x9F] = op("lahf")
  result[0xA0] = op("movabs", fMoffs, fByte)
  result[0xA1] = op("movabs", fMoffs)
  result[0xA2] = op("movabs", fMoffs, fByte)
  result[0xA3] = op("movabs", fMoffs)
  result[0xA4] = op("movsb", fStr); result[0xA5] = op("movs", fStr)
  result[0xA6] = op("cmpsb", fStr); result[0xA7] = op("cmps", fStr)
  result[0xA8] = op("test", fByte, fImm8)
  result[0xA9] = op("test", fImmZ)
  result[0xAA] = op("stosb", fStr); result[0xAB] = op("stos", fStr)
  result[0xAC] = op("lodsb", fStr); result[0xAD] = op("lods", fStr)
  result[0xAE] = op("scasb", fStr); result[0xAF] = op("scas", fStr)
  for i in 0 ..< 8:
    result[0xB0 + i] = op("mov", fByte, fImm8, fNoRexW)
    result[0xB8 + i] = op("mov", fImmZ)   # REX.W -> mov r64, imm64
  result[0xC0] = op("grp2", fModrm, fGrp2, fByte, fImm8)
  result[0xC1] = op("grp2", fModrm, fGrp2, fImm8)
  result[0xC2] = op("ret", fImm8)
  result[0xC3] = op("ret")
  result[0xC4] = invalid(); result[0xC5] = invalid()
  result[0xC6] = op("mov", fModrm, fByte, fImm8)
  result[0xC7] = op("mov", fModrm, fImmZ)
  result[0xC8] = op("enter")  # imm16+imm8 read manually in decoder
  result[0xC9] = op("leave")
  result[0xCA] = op("retf", fImm8)
  result[0xCB] = op("retf")
  result[0xCC] = op("int3")
  result[0xCD] = op("int", fImm8)
  result[0xCE] = op("into")
  result[0xCF] = op("iret")
  result[0xD0] = op("grp2", fModrm, fGrp2, fByte)
  result[0xD1] = op("grp2", fModrm, fGrp2)
  result[0xD2] = op("grp2", fModrm, fGrp2, fByte)
  result[0xD3] = op("grp2", fModrm, fGrp2)
  result[0xD4] = invalid(); result[0xD5] = invalid()
  result[0xD6] = op("salc")
  result[0xD7] = op("xlat")
  # D8-DF x87 escape (not decoded; treated as modrm-consuming FPU ops)
  for i in 0xD8 .. 0xDF:
    result[i] = op("fpu", fModrm)
  result[0xE0] = op("loopne", fRel8)
  result[0xE1] = op("loope", fRel8)
  result[0xE2] = op("loop", fRel8)
  result[0xE3] = op("jrcxz", fRel8)
  result[0xE4] = op("in", fByte, fImm8); result[0xE5] = op("in", fImm8)
  result[0xE6] = op("out", fByte, fImm8); result[0xE7] = op("out", fImm8)
  result[0xE8] = op("call", fRel32)
  result[0xE9] = op("jmp", fRel32)
  result[0xEA] = invalid()
  result[0xEB] = op("jmp", fRel8)
  result[0xEC] = op("in", fByte); result[0xED] = op("in")
  result[0xEE] = op("out", fByte); result[0xEF] = op("out")
  result[0xF0] = op(".lock")
  result[0xF1] = op("int1")
  result[0xF2] = op(".repne")
  result[0xF3] = op(".rep")
  result[0xF4] = op("hlt")
  result[0xF5] = op("cmc")
  result[0xF6] = op("grp3", fModrm, fGrp3, fByte)
  result[0xF7] = op("grp3", fModrm, fGrp3)
  result[0xF8] = op("clc"); result[0xF9] = op("stc")
  result[0xFA] = op("cli"); result[0xFB] = op("sti")
  result[0xFC] = op("cld"); result[0xFD] = op("std")
  result[0xFE] = op("grp4", fModrm, fGrp4, fByte)
  result[0xFF] = op("grp5", fModrm, fGrp5)

proc buildTable2(): array[256, OpInfo] =
  for i in 0 ..< 256: result[i] = invalid()
  result[0x05] = op("syscall")
  result[0x0B] = op("ud2")
  result[0x0D] = op("prefetch", fModrm, fByte)
  result[0x0E] = op("femms")
  result[0x1E] = op("endbr", fModrm, fByte)
  result[0x1F] = op("nop", fModrm)
  result[0x10] = op("movups", fModrm, fDstReg)   # F3: movss, 66: movupd
  result[0x11] = op("movups", fModrm)
  result[0x12] = op("movlps", fModrm, fDstReg)
  result[0x13] = op("movlps", fModrm)
  result[0x14] = op("unpcklps", fModrm, fDstReg)
  result[0x15] = op("unpckhps", fModrm, fDstReg)
  result[0x16] = op("movhps", fModrm, fDstReg)
  result[0x17] = op("movhps", fModrm)
  result[0x28] = op("movaps", fModrm, fDstReg)   # 66: movapd
  result[0x29] = op("movaps", fModrm)
  result[0x2A] = op("cvtsi2ss", fModrm, fDstReg)
  result[0x2B] = op("movntps", fModrm)
  result[0x2C] = op("cvttss2si", fModrm, fDstReg)
  result[0x2D] = op("cvtss2si", fModrm, fDstReg)
  result[0x2E] = op("ucomiss", fModrm, fDstReg)
  result[0x2F] = op("comiss", fModrm, fDstReg)
  for i in 0 ..< 16:
    result[0x40 + i] = op("cmov" & CC_NAMES[i], fModrm, fDstReg)
  result[0x31] = op("rdtsc")
  result[0x37] = op("getsec")
  # SSE arithmetic (58-5F): add/mul/sub/div with F2/F3/66 variants
  result[0x51] = op("sqrt", fModrm, fDstReg)
  result[0x54] = op("andps", fModrm, fDstReg)
  result[0x55] = op("andnps", fModrm, fDstReg)
  result[0x56] = op("orps", fModrm, fDstReg)
  result[0x57] = op("xorps", fModrm, fDstReg)
  result[0x58] = op("add", fModrm, fDstReg)
  result[0x59] = op("mul", fModrm, fDstReg)
  result[0x5A] = op("cvtps2pd", fModrm, fDstReg)
  result[0x5B] = op("cvtdq2ps", fModrm, fDstReg)
  result[0x5C] = op("sub", fModrm, fDstReg)
  result[0x5D] = op("min", fModrm, fDstReg)
  result[0x5E] = op("div", fModrm, fDstReg)
  result[0x5F] = op("max", fModrm, fDstReg)
  result[0x60] = op("punpcklbw", fModrm, fDstReg)
  result[0x61] = op("punpcklwd", fModrm, fDstReg)
  result[0x62] = op("punpckldq", fModrm, fDstReg)
  result[0x6E] = op("movd", fModrm, fDstReg)
  result[0x6F] = op("movdqa", fModrm, fDstReg)
  result[0x70] = op("pshuf", fModrm, fDstReg, fImm8)
  result[0x7E] = op("movd", fModrm)
  result[0x7F] = op("movdqa", fModrm)
  for i in 0 ..< 16:
    result[0x80 + i] = op("j" & CC_NAMES[i], fRel32)
  for i in 0 ..< 16:
    result[0x90 + i] = op("set" & CC_NAMES[i], fModrm, fByte)
  result[0xA2] = op("cpuid")
  result[0xA3] = op("bt", fModrm)
  result[0xA4] = op("shld", fModrm, fDstReg, fImm8)
  result[0xA5] = op("shld", fModrm, fDstReg)
  result[0xAB] = op("bts", fModrm)
  result[0xAC] = op("shrd", fModrm, fDstReg, fImm8)
  result[0xAD] = op("shrd", fModrm, fDstReg)
  result[0xAF] = op("imul", fModrm, fDstReg)
  result[0xB0] = op("cmpxchg", fModrm, fByte)
  result[0xB1] = op("cmpxchg", fModrm)
  result[0xB3] = op("btr", fModrm)
  result[0xB6] = op("movzx", fModrm, fByte, fDstReg)
  result[0xB7] = op("movzx", fModrm, fDstReg)
  result[0xB8] = op("popcnt", fModrm, fDstReg)
  result[0xBA] = op("grp8", fModrm, fImm8)
  result[0xBB] = op("btc", fModrm)
  result[0xBC] = op("bsf", fModrm, fDstReg)
  result[0xBD] = op("bsr", fModrm, fDstReg)
  result[0xBE] = op("movsx", fModrm, fByte, fDstReg)
  result[0xBF] = op("movsx", fModrm, fDstReg)
  result[0xC0] = op("xadd", fModrm, fByte)
  result[0xC1] = op("xadd", fModrm)
  result[0xC3] = op("movnti", fModrm)
  result[0xC6] = op("shufp", fModrm, fDstReg, fImm8)
  for i in 0 ..< 8:
    result[0xC8 + i] = op("bswap")

const TABLE1* = buildTable1()
const TABLE2* = buildTable2()

const REG64* = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
const REG32* = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
                "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"]
const REG16* = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
                "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"]
const REG8_REX* = ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
                   "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"]
const REG8_PLAIN* = ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"]
const XMM* = ["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
              "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"]
const SEGREG* = ["es", "cs", "ss", "ds", "fs", "gs", "unused", "unused"]
