## ndisasm.nim — built-in x86-64 disassembler (no capstone, no tables on disk).
## Length-accurate decode with Intel-syntax rendering, RIP-relative resolution
## and branch metadata for the function/call-graph passes.
import ncommon, ndis_tables
import std/[strutils]

type
  Branch* = enum brNone, brCall, brJmp, brJcc, brRet

  Insn* = object
    va*: uint64          # virtual address of the instruction
    size*: int
    text*: string
    branch*: Branch
    target*: uint64      # resolved branch target (call/jmp/jcc)
    memRef*: uint64      # resolved RIP-relative data address (0 = none)

proc signExt64(v: uint64, bits: int): int64 =
  let shift = 64 - bits
  cast[int64](v shl shift) shr shift

proc hxs(v: uint64): string =
  ## minimal-width hex (0x10, not 0x0000000000000010)
  var s = v.toHex.toLowerAscii
  var i = 0
  while i < s.len - 1 and s[i] == '0':
    inc i
  "0x" & s[i ..^ 1]

proc renderSigned(v: int64): string =
  if v == low(int64): "-0x8000000000000000"
  elif v < 0: "-" & hxs(cast[uint64](-v))
  else: hxs(cast[uint64](v))

proc memString(base, index: int, scale: int, disp: int64, ripRel: bool,
               ripTarget: uint64): string =
  if ripRel:
    var s = "[rip"
    if disp != 0:
      s.add(if disp < 0: "-" & hxs(cast[uint64](-disp)) else: "+" & hxs(cast[uint64](disp)))
    s.add("]")
    if ripTarget != 0: s.add(" ; " & hx(ripTarget))
    return s
  var parts: seq[string] = @[]
  if base >= 0: parts.add(REG64[base])
  if index >= 0: parts.add(REG64[index] & "*" & $scale)
  var s = "["
  var first = true
  for p in parts:
    if not first: s.add("+")
    s.add(p)
    first = false
  if disp != 0 or parts.len == 0:
    if not first: s.add(if disp < 0: "" else: "+")
    if disp < 0: s.add("-" & hxs(cast[uint64](-disp)))
    else: s.add(hxs(cast[uint64](disp)))
  s.add("]")
  s

proc sizeName(sz: int): string =
  case sz
  of 1: "byte ptr "
  of 2: "word ptr "
  of 4: "dword ptr "
  of 8: "qword ptr "
  else: ""

proc decodeInsn*(data: openArray[byte], fileOff: uint64, va: uint64): Insn =
  ## Decode one instruction. `fileOff` is the offset in `data`, `va` its
  ## virtual address. Always advances by a valid length (>= 1).
  result.va = va
  result.branch = brNone
  var off = fileOff
  var lock = false
  var repne = false
  var rep = false
  var osize66 = false
  var rexW = false
  var rexR = 0
  var rexX = 0
  var rexB = 0
  var anyRex = false
  var segPrefix = ""

  template guard(extra: int) =
    if off + uint64(extra) > uint64(data.len):
      result.text = ".byte 0x" & toHex(int(data[data.len - 1]), 2).toLowerAscii
      result.size = 1
      return

  # ---------------- prefixes
  var prefixBudget = 15
  while prefixBudget > 0:
    guard(1)
    let p = data[int(off)]
    case p
    of 0xF0: lock = true
    of 0xF2: repne = true; rep = false
    of 0xF3: rep = true; repne = false
    of 0x66: osize66 = true
    of 0x67: discard
    of 0x2E, 0x36, 0x3E, 0x26: discard
    of 0x64: segPrefix = "fs"
    of 0x65: segPrefix = "gs"
    of 0x40..0x4F:
      anyRex = true
      rexW = (p and 8) != 0
      rexR = if (p and 4) != 0: 8 else: 0
      rexX = if (p and 2) != 0: 8 else: 0
      rexB = if (p and 1) != 0: 8 else: 0
    else: break
    inc off
    dec prefixBudget

  guard(1)
  let op1 = data[int(off)]
  inc off
  var two = false
  var op2 = 0
  if op1 == 0x0F:
    guard(1)
    two = true
    op2 = int(data[int(off)])
    inc off
  let oi = (if two: TABLE2[op2] else: TABLE1[int(op1)])
  var mn = oi.mn
  var osz = if rexW: 8 elif osize66: 2 else: 4

  # ---------------- invalid / raw fallback
  if fInv64 in oi.flags:
    result.text = ".byte 0x" & toHex(int(op1), 2).toLowerAscii
    result.size = int(off - fileOff)
    return

  # ---------------- ModRM stage
  var modrm = 0
  var modv, regv, rmv = 0
  var memStr = ""
  var memSize = 0
  var ripRel = false
  var ripTarget: uint64 = 0
  var haveMem = false
  if fModrm in oi.flags:
    guard(1)
    modrm = int(data[int(off)])
    inc off
    modv = (modrm shr 6) and 3
    regv = ((modrm shr 3) and 7) or rexR
    rmv = (modrm and 7) or rexB
    if modv != 3 and (modrm and 7) == 4:
      guard(1)
      let sib = int(data[int(off)])
      inc off
      let scale = 1 shl ((sib shr 6) and 3)
      var idx = ((sib shr 3) and 7) or rexX
      var base = (sib and 7) or rexB
      if idx >= 8: idx = idx - 8
      if base >= 8: base = base - 8
      var disp: int64 = 0
      if (sib and 7) == 5 and modv == 0:
        guard(4)
        disp = signExt64(rdN(data, off, 4), 32)
        off += 4
        base = -1
      elif modv == 1:
        guard(1)
        disp = signExt64(rdN(data, off, 1), 8)
        off += 1
      elif modv == 2:
        guard(4)
        disp = signExt64(rdN(data, off, 4), 32)
        off += 4
      haveMem = true
      memSize = (if fByte in oi.flags: 1 else: osz)
      memStr = memString(base, idx, scale, disp, false, 0)
    elif modv == 0 and (modrm and 7) == 5:
      guard(4)
      let disp = signExt64(rdN(data, off, 4), 32)
      off += 4
      haveMem = true
      ripRel = true
      ripTarget = va + uint64(off - fileOff) + cast[uint64](disp)
      result.memRef = ripTarget
      memSize = (if fByte in oi.flags: 1 else: osz)
      memStr = memString(-1, -1, 1, disp, true, ripTarget)
    elif modv == 1:
      guard(1)
      let disp = signExt64(rdN(data, off, 1), 8)
      off += 1
      haveMem = true
      memSize = (if fByte in oi.flags: 1 else: osz)
      memStr = memString(rmv, -1, 1, disp, false, 0)
    elif modv == 2:
      guard(4)
      let disp = signExt64(rdN(data, off, 4), 32)
      off += 4
      haveMem = true
      memSize = (if fByte in oi.flags: 1 else: osz)
      memStr = memString(rmv, -1, 1, disp, false, 0)
    else:
      haveMem = false

  proc regName(idx: int, size: int): string =
    case size
    of 1: (if anyRex: REG8_REX[idx] else: REG8_PLAIN[idx])
    of 2: REG16[idx]
    of 8: REG64[idx]
    else: REG32[idx]

  # ---------------- immediate stage (conditional for groups)
  var imm8: int64 = 0
  var immZ: int64 = 0
  var haveImm8 = false
  var haveImmZ = false
  var immBytes = 0

  template readImm8() =
    guard(1)
    imm8 = signExt64(rdN(data, off, 1), 8)
    off += 1
    haveImm8 = true
    inc immBytes

  template readImmZ() =
    let n = if osize66: 2 else: 4
    guard(n)
    immZ = signExt64(rdN(data, off, n), n * 8)
    off += uint64(n)
    haveImmZ = true
    inc immBytes

  if mn == "grp3":
    if (regv and 7) < 2:
      if fByte in oi.flags: readImm8() else: readImmZ()
  elif mn == "grp1":
    if op1 == 0x83:
      readImm8()
    else:
      readImmZ()
  elif fImm8 in oi.flags:
    readImm8()
  elif fImmZ in oi.flags:
    if rexW and op1 >= 0xB8 and op1 <= 0xBF:
      # mov r64, imm64 (B8-BF with REX.W): full 8-byte immediate
      guard(8)
      immZ = cast[int64](rdN(data, off, 8))
      off += 8
      haveImmZ = true
      inc immBytes
    else:
      readImmZ()
  elif fImm64 in oi.flags:
    guard(8)
    immZ = cast[int64](rdN(data, off, 8))
    off += 8
    haveImmZ = true
    inc immBytes

  # ---------------- rel branches
  if fRel8 in oi.flags:
    guard(1)
    let d = signExt64(rdN(data, off, 1), 8)
    off += 1
    result.target = va + uint64(off - fileOff) + cast[uint64](d)
    case op1
    of 0xE8: result.branch = brCall
    of 0xE9, 0xEB: result.branch = brJmp
    else: result.branch = brJcc
  elif fRel32 in oi.flags:
    guard(4)
    let d = signExt64(rdN(data, off, 4), 32)
    off += 4
    result.target = va + uint64(off - fileOff) + cast[uint64](d)
    if op1 == 0xE8: result.branch = brCall
    else: result.branch = brJmp

  # ---------------- branch classification for non-branch opcodes
  if result.branch == brNone and not two:
    if op1 in {0xC3, 0xC2, 0xCA, 0xCB}:
      result.branch = brRet

  # ---------------- operand assembly
  var operands: seq[string] = @[]
  var sizeHint = (if fByte in oi.flags: 1 else: osz)

  template memOperand(): string =
    sizeName(memSize) & memStr

  template rmOperand(): string =
    if haveMem: memOperand() else: regName(rmv, sizeHint)

  template regOperand(): string =
    regName(regv, sizeHint)

  if mn == "grp1":
    mn = GRP1_NAMES[regv and 7]
    operands.add(rmOperand())
    if haveImm8:
      operands.add(renderSigned(imm8))
    else:
      operands.add(renderSigned(immZ))
  elif mn == "grp2":
    mn = GRP2_NAMES[regv and 7]
    operands.add(rmOperand())
    if op1 == 0xD0 or op1 == 0xD1: operands.add("1")
    elif op1 == 0xD2 or op1 == 0xD3: operands.add("cl")
    else: operands.add("0x" & toHex(int(imm8) and 0xFF, 2).toLowerAscii)
  elif mn == "grp3":
    let g = regv and 7
    if g < 2:
      mn = "test"
      operands.add(rmOperand())
      if fByte in oi.flags:
        operands.add("0x" & toHex(int(imm8) and 0xFF, 2).toLowerAscii)
      else:
        operands.add(renderSigned(immZ))
    else:
      mn = GRP3_NAMES8[g]
      operands.add(rmOperand())
  elif mn == "grp4":
    mn = (if (regv and 7) == 0: "inc" else: "dec")
    operands.add(rmOperand())
  elif mn == "grp5":
    let g = regv and 7
    case g
    of 0: mn = "inc"
    of 1: mn = "dec"
    of 2:
      mn = "call"
      result.branch = brCall
      if ripRel: result.target = ripTarget
    of 3: mn = "lcall"
    of 4:
      mn = "jmp"
      result.branch = brJmp
      if ripRel: result.target = ripTarget
    of 5: mn = "ljmp"
    else: mn = "push"
    operands.add(rmOperand())
  elif mn == "grp8":
    let g = regv and 7
    mn = case g
      of 4: "bt"
      of 5: "bts"
      of 6: "btr"
      else: "btc"
    operands.add(rmOperand())
    operands.add("0x" & toHex(int(imm8) and 0xFF, 2).toLowerAscii)
  elif mn == "popcnt":
    if not rep:
      result.text = ".byte 0x" & toHex(int(op2), 2).toLowerAscii
      result.size = 1
      return
    operands.add(regOperand())
    operands.add(rmOperand())
  elif mn == "endbr":
    if rep and modrm == 0xFA: mn = "endbr64"
    elif rep and modrm == 0xFB: mn = "endbr32"
    else: mn = "nop"
  elif two and op2 in {0x10, 0x11, 0x12, 0x13, 0x16, 0x17, 0x28, 0x29, 0x2A,
                       0x2C, 0x2D, 0x51, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D,
                       0x5E, 0x5F}:
    # SSE family with F2/F3/66 variants
    var suffix = "ps"
    if repne: suffix = "sd"
    elif rep: suffix = "ss"
    elif osize66: suffix = "pd"
    mn = case op2
      of 0x10: (if rep: "movss" elif repne: "movsd" elif osize66: "movupd" else: "movups")
      of 0x11: (if rep: "movss" elif repne: "movsd" elif osize66: "movupd" else: "movups")
      of 0x12: "movlps"
      of 0x13: "movlps"
      of 0x16: "movhps"
      of 0x17: "movhps"
      of 0x28: (if osize66: "movapd" else: "movaps")
      of 0x29: (if osize66: "movapd" else: "movaps")
      of 0x2A: "cvtsi2" & suffix
      of 0x2C: "cvtt" & suffix & "2si"
      of 0x2D: "cvt" & suffix & "2si"
      of 0x51: "sqrt" & suffix
      of 0x58: "add" & suffix
      of 0x59: "mul" & suffix
      of 0x5A: "cvtps2pd"
      of 0x5B: "cvtdq2ps"
      of 0x5C: "sub" & suffix
      of 0x5D: "min" & suffix
      of 0x5E: "div" & suffix
      else: "max" & suffix
    let srcX = if haveMem: memStr else: "xmm" & $(rmv)
    if op2 in {0x11, 0x13, 0x17, 0x29}:
      operands.add(srcX)
      operands.add("xmm" & $regv)
    else:
      operands.add("xmm" & $regv)
      operands.add(srcX)
  elif two and op2 in {0x6E, 0x6F, 0x7E, 0x7F}:
    mn = case op2
      of 0x6E: (if osize66: "movq" else: "movd")
      of 0x6F: (if osize66: "movdqa" elif rep: "movdqu" else: "movq")
      of 0x7E: (if osize66 or rep: "movq" else: "movd")
      else: (if osize66: "movdqa" elif rep: "movdqu" else: "movq")
    let srcX = if haveMem: memStr else: "xmm" & $(rmv)
    if op2 in {0x7E, 0x7F}:
      operands.add(srcX); operands.add("xmm" & $regv)
    else:
      operands.add("xmm" & $regv); operands.add(srcX)
  elif two and op2 in {0x70, 0xC6}:
    mn = (if op2 == 0x70: "pshufd" else: "shufpd")
    operands.add("xmm" & $regv)
    operands.add(if haveMem: memStr else: "xmm" & $(rmv))
    operands.add("0x" & toHex(int(imm8) and 0xFF, 2).toLowerAscii)
  elif two and op2 in {0xA4, 0xAC}:
    mn = (if op2 == 0xA4: "shld" else: "shrd")
    operands.add(rmOperand())
    operands.add(regName(regv, osz))
    operands.add("0x" & toHex(int(imm8) and 0xFF, 2).toLowerAscii)
  elif two and op2 in {0xA5, 0xAD}:
    mn = (if op2 == 0xA5: "shld" else: "shrd")
    operands.add(rmOperand())
    operands.add(regName(regv, osz))
    operands.add("cl")
  elif two and op2 in {0xB6, 0xB7, 0xBE, 0xBF}:
    let srcSz = (if op2 in {0xB6, 0xBE}: 1 else: 2)
    mn = (if op2 in {0xB6, 0xB7}: "movzx" else: "movsx")
    operands.add(regOperand())
    if haveMem:
      operands.add(sizeName(srcSz) & memStr)
    else:
      operands.add(regName(rmv, srcSz))
  elif op1 == 0x69 or op1 == 0x6B:
    mn = "imul"
    operands.add(regOperand())
    operands.add(rmOperand())
    if op1 == 0x69: operands.add(renderSigned(immZ))
    else: operands.add(renderSigned(imm8))
  elif op1 == 0xC6 or op1 == 0xC7:
    mn = "mov"
    operands.add(rmOperand())
    if op1 == 0xC6:
      operands.add("0x" & toHex(int(imm8) and 0xFF, 2).toLowerAscii)
    else:
      operands.add(hxs(cast[uint64](immZ) and 0xFFFFFFFF'u64))
  elif op1 == 0x8F:
    mn = "pop"
    operands.add(rmOperand())
  elif op1 == 0xC8:
    guard(3)
    let imm16 = rdN(data, off, 2)
    let lvl = data[int(off) + 2]
    off += 3
    mn = "enter"
    operands.add(hx(imm16))
    operands.add(hx(uint64(lvl)))
  elif mn == "fpu":
    mn = "x87"
    operands.add(rmOperand())
  elif fModrm in oi.flags:
    if op1 == 0x8D:
      mn = "lea"
      operands.add(regOperand())
      operands.add(if haveMem: memStr else: regName(rmv, 8))
    elif two and op2 == 0xAF:
      mn = "imul"
      operands.add(regOperand())
      operands.add(rmOperand())
    elif op1 == 0x8C:
      operands.add(rmOperand())
      operands.add(SEGREG[regv and 7])
    elif op1 == 0x8E:
      operands.add(SEGREG[regv and 7])
      operands.add(rmOperand())
    elif fDstReg in oi.flags:
      operands.add(regOperand())
      operands.add(rmOperand())
    else:
      operands.add(rmOperand())
      operands.add(regOperand())
  elif fMoffs in oi.flags:
    guard(8)
    let m = rdN(data, off, 8)
    off += 8
    let acc = (if fByte in oi.flags: "al" elif osize66: "ax" elif rexW: "rax" else: "eax")
    if op1 == 0xA2 or op1 == 0xA3:
      operands.add("[" & hx(m) & "]")
      operands.add(acc)
    else:
      operands.add(acc)
      operands.add("[" & hx(m) & "]")
  elif haveImm8 or haveImmZ:
    if (int(op1) and 0xC7) in {0x04, 0x05} and op1 <= 0x3D:
      # ALU with accumulator: ADD AL/eAX, imm
      let acc = (if fByte in oi.flags: "al" elif osize66: "ax" elif rexW: "rax" else: "eax")
      operands.add(acc)
      if fByte in oi.flags:
        operands.add("0x" & toHex(int(imm8) and 0xFF, 2).toLowerAscii)
      else:
        operands.add(hxs(cast[uint64](immZ) and (if osize66: 0xFFFF'u64 else: 0xFFFFFFFF'u64)))
    elif op1 in {0xE4, 0xE5, 0xE6, 0xE7}:
      let p8 = "0x" & toHex(int(imm8) and 0xFF, 2).toLowerAscii
      let acc = (if fByte in oi.flags: "al" else: "eax")
      if op1 <= 0xE5: operands.add(acc); operands.add(p8)
      else: operands.add(p8); operands.add(acc)
    elif op1 in {0xEC, 0xED, 0xEE, 0xEF}:
      let acc = (if fByte in oi.flags: "al" else: "eax")
      if op1 <= 0xED: operands.add(acc); operands.add("dx")
      else: operands.add("dx"); operands.add(acc)
    elif op1 >= 0xB8 and op1 <= 0xBF:
      let ri = (int(op1) and 7) or rexB
      operands.add(regName(ri, if rexW: 8 elif osize66: 2 else: 4))
      operands.add(renderSigned(immZ))
    elif op1 >= 0xB0 and op1 <= 0xB7:
      let ri = (int(op1) and 7) or rexB
      operands.add(regName(ri, 1))
      operands.add("0x" & toHex(int(imm8) and 0xFF, 2).toLowerAscii)
    elif op1 == 0xA8:
      operands.add("al")
      operands.add("0x" & toHex(int(imm8) and 0xFF, 2).toLowerAscii)
    elif op1 == 0xA9:
      operands.add((if rexW: "rax" elif osize66: "ax" else: "eax"))
      operands.add(renderSigned(immZ))
    elif op1 == 0x68 or op1 == 0x6A:
      operands.add(renderSigned(if op1 == 0x68: immZ else: imm8))
    elif fByte in oi.flags:
      operands.add("0x" & toHex(int(imm8) and 0xFF, 2).toLowerAscii)
    else:
      operands.add(hxs(cast[uint64](immZ) and 0xFFFFFFFF'u64))
  elif fRel8 in oi.flags or fRel32 in oi.flags:
    operands.add(hx(result.target))
  else:
    if op1 >= 0x50 and op1 <= 0x5F:
      let ri = (int(op1) and 7) or rexB
      operands.add(REG64[ri])
    elif op1 >= 0x91 and op1 <= 0x97:
      let ri = (int(op1) and 7) or rexB
      operands.add("rax"); operands.add(REG64[ri])
    elif two and op2 >= 0xC8 and op2 <= 0xCF:
      operands.add(REG64[(int(op2) and 7) or rexB])
    elif op1 == 0x98 or op1 == 0x99:
      discard  # cdqe/cqo take no operands

  # ---------------- text assembly
  var m = mn
  if m == ".byte":
    result.text = ".byte 0x" & toHex((if two: op2 else: int(op1)), 2).toLowerAscii
    result.size = 1
    return
  if lock: m = "lock " & m
  if rep and not two and op1 == 0x90:
    m = "pause"
  elif repne and fStr in oi.flags:
    m = "repne " & m
  elif rep and fStr in oi.flags:
    m = "rep " & m
  if segPrefix.len > 0 and haveMem and not ripRel:
    m = segPrefix & " " & m
  if operands.len > 0:
    result.text = m & " " & operands.join(", ")
  else:
    result.text = m
  result.size = int(off - fileOff)
