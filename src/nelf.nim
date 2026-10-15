## nelf.nim — ELF32/ELF64 parser (little & big endian), from scratch.
import ncommon
import std/[strutils, algorithm]

type ElfCtx = object
  be: bool
  is64: bool
  shoff: uint64
  shentsize, shnum, shstrndx: int
  symtabIdx: int      # .symtab section index (-1 none)
  dynsymIdx: int      # .dynsym section index (-1 none)
  dynstrIdx: int
  strtabIdx: int

proc secName(ctx: ElfCtx, d: openArray[byte], idx: int): string =
  if ctx.shstrndx < 0 or ctx.shstrndx >= ctx.shnum: return ""
  let strOff = ctx.shoff + uint64(ctx.shstrndx * ctx.shentsize) + 16  # sh_name at 0
  discard strOff
  result = ""

proc parseSections(b: Binary, ctx: var ElfCtx) =
  let d = b.data
  b.sections = @[]
  if ctx.shoff == 0 or ctx.shentsize == 0 or ctx.shnum == 0:
    return
  # first read section[0] for extended numbering
  var shnum = ctx.shnum
  if shnum == 0 and ctx.shoff + 64 <= uint64(d.len):
    let ext = rdU32(d, ctx.shoff + 32, ctx.be)  # sh_size of section header 0
    shnum = int(ext)
  for i in 0 ..< shnum:
    let h = ctx.shoff + uint64(i * ctx.shentsize)
    if h + uint64(ctx.shentsize) > uint64(d.len): break
    var nameOff: uint64
    var shType, shFlags, shAddr, shOff, shSize: uint64
    if ctx.is64:
      nameOff = rdU32(d, h, ctx.be)
      shType = rdU32(d, h + 4, ctx.be)
      shFlags = rdU64(d, h + 8, ctx.be)
      shAddr = rdU64(d, h + 16, ctx.be)
      shOff = rdU64(d, h + 24, ctx.be)
      shSize = rdU64(d, h + 32, ctx.be)
    else:
      nameOff = rdU32(d, h, ctx.be)
      shType = rdU32(d, h + 4, ctx.be)
      shFlags = rdU32(d, h + 8, ctx.be)
      shAddr = rdU32(d, h + 12, ctx.be)
      shOff = rdU32(d, h + 16, ctx.be)
      shSize = rdU32(d, h + 20, ctx.be)
    var flags = ""
    let w = (shFlags and 1) != 0
    let a = (shFlags and 2) != 0
    let x = (shFlags and 4) != 0
    flags.add(if a: "r" else: "-")
    flags.add(if w: "w" else: "-")
    flags.add(if x: "x" else: "-")
    var name = ""
    if ctx.shstrndx > 0 and ctx.shstrndx < shnum:
      let sh = ctx.shoff + uint64(ctx.shstrndx * ctx.shentsize)
      let strOff = (if ctx.is64: rdU64(d, sh + 24, ctx.be) else: rdU32(d, sh + 16, ctx.be))
      if nameOff > 0:
        try: name = rdCstr(d, strOff + nameOff)
        except NecroError: name = ""
    let szInFile = (if shType == 8: 0'u64 else: shSize)  # NOBITS occupies no file bytes
    var ent = SectionRec(
      name: name, va: shAddr, off: shOff, size: szInFile, vsize: shSize, flags: flags
    )
    if shType != 8 and szInFile > 0 and shOff + szInFile <= uint64(d.len):
      ent.entropy = shannon(d[int(shOff) ..< int(shOff + szInFile)])
    b.sections.add(ent)

proc findSec(b: Binary, name: string): int =
  result = -1
  for i, s in b.sections:
    if s.name == name: return i

proc symName(b: Binary, strSec: int, off: uint64): string =
  if strSec < 0 or strSec >= b.sections.len: return ""
  let s = b.sections[strSec]
  if s.size == 0 or off >= s.size: return ""
  try: rdCstr(b.data, s.off + off)
  except NecroError: ""

proc parseSyms(b: Binary, ctx: ElfCtx, symSec, strSec: int, onlyDyn: bool) =
  ## Parse a symbol table section into b.symbols.
  if symSec < 0 or symSec >= b.sections.len: return
  let s = b.sections[symSec]
  if s.size == 0 or s.off == 0: return
  let entSize = if ctx.is64: 24 else: 16
  let count = int(s.size div uint64(entSize))
  if count > 500_000: return  # sanity cap
  const sttFunc: uint64 = 2
  for i in 0 ..< count:
    let off = s.off + uint64(i * entSize)
    var nameOff: uint64
    var info: uint64
    var shndx: uint64
    var value, size: uint64
    if ctx.is64:
      nameOff = rdU32(b.data, off, ctx.be)
      info = rdU8(b.data, off + 4)
      shndx = rdU16(b.data, off + 6, ctx.be)
      value = rdU64(b.data, off + 8, ctx.be)
      size = rdU64(b.data, off + 16, ctx.be)
    else:
      nameOff = rdU32(b.data, off, ctx.be)
      info = rdU8(b.data, off + 4)
      shndx = rdU16(b.data, off + 12, ctx.be)
      value = rdU32(b.data, off + 4, ctx.be)
      size = rdU32(b.data, off + 8, ctx.be)
    let typ = info and 0xF
    let name = b.symName(strSec, nameOff)
    if name.len == 0: continue
    if shndx == 0:
      # UNDEF -> imported symbol
      if onlyDyn:
        b.imports.add(ImportRec(dll: "", name: name, ordinal: 0))
      continue
    if typ == sttFunc:
      b.symbols.add(SymRec(name: name, va: value, size: size, isFunc: true))

proc parseDynNeeded(b: Binary, ctx: ElfCtx) =
  ## Walk .dynamic for DT_NEEDED -> resolve names from .dynstr.
  if ctx.dynsymIdx < 0 and ctx.dynstrIdx < 0: return
  let dynIdx = block:
    var r = -1
    for i, s in b.sections:
      if s.name == ".dynamic": r = i; break
    r
  if dynIdx < 0: return
  let s = b.sections[dynIdx]
  let entSize = if ctx.is64: 16 else: 8
  let count = int(s.size div uint64(entSize))
  var needed: seq[uint64] = @[]
  for i in 0 ..< min(count, 4096):
    let off = s.off + uint64(i * entSize)
    var tag, val: uint64
    if ctx.is64:
      tag = rdU64(b.data, off, ctx.be); val = rdU64(b.data, off + 8, ctx.be)
    else:
      tag = rdU32(b.data, off, ctx.be); val = rdU32(b.data, off + 4, ctx.be)
    if tag == 0: break
    if tag == 1: needed.add(val)  # DT_NEEDED
  for v in needed:
    let nm = b.symName(ctx.dynstrIdx, v)
    if nm.len > 0: b.dlls.add(nm)

proc parseElf*(b: Binary) =
  let d = b.data
  b.format = fmtELF
  let cls = d[4]
  let dat = d[5]
  if cls == 2: b.bits = 64 else: b.bits = 32
  if dat == 2: b.endian = "big" else: b.endian = "little"
  let be = (dat == 2)
  let etype = rdU16(d, 16, be)
  let mach = rdU16(d, 18, be)
  b.kind = case etype
    of 1: "relocatable"
    of 2: "executable"
    of 3: "shared object"
    of 4: "core dump"
    else: "elf(" & $etype & ")"
  b.arch = case mach
    of 0x03: "x86"
    of 0x3E: "x86-64"
    of 0xB7: "aarch64"
    of 0x28: "arm"
    of 0x08: "mips"
    of 0xF3: "riscv"
    of 0x14: "powerpc"
    of 0x15: "ppc64"
    of 0x02: "sparc"
    else: "machine " & $mach
  if b.bits == 64:
    b.entry = rdU64(d, 24, be)
  else:
    b.entry = rdU32(d, 24, be)
  var ctx: ElfCtx
  ctx.be = be
  ctx.is64 = (b.bits == 64)
  if b.bits == 64:
    ctx.shoff = rdU64(d, 40, be)
    ctx.shentsize = int(rdU16(d, 58, be))
    ctx.shnum = int(rdU16(d, 60, be))
    ctx.shstrndx = int(rdU16(d, 62, be))
  else:
    ctx.shoff = rdU32(d, 32, be)
    ctx.shentsize = int(rdU16(d, 46, be))
    ctx.shnum = int(rdU16(d, 48, be))
    ctx.shstrndx = int(rdU16(d, 50, be))
  ctx.symtabIdx = -1
  ctx.dynsymIdx = -1
  ctx.dynstrIdx = -1
  ctx.strtabIdx = -1
  if ctx.shoff != 0 and ctx.shentsize != 0:
    parseSections(b, ctx)
    for i, s in b.sections:
      case s.name
      of ".symtab": ctx.symtabIdx = i
      of ".dynsym": ctx.dynsymIdx = i
      of ".dynstr": ctx.dynstrIdx = i
      of ".strtab": ctx.strtabIdx = i
      else: discard
    # .dynamic is parsed for DT_NEEDED
    parseDynNeeded(b, ctx)
    # exports: defined dynamic symbols
    if ctx.dynsymIdx >= 0:
      let ds = b.sections[ctx.dynsymIdx]
      let entSize = if ctx.is64: 24 else: 16
      let count = int(ds.size div uint64(entSize))
      for i in 0 ..< min(count, 200_000):
        let off = ds.off + uint64(i * entSize)
        var nameOff, value, size: uint64
        var info, shndx: uint64
        if ctx.is64:
          nameOff = rdU32(d, off, ctx.be)
          info = rdU8(d, off + 4)
          shndx = rdU16(d, off + 6, ctx.be)
          value = rdU64(d, off + 8, ctx.be)
          size = rdU64(d, off + 16, ctx.be)
        else:
          nameOff = rdU32(d, off, ctx.be)
          info = rdU8(d, off + 4)
          shndx = rdU16(d, off + 6, ctx.be)
          value = rdU32(d, off + 4, ctx.be)
          size = rdU32(d, off + 8, ctx.be)
        if shndx != 0 and nameOff != 0:
          let nm = b.symName(ctx.dynstrIdx, nameOff)
          if nm.len > 0:
            b.exportsList.add(ExportRec(name: nm, va: value, ordinal: i))
      b.exportsList.sort() do (x, y: ExportRec) -> int:
        cmp(x.va, y.va)
    # imports + functions from dynamic symbol table
    parseSyms(b, ctx, ctx.dynsymIdx, ctx.dynstrIdx, true)
    parseSyms(b, ctx, ctx.symtabIdx, ctx.strtabIdx, false)
  # executable range for the disassembler: pick the LARGEST exec section
  var best = 0'u64
  for s in b.sections:
    if 'x' in s.flags and s.size > best:
      best = s.size
      b.textStart = s.va
      b.textSize = s.size
