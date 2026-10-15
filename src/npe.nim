## npe.nim — PE32/PE32+ parser: headers, sections, import/export tables, .NET.
import ncommon
import std/[strutils]

const
  IMAGE_SCN_MEM_EXECUTE = 0x20000000'u64
  IMAGE_SCN_MEM_READ = 0x40000000'u64
  IMAGE_SCN_MEM_WRITE = 0x80000000'u64

type PeCtx = object
  is64: bool
  optOff: uint64      # optional header offset
  imageBase: uint64
  ddOff: uint64       # data directory offset
  numDir: int
  secOff: uint64
  numSec: int

proc rvaToOff(b: Binary, ctx: PeCtx, rva: uint64): uint64 =
  ## Map RVA to file offset via section table; raw header space maps 1:1.
  if rva == 0: return 0
  for i in 0 ..< ctx.numSec:
    let h = ctx.secOff + uint64(i * 40)
    let vaddr = rdU32(b.data, h + 12)
    let rawSize = rdU32(b.data, h + 16)
    let rawPtr = rdU32(b.data, h + 20)
    let vsize = rdU32(b.data, h + 8)
    let lim = max(rawSize, vsize)
    if rva >= vaddr and rva < vaddr + lim:
      let delta = rva - vaddr
      if delta < rawSize: return rawPtr + delta
      raise necroFail("RVA 0x" & rva.toHex & " points into unmapped tail of section")
  raise necroFail("RVA 0x" & rva.toHex & " not mapped by any section")

proc peFlags(chars: uint64): string =
  result = ""
  result.add(if (chars and IMAGE_SCN_MEM_READ) != 0: "r" else: "-")
  result.add(if (chars and IMAGE_SCN_MEM_WRITE) != 0: "w" else: "-")
  result.add(if (chars and IMAGE_SCN_MEM_EXECUTE) != 0: "x" else: "-")

proc parseSections(b: Binary, ctx: PeCtx) =
  for i in 0 ..< ctx.numSec:
    let h = ctx.secOff + uint64(i * 40)
    var nameBuf = ""
    for j in 0 ..< 8:
      let c = b.data[int(h) + j]
      if c == 0: break
      nameBuf.add(chr(c))
    let vsize = rdU32(b.data, h + 8)
    let vaddr = rdU32(b.data, h + 12)
    let rawSize = rdU32(b.data, h + 16)
    let rawPtr = rdU32(b.data, h + 20)
    let chars = rdU32(b.data, h + 36)
    var ent = SectionRec(
      name: nameBuf, va: ctx.imageBase + vaddr, off: rawPtr,
      size: rawSize, vsize: vsize, flags: peFlags(chars)
    )
    if rawSize > 0 and rawPtr + rawSize <= uint64(b.data.len):
      ent.entropy = shannon(b.data[int(rawPtr) ..< int(rawPtr + rawSize)])
    b.sections.add(ent)

proc readPeStr(b: Binary, rva: uint64): string =
  try:
    let ctx = PeCtx()  # unused
    discard ctx
    # caller supplies offset already; here rva param is actually a file offset
    rdCstr(b.data, rva)
  except NecroError:
    ""

proc parseImports(b: Binary, ctx: PeCtx, dirRva, dirSize: uint64) =
  if dirRva == 0: return
  let descOff = rvaToOff(b, ctx, dirRva)
  var i = 0
  while true:
    let h = descOff + uint64(i * 20)
    if h + 20 > uint64(b.data.len): break
    let oft = rdU32(b.data, h)
    let nameRva = rdU32(b.data, h + 12)
    let ft = rdU32(b.data, h + 16)
    if nameRva == 0 and ft == 0 and oft == 0: break  # terminator
    inc i
    if i > 512: break
    let dllName = rdCstr(b.data, rvaToOff(b, ctx, nameRva))
    if dllName.len > 0: b.dlls.add(dllName)
    var thunkRva = oft
    if thunkRva == 0: thunkRva = ft
    if thunkRva == 0: continue
    let toff = rvaToOff(b, ctx, thunkRva)
    let entSize = if ctx.is64: 8 else: 4
    var j = 0
    while true:
      let e = toff + uint64(j * entSize)
      if e + uint64(entSize) > uint64(b.data.len): break
      let val = if ctx.is64: rdU64(b.data, e) else: rdU32(b.data, e)
      if val == 0: break
      inc j
      if j > 8192: break
      let isOrd = (val and (if ctx.is64: 0x8000000000000000'u64 else: 0x80000000'u64)) != 0
      if isOrd:
        b.imports.add(ImportRec(dll: dllName, name: "", ordinal: int(val and 0xFFFF)))
      else:
        let nOff = rvaToOff(b, ctx, val)
        # IMAGE_IMPORT_BY_NAME: 2-byte hint, then name
        b.imports.add(ImportRec(dll: dllName, name: rdCstr(b.data, nOff + 2), ordinal: 0))

proc parseExports(b: Binary, ctx: PeCtx, dirRva: uint64) =
  if dirRva == 0: return
  let e = rvaToOff(b, ctx, dirRva)
  let nFuncs = rdU32(b.data, e + 20)
  let nNames = rdU32(b.data, e + 24)
  let aFuncs = rvaToOff(b, ctx, rdU32(b.data, e + 28))
  let aNames = rvaToOff(b, ctx, rdU32(b.data, e + 32))
  let aOrds = rvaToOff(b, ctx, rdU32(b.data, e + 36))
  let n = min(nNames, nFuncs)
  for i in 0 ..< min(int(n), 65536):
    let nameRva = rdU32(b.data, aNames + uint64(i * 4))
    let ordIdx = rdU16(b.data, aOrds + uint64(i * 2))
    if nameRva == 0: continue
    let nm = rdCstr(b.data, rvaToOff(b, ctx, nameRva))
    var fnAddr: uint64 = 0
    if int(ordIdx) < int(nFuncs):
      fnAddr = rdU32(b.data, aFuncs + ordIdx * 4)
    b.exportsList.add(ExportRec(name: nm, va: ctx.imageBase + fnAddr, ordinal: int(ordIdx) + 1))

proc parsePe*(b: Binary) =
  let d = b.data
  b.format = fmtPE
  b.endian = "little"
  let peOff = rdU32(d, 0x3C)
  if peOff + 24 > uint64(d.len): raise necroFail("truncated PE header")
  if d[int(peOff)] != 0x50 or d[int(peOff)+1] != 0x45:
    raise necroFail("bad PE signature")
  let machine = rdU16(d, peOff + 4)
  b.arch = case machine
    of 0x8664: "x86-64"
    of 0x14C: "x86"
    of 0xAA64: "aarch64"
    of 0x1C0: "arm"
    of 0x1C4: "armnt"
    of 0x0200: "ia64"
    else: "machine " & machine.toHex
  let nsec = int(rdU16(d, peOff + 6))
  let optSize = int(rdU16(d, peOff + 20))
  let chars = rdU16(d, peOff + 22)
  let optOff = peOff + 24
  let magic = rdU16(d, optOff)
  var ctx: PeCtx
  ctx.optOff = optOff
  ctx.numSec = nsec
  ctx.secOff = optOff + uint64(optSize)
  if magic == 0x20B:
    ctx.is64 = true
    b.bits = 64
    b.entry = rdU64(d, optOff + 16)
    ctx.imageBase = rdU64(d, optOff + 24)
    ctx.ddOff = optOff + 112
    ctx.numDir = int(rdU32(d, optOff + 108))
    b.kind = if (chars and 0x2000) != 0: "driver" else: "executable"
  elif magic == 0x10B:
    ctx.is64 = false
    b.bits = 32
    b.entry = rdU32(d, optOff + 16)
    ctx.imageBase = rdU32(d, optOff + 28)
    ctx.ddOff = optOff + 96
    ctx.numDir = int(rdU32(d, optOff + 92))
    b.kind = if (chars and 0x2000) != 0: "driver" else: "executable"
  else:
    raise necroFail("unknown optional header magic 0x" & magic.toHex)
  b.imageBase = ctx.imageBase
  parseSections(b, ctx)
  if ctx.numDir >= 15:
    let expRva = rdU32(d, ctx.ddOff + 0 * 8)
    let impRva = rdU32(d, ctx.ddOff + 1 * 8)
    let comRva = rdU32(d, ctx.ddOff + 14 * 8)
    let comSize = rdU32(d, ctx.ddOff + 14 * 8 + 4)
    b.dotnet = comRva != 0 and comSize > 0
    if b.dotnet: b.kind = ".NET assembly"
    parseImports(b, ctx, impRva, 0)
    parseExports(b, ctx, expRva)
  var best = 0'u64
  for s in b.sections:
    if 'x' in s.flags and s.size > best:
      best = s.size
      b.textStart = s.va
      b.textSize = s.size
