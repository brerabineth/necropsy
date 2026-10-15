## ncommon.nim — shared types + bounded binary reading primitives.
## Every read is bounds-checked; malformed input raises NecroError,
## which the CLI converts into a clean error message and exit 64.
import std/[strutils, math, algorithm]

type
  NecroError* = object of CatchableError

  Format* = enum fmtUnknown, fmtELF, fmtPE, fmtMachO

  SectionRec* = object
    name*: string
    va*: uint64
    off*: uint64
    size*: uint64       # raw size in file
    vsize*: uint64      # virtual size
    flags*: string      # e.g. "rx", "rw-", "info"
    entropy*: float64

  ImportRec* = object
    dll*: string        # "" when the format carries no per-symbol dll
    name*: string
    ordinal*: int

  ExportRec* = object
    name*: string
    va*: uint64
    ordinal*: int

  SymRec* = object
    name*: string
    va*: uint64
    size*: uint64
    isFunc*: bool

  StrKind* = enum skAscii, skUrl, skIp, skDomain, skPath, skRegistry, skGuid, skB64, skSus

  StringRec* = object
    off*: uint64
    kind*: StrKind
    value*: string

  CryptoRec* = object
    name*: string
    off*: uint64
    note*: string

  Binary* = ref object
    path*: string
    displayPath*: string   # as shown in reports (never an absolute host path)
    data*: seq[byte]
    format*: Format
    bits*: int
    arch*: string
    endian*: string
    kind*: string          # executable / shared object / driver / ...
    entry*: uint64
    imageBase*: uint64
    sections*: seq[SectionRec]
    imports*: seq[ImportRec]
    exportsList*: seq[ExportRec]
    symbols*: seq[SymRec]
    dlls*: seq[string]
    textStart*: uint64
    textSize*: uint64
    compiler*: string
    packer*: string
    dotnet*: bool

const
  MAX_FILE* = 512 * 1024 * 1024
  MAX_STRING_SHOW* = 120

proc necroFail*(msg: string): ref NecroError =
  result = newException(NecroError, msg)

# ---------------------------------------------------------------- reading
proc rdU8*(d: openArray[byte], off: uint64): uint64 =
  if off >= uint64(d.len): raise necroFail("read past end of file (offset 0x" & off.toHex & ")")
  uint64(d[int(off)])

proc rdN*(d: openArray[byte], off: uint64, n: int, be = false): uint64 =
  ## Read n bytes little-endian (or big-endian) as an unsigned integer.
  if off + uint64(n) > uint64(d.len): raise necroFail("read past end of file (offset 0x" & off.toHex & ")")
  var v: uint64 = 0
  for i in 0 ..< n:
    let b = uint64(d[int(off) + i])
    if be: v = (v shl 8) or b
    else: v = v or (b shl (8 * i))
  v

proc rdU16*(d: openArray[byte], off: uint64, be = false): uint64 = rdN(d, off, 2, be)
proc rdU32*(d: openArray[byte], off: uint64, be = false): uint64 = rdN(d, off, 4, be)
proc rdU64*(d: openArray[byte], off: uint64, be = false): uint64 = rdN(d, off, 8, be)

proc rdCstr*(d: openArray[byte], off: uint64, maxLen = 4096): string =
  ## NUL-terminated string read, bounds-checked and length-capped.
  if off > uint64(d.len): raise necroFail("string offset out of range (0x" & off.toHex & ")")
  var i = int(off)
  let cap = min(d.len, i + maxLen)
  while i < cap and d[i] != 0:
    inc i
  var s = newStringOfCap(min(256, i - int(off)))
  for j in int(off) ..< i:
    s.add chr(d[j])
  s

proc rdBytes*(d: openArray[byte], off: uint64, n: int): seq[byte] =
  if off + uint64(n) > uint64(d.len): raise necroFail("range out of bounds (0x" & off.toHex & " +" & $n & ")")
  result = newSeq[byte](n)
  for i in 0 ..< n: result[i] = d[int(off) + i]

# ---------------------------------------------------------------- helpers
proc hx*(v: uint64): string = "0x" & v.toHex.toLowerAscii

proc baseName*(p: string): string =
  let norm = p.replace('\\', '/')
  let idx = norm.rfind('/')
  if idx >= 0: norm[idx + 1 .. ^1] else: norm

proc shannon*(bytes: openArray[byte]): float64 =
  ## Shannon entropy in bits/byte (0..8).
  if bytes.len == 0: return 0.0
  var freq: array[256, int]
  for b in bytes: inc freq[b]
  var ent = 0.0
  let n = float64(bytes.len)
  for c in freq:
    if c > 0:
      let p = float64(c) / n
      ent -= p * log2(p)
  ent

proc printableChar*(b: byte): bool =
  (b >= 0x20 and b <= 0x7E) or b == 0x09

proc sanitize*(s: string, keep = MAX_STRING_SHOW): string =
  ## Make a byte string safe to print: cut, strip non-printables.
  var outp = newStringOfCap(min(s.len, keep))
  for i in 0 ..< min(s.len, keep):
    let c = s[i]
    outp.add(if printableChar(byte(ord(c))): c else: '.')
  outp

proc trunc*(s: string, keep = MAX_STRING_SHOW): string =
  if s.len <= keep: s
  else: s[0 ..< keep - 1] & "\xE2\x80\xA6"

proc fmtEntropy*(e: float64): string =
  e.formatFloat(ffDecimal, 2)

proc bandColor*(score: int): string =
  if score >= 60: "196"    # red
  elif score >= 30: "208"  # orange
  elif score >= 10: "220"  # yellow
  else: "82"               # green

proc verdictOf*(score: int): string =
  if score >= 60: "CRITICAL"
  elif score >= 30: "SUSPECT"
  elif score >= 10: "LOW"
  else: "CLEAN"

proc verdictExit*(score: int): int =
  if score >= 60: 3
  elif score >= 30: 2
  elif score >= 10: 1
  else: 0

proc scoreExit*(band: string): int =
  case band
  of "CRITICAL": 3
  of "SUSPECT": 2
  of "LOW": 1
  else: 0

# ---------------------------------------------------------------- format detect
proc detectFormat*(d: openArray[byte]): Format =
  if d.len >= 4 and d[0] == 0x7f and d[1] == 0x45 and d[2] == 0x4c and d[3] == 0x46: fmtELF
  elif d.len >= 2 and d[0] == 0x4d and d[1] == 0x5a: fmtPE
  elif d.len >= 4:
    let m = rdU32(d, 0)
    if m == 0xFEEDFACF'u64 or m == 0xCFFAEDFE'u64 or m == 0xFEEDFACE'u64 or m == 0xCEFAEDFE'u64: fmtMachO
    else: fmtUnknown
  else: fmtUnknown

proc loadFile*(path: string, displayPath = ""): Binary =
  var f: File
  if not f.open(path, fmRead):
    raise necroFail("cannot open file: " & path)
  defer: f.close()
  let size = f.getFileSize()
  if size == 0: raise necroFail("empty file")
  if size > MAX_FILE:
    raise necroFail("file too large (" & $size & " bytes, cap is " & $MAX_FILE & ")")
  var data = newSeq[byte](int(size))
  let got = f.readBytes(data, 0, int(size))
  if got != int(size): raise necroFail("short read")
  result = Binary(
    path: path,
    displayPath: (if displayPath.len > 0: displayPath else: baseName(path)),
    data: data,
    format: detectFormat(data)
  )
