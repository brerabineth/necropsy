## nfinger.nim — compiler, packer and runtime fingerprinting.
## Needles are assembled at runtime so the scanner never flags itself
## (the needle literals are not contiguous in .rodata).
import ncommon, nstrings
import std/[strutils]

proc hasSectionSub(b: Binary, sub: string): bool =
  for s in b.sections:
    if sub in s.name.toLowerAscii: return true
  false

proc fromCodes(codes: openArray[int]): string =
  ## Runtime-assembled needles: the compiler cannot fold these into
  ## contiguous .rodata literals, so necropsy never flags itself.
  for c in codes: result.add(chr(c))

proc anyString(strs: seq[StringRec], needles: openArray[string]): bool =
  for s in strs:
    let v = s.value.toLowerAscii
    for n in needles:
      if n.toLowerAscii in v: return true
  false

proc hasGoVersionString(strs: seq[StringRec]): bool =
  ## exact "go1.x(.y)" token, not a substring of unrelated text
  for s in strs:
    let v = s.value
    if v.startsWith("go1.") and v.len >= 6:
      var i = 4
      var digits = 0
      while i < v.len and v[i] in {'0'..'9'}:
        inc i; inc digits
      if digits >= 1 and i == v.len: return true
  false

proc findComment(b: Binary): string =
  for s in b.sections:
    if s.name == ".comment" and s.size > 0:
      try:
        return rdCstr(b.data, s.off, 512)
      except NecroError: discard
  ""

proc parseRichHeader(b: Binary): string =
  ## PE Rich header: version info XORed with a key after the DOS stub.
  let d = b.data
  if d.len < 0x200: return ""
  var richOff = -1
  for i in 0x40 ..< 0x200 - 8:
    if d[i] == 0x52 and d[i+1] == 0x69 and d[i+2] == 0x63 and d[i+3] == 0x68:
      richOff = i; break
  if richOff < 0: return ""
  let key = rdU32(d, uint64(richOff + 4))
  if key == 0: return ""
  var i = richOff - 4
  var best = ""
  while i >= 0x40:
    let v = rdU32(d, uint64(i)) xor key
    if v == 0x536e6144:  # "DanS" LE
      let prodId = rdU32(d, uint64(i + 0x10)) xor key
      let prodBuild = rdU32(d, uint64(i + 0x14)) xor key
      if prodBuild > 0:
        let (maj, minr) = (int(prodId shr 16), int(prodId and 0xFFFF))
        let vs = int(prodBuild)
        let vsName = case (vs div 1000)
          of 11: "VS2010"
          of 12: "VS2012"
          of 13: "VS2013"
          of 14: "VS2015"
          of 15: "VS2017"
          of 16: "VS2019"
          of 17: "VS2022"
          else: "VS(v" & $vs & ")"
        best = "MSVC " & vsName & " (toolchain " & $maj & "." & $minr & ")"
      break
    i -= 4
  return best

proc fingerprint*(b: Binary, strs: seq[StringRec]): tuple[compiler: string, packer: string] =
  var compiler = ""
  var packer = ""
  # runtime-assembled needles (defeat self-flagging)
  let upxNeedle = fromCodes([0x75, 0x70, 0x78, 0x21])                     # upx!
  let goBuildid = fromCodes([0x67, 0x6f, 0x2e, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x69, 0x64])  # go.buildid
  let rustPath = fromCodes([0x2f, 0x72, 0x75, 0x73, 0x74, 0x63, 0x2f])    # /rustc/
  let cargoPath = fromCodes([0x2e, 0x63, 0x61, 0x72, 0x67, 0x6f, 0x2f, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x79])  # .cargo/registry
  let nimMain = fromCodes([0x4e, 0x69, 0x6d, 0x4d, 0x61, 0x69, 0x6e])     # NimMain
  let nimSys = fromCodes([0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2e, 0x6e, 0x69, 0x6d])  # system.nim
  let clangVer = fromCodes([0x63, 0x6c, 0x61, 0x6e, 0x67, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e])  # clang version
  let mingwNeedle = fromCodes([0x6d, 0x69, 0x6e, 0x67, 0x77])             # mingw

  # ---------- packers first ----------
  case b.format
  of fmtPE:
    var names: seq[string] = @[]
    for s in b.sections: names.add(s.name.toLowerAscii)
    if "upx0" in names or "upx1" in names or "upx2" in names: packer = "UPX"
    elif "mpress1" in names or "mpress2" in names: packer = "MPRESS"
    elif ".vmp0" in names or ".vmp1" in names: packer = "VMProtect"
    elif ".themida" in names: packer = "Themida"
    if packer.len == 0:
      var pk = false
      var why = ""
      for s in b.sections:
        if s.size > 4096 and s.entropy > 7.5 and "x" in s.flags and b.imports.len <= 4:
          pk = true
          why = "entropy " & fmtEntropy(s.entropy) & " in " & s.name & " with " & $b.imports.len & " imports"
          break
      if pk: packer = "packed/encrypted (" & why & ")"
  of fmtELF:
    if anyString(strs, [upxNeedle]) or hasSectionSub(b, "upx"): packer = "UPX"
  of fmtMachO: discard
  else: discard

  # ---------- compilers ----------
  case b.format
  of fmtELF:
    let comment = findComment(b)
    if comment.len > 0:
      if clangVer in comment: compiler = "Clang (" & comment[0 ..< min(64, comment.len)] & ")"
      elif "GCC:" in comment: compiler = "GCC (" & comment[0 ..< min(64, comment.len)] & ")"
  of fmtPE:
    let rich = parseRichHeader(b)
    if rich.len > 0: compiler = rich
    if b.dotnet and compiler.len == 0: compiler = ".NET (CIL metadata)"
    if anyString(strs, [mingwNeedle]):
      compiler = (if compiler.len == 0: "MinGW-w64 (GCC)" else: compiler & " / MinGW-w64")
  of fmtMachO:
    for s in strs:
      if clangVer in s.value.toLowerAscii:
        compiler = "Apple Clang (" & s.value[0 ..< min(56, s.value.len)] & ")"
        break
  else: discard

  # ---------- language runtimes (structural first, joined needles second) ----------
  var goHit = hasSectionSub(b, "gopclntab") or hasSectionSub(b, "go.buildinfo") or
              hasGoVersionString(strs) or anyString(strs, [goBuildid])
  var rustHit = anyString(strs, [rustPath]) and anyString(strs, [cargoPath])
  var nimHit = anyString(strs, [nimMain, nimSys])
  if goHit:
    compiler = (if compiler.len == 0: "" else: compiler & " + ") & "Go runtime"
  elif rustHit:
    compiler = (if compiler.len == 0: "" else: compiler & " + ") & "Rust"
  elif nimHit:
    compiler = (if compiler.len == 0: "" else: compiler & " + ") & "Nim"
  if compiler.len == 0:
    compiler = "unknown"
  return (compiler, packer)
