## nentropy.nim — per-section entropy + sliding-window entropy map.
import ncommon
import std/[strutils, math]

type EntropyBucket* = object
  off*: uint64
  ent*: float64

proc overallEntropy*(b: Binary): float64 = shannon(b.data)

proc entropyMap*(b: Binary, buckets = 64): seq[EntropyBucket] =
  ## File-wide entropy map, bucketed over the entire file.
  result = @[]
  if b.data.len == 0: return
  let n = max(1, min(buckets, b.data.len))
  let chunk = (b.data.len + n - 1) div n
  for i in 0 ..< n:
    let lo = i * chunk
    let hi = min(b.data.len, lo + chunk)
    if lo >= hi: break
    result.add(EntropyBucket(off: uint64(lo), ent: shannon(b.data[lo ..< hi])))

proc sparkline*(ents: openArray[float64]): string =
  ## ASCII sparkline over entropy values (0..8).
  const ramp = " .:-=+*#%@"
  for e in ents:
    let idx = int(clamp(round(e / 8.0 * 9.0), 0.0, 9.0))
    result.add(ramp[idx])

proc sectionNameAt*(b: Binary, off: uint64): string =
  for s in b.sections:
    if s.size > 0 and off >= s.off and off < s.off + s.size:
      return s.name
  return ""

proc packerHeuristic*(b: Binary): tuple[packed: bool, why: string] =
  ## Heuristics: high entropy + tiny import set + weird section names.
  var maxEnt = 0.0
  var execEnt = 0.0
  var nSections = 0
  for s in b.sections:
    if s.size > 512:
      inc nSections
      if s.entropy > maxEnt: maxEnt = s.entropy
      if 'x' in s.flags and s.entropy > execEnt: execEnt = s.entropy
  case b.format
  of fmtPE:
    if b.imports.len <= 3 and maxEnt > 7.0:
      return (true, "high entropy (" & fmtEntropy(maxEnt) & ") with " & $b.imports.len & " imports")
    for s in b.sections:
      let ln = s.name.toLowerAscii
      if ln in ["upx0", "upx1", "upx2", ".vmp0", ".vmp1", "mpress1", "mpress2", ".themida"]:
        return (true, "packer section name: " & s.name)
  of fmtELF:
    if b.dlls.len == 0 and b.imports.len == 0 and maxEnt > 7.4 and nSections > 3:
      return (true, "no dynamic imports with peak entropy " & fmtEntropy(maxEnt))
  of fmtMachO:
    if b.imports.len == 0 and maxEnt > 7.4:
      return (true, "no imports with peak entropy " & fmtEntropy(maxEnt))
  else: discard
  if execEnt > 7.6:
    return (true, "executable section entropy " & fmtEntropy(execEnt))
  return (false, "")
