## ncaps.nim — capability aggregation + weighted verdict engine.
## Combines: import taxonomy, suspicious strings, crypto constants, packer signals.
import ncommon, nimports, nstrings, ncrypto, nentropy
import std/[tables, strutils, algorithm]

type
  Capability* = object
    category*: string
    weight*: int
    evidence*: seq[string]

  Verdict* = object
    score*: int
    band*: string      # CLEAN / LOW / SUSPECT / CRITICAL
    exitCode*: int
    caps*: seq[Capability]
    cryptoScore*: int
    cryptoNames*: string
    susStringScore*: int
    susStrings*: seq[string]
    packed*: bool
    packerWhy*: string
    packerName*: string
    registrySignal*: bool
    notes*: seq[string]

proc catTitle*(cat: string): string =
  cat.replace("-", " ")

proc aggregate(hits: seq[CapHit]): seq[Capability] =
  var byCat = initTable[string, seq[string]]()
  for h in hits:
    if not byCat.hasKey(h.category): byCat[h.category] = @[]
    var ev = ""
    if h.dll.len > 0: ev = h.dll & "!" & h.symbol
    else: ev = h.symbol
    if not (ev in byCat[h.category]):
      byCat[h.category].add(ev)
  var keys: seq[string] = @[]
  for k in byCat.keys: keys.add(k)
  keys.sort()
  for k in keys:
    var evs = byCat[k]
    if evs.len > 6: evs = evs[0 ..< 6] & @["(+" & $(byCat[k].len - 6) & " more)"]
    var w = catBaseWeight(k)
    let extra = min(16, 4 * (byCat[k].len - 1))
    w = w + extra
    # memory-alloc alone is weak; only counts a little
    result.add(Capability(category: k, weight: w, evidence: evs))

proc buildVerdict*(b: Binary, strs: seq[StringRec], crypto: seq[CryptoRec],
                   packerName: string): Verdict =
  var caps = aggregate(b.classifyImports())
  var score = 0
  for c in caps: score += c.weight
  # crypto bonus
  let (cs, cnames) = cryptoVerdictBonus(crypto)
  result.cryptoScore = cs
  result.cryptoNames = cnames
  if cs > 0:
    var cryptoCap = Capability(category: "embedded crypto", weight: cs, evidence: @[])
    for n in cnames.split(", "):
      if n.len > 0: cryptoCap.evidence.add(n)
    caps.add(cryptoCap)
    score += cs
  # suspicious strings
  var sus: seq[string] = @[]
  for s in strs:
    if s.kind == skSus:
      let v = s.value.toLowerAscii
      var dup = false
      for x in sus:
        if x in v or v in x: dup = true; break
      if not dup and sus.len < 12: sus.add(s.value)
  result.susStrings = sus
  result.susStringScore = min(10, sus.len * 2)
  if sus.len > 0:
    var cap = Capability(category: "suspicious strings", weight: result.susStringScore,
                         evidence: sus[0 ..< min(4, sus.len)])
    caps.add(cap)
    score += result.susStringScore
  # registry persistence markers in strings
  var regSig = false
  for s in strs:
    if s.kind == skRegistry and "run" in s.value.toLowerAscii:
      regSig = true; break
  result.registrySignal = regSig
  if regSig:
    caps.add(Capability(category: "persistence markers", weight: 10,
                        evidence: @["autorun registry path in strings"]))
    score += 10
  # packer
  result.packerName = packerName
  if packerName.len > 0:
    result.packed = true
    caps.add(Capability(category: "packing", weight: 25, evidence: @[packerName]))
    score += 25
  if score > 100: score = 100
  caps.sort() do (x, y: Capability) -> int:
    cmp(y.weight, x.weight)
  result.score = score
  result.band = verdictOf(score)
  result.exitCode = scoreExit(result.band)
  result.caps = caps
