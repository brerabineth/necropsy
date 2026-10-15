## nreport.nim — ANSI terminal, JSON and Markdown report rendering.
import ncommon, nstrings, ncrypto, ncaps, nentropy, nfuncs
import std/[strutils, json, algorithm]

const BANNER = r"""
  _  _ ___ ___  _  _ ___ _____ ___  _
 | \| | __|   \| \| | __|_   _/ _ \| |
 | .` | _|| |) | .` | _|  | || (_) | |__
 |_|\_|___|___/|\_\_|___| |_| \___/|____|
 the binary post-mortem kit
"""

const C_RESET = "\x1b[0m"
proc c(code: string): string = "\x1b[" & code & "m"

proc kLabel(s: string): string = c("38;5;75") & s & C_RESET       # blue-ish
proc kDim(s: string): string = c("38;5;245") & s & C_RESET        # gray
proc kGood(s: string): string = c("38;5;82") & s & C_RESET
proc kWarn(s: string): string = c("38;5;220") & s & C_RESET
proc kBad(s: string): string = c("38;5;196") & s & C_RESET

proc colVerdict(band: string, s: string): string =
  case band
  of "CRITICAL": kBad(s)
  of "SUSPECT": kWarn(s)
  of "LOW": kWarn(s)
  else: kGood(s)

proc fmtSize(n: uint64): string =
  if n >= 1_048_576: (n.float64 / 1_048_576.0).formatFloat(ffDecimal, 1) & " MB"
  elif n >= 1024: (n.float64 / 1024.0).formatFloat(ffDecimal, 1) & " KB"
  else: $n & " B"

proc secFlagsPretty(fl: string): string =
  if fl == "---": "info" else: fl

proc reportAnsi*(b: Binary, strs: seq[StringRec], crypto: seq[CryptoRec],
                 v: Verdict, funcs: seq[FuncRec]): string =
  result = ""
  let color = bandColor(v.score)
  result.add(kDim(BANNER) & "\n")
  result.add(kLabel("SAMPLE") & "     " & b.displayPath & "\n")
  result.add(kLabel("FORMAT") & "     " & $b.format & " " & $b.bits & "-bit / " & b.arch &
             " / " & b.kind & " (" & b.endian & " endian)\n")
  result.add(kLabel("SIZE") & "       " & fmtSize(uint64(b.data.len)) &
             kDim("  entry " & hx(b.entry)) & "\n")
  var peakEnt = 0.0
  var peakName = "-"
  for s in b.sections:
    if s.size > 512 and s.entropy > peakEnt:
      peakEnt = s.entropy
      peakName = s.name
  result.add(kLabel("ENTROPY") & "    " & fmtEntropy(overallEntropy(b)) & " overall" &
             kDim("  peak " & fmtEntropy(peakEnt) & " " & peakName) & "\n")
  result.add(kLabel("COMPILER") & "   " & b.compiler)
  if b.packer.len > 0: result.add(kWarn("  [" & b.packer & "]"))
  result.add("\n")
  # --- sections
  if b.sections.len > 0:
    result.add("\n" & kLabel("SECTIONS") & kDim(" (" & $b.sections.len & ")") & "\n")
    result.add(kDim("  name                     va         off        size       ent    fl") & "\n")
    for s in b.sections:
      if s.size == 0 and s.vsize == 0: continue
      result.add("  " & (s.name & "                     ")[0 ..< min(24, s.name.len + 24)] &
                 hx(s.va).align(10) & " " & hx(s.off).align(10) & " " &
                 hx(s.size).align(10) & " " & fmtEntropy(s.entropy).align(6) & "  " &
                 secFlagsPretty(s.flags) & "\n")
  # --- imports
  if b.imports.len > 0:
    result.add("\n" & kLabel("IMPORTS") & kDim(" (" & $b.imports.len & ")") & "\n")
    let show = min(40, b.imports.len)
    for i in 0 ..< show:
      let imp = b.imports[i]
      var line = "  "
      if imp.dll.len > 0: line &= imp.dll & "!"
      line &= (if imp.name.len > 0: imp.name else: "ordinal#" & $imp.ordinal)
      result.add(line & "\n")
    if b.imports.len > show:
      result.add(kDim("  ... +" & $(b.imports.len - show) & " more") & "\n")
    if b.dlls.len > 0 and b.imports.len == 0:
      for dll in b.dlls[0 ..< min(20, b.dlls.len)]:
        result.add("  " & dll & "\n")
  # --- crypto
  if crypto.len > 0:
    result.add("\n" & kLabel("CRYPTO CONSTANTS") & kDim(" (" & $crypto.len & ")") & "\n")
    var shown: seq[string] = @[]
    for h in crypto:
      if h.name in shown: continue
      shown.add(h.name)
      result.add("  " & h.name & " " & kDim("@ " & hx(h.off)) & "\n")
      if shown.len >= 12: break
  # --- capabilities / verdict
  result.add("\n" & kLabel("CAPABILITIES") & " — " &
             colVerdict(v.band, v.band & " " & $v.score & "/100") &
             kDim(" [exit " & $v.exitCode & "]") & "\n")
  if v.caps.len == 0:
    result.add(kDim("  no suspicious capability signals") & "\n")
  for cap in v.caps:
    let wcol = (if cap.weight >= 20: kBad elif cap.weight >= 10: kWarn else: kDim)($cap.weight)
    result.add("  " & wcol.align(3) & "  " & catTitle(cap.category) &
               kDim("  <- " & cap.evidence.join(", ")) & "\n")
  # --- ioc strings
  let iocs = iocStrings(strs)
  if iocs.len > 0:
    result.add("\n" & kLabel("STRINGS / IOCs") & kDim(" (" & $iocs.len & " classified)") & "\n")
    for s in iocs[0 ..< min(16, iocs.len)]:
      result.add("  [" & kindName(s.kind) & "] " & s.value.trunc(88) & "\n")
    if iocs.len > 16:
      result.add(kDim("  ... use `necropsy strings " & b.displayPath & "` for the full set") & "\n")
  # --- functions
  if funcs.len > 0:
    result.add("\n" & kLabel("FUNCTIONS") & kDim(" (" & $funcs.len & " discovered)") & "\n")
    for f in funcs[0 ..< min(12, funcs.len)]:
      result.add("  " & hx(f.va) & " " & (f.name & "                    ")[0 ..< 20] &
                 kDim($f.size & "b, " & $f.ninsns & " insns, " & $f.callees.len & " calls") & "\n")
    if funcs.len > 12:
      result.add(kDim("  ... + " & $(funcs.len - 12) & " more (necropsy functions " & b.displayPath & ")") & "\n")
  result.add("\n")

proc toJsonReport*(b: Binary, strs: seq[StringRec], crypto: seq[CryptoRec],
                   v: Verdict, funcs: seq[FuncRec]): string =
  var j = newJObject()
  j["sample"] = %b.displayPath
  j["format"] = %($b.format)
  j["bits"] = %b.bits
  j["arch"] = %b.arch
  j["kind"] = %b.kind
  j["endian"] = %b.endian
  j["entry"] = %hx(b.entry)
  j["size"] = %b.data.len
  j["entropy"] = %overallEntropy(b)
  j["compiler"] = %b.compiler
  j["packer"] = %b.packer
  j["dotnet"] = %b.dotnet
  var secs = newJArray()
  for s in b.sections:
    var so = newJObject()
    so["name"] = %s.name
    so["va"] = %hx(s.va)
    so["off"] = %hx(s.off)
    so["size"] = %int(s.size)
    so["vsize"] = %int(s.vsize)
    so["entropy"] = %s.entropy
    so["flags"] = %s.flags
    secs.add(so)
  j["sections"] = secs
  var imps = newJArray()
  for i in b.imports:
    var io = newJObject()
    io["dll"] = %i.dll
    io["name"] = %i.name
    io["ordinal"] = %i.ordinal
    imps.add(io)
  j["imports"] = imps
  var exps = newJArray()
  for e in b.exportsList[0 ..< min(4000, b.exportsList.len)]:
    var eo = newJObject()
    eo["name"] = %e.name
    eo["va"] = %hx(e.va)
    exps.add(eo)
  j["exports"] = exps
  var cs = newJArray()
  for h in crypto:
    var co = newJObject()
    co["name"] = %h.name
    co["off"] = %hx(h.off)
    co["note"] = %h.note
    cs.add(co)
  j["crypto"] = cs
  var caps = newJArray()
  for cap in v.caps:
    var co = newJObject()
    co["category"] = %cap.category
    co["weight"] = %cap.weight
    co["evidence"] = %cap.evidence
    caps.add(co)
  var vd = newJObject()
  vd["score"] = %v.score
  vd["band"] = %v.band
  vd["exit_code"] = %v.exitCode
  vd["capabilities"] = caps
  vd["crypto_score"] = %v.cryptoScore
  vd["suspicious_strings"] = %v.susStrings
  vd["packed"] = %v.packed
  vd["registry_autorun_signal"] = %v.registrySignal
  j["verdict"] = vd
  var ss = newJArray()
  for s in strs:
    var so = newJObject()
    so["off"] = %hx(s.off)
    so["kind"] = %kindName(s.kind)
    so["value"] = %s.value
    ss.add(so)
  j["strings"] = ss
  var fs = newJArray()
  for f in funcs:
    var fo = newJObject()
    fo["name"] = %f.name
    fo["va"] = %hx(f.va)
    fo["size"] = %f.size
    fo["insns"] = %f.ninsns
    fo["calls"] = %f.callees.len
    fs.add(fo)
  j["functions"] = fs
  pretty(j)

proc toMdReport*(b: Binary, strs: seq[StringRec], crypto: seq[CryptoRec],
                 v: Verdict, funcs: seq[FuncRec]): string =
  result = ""
  result.add("# necropsy report — " & b.displayPath & "\n\n")
  result.add("| field | value |\n|---|---|\n")
  result.add("| format | " & $b.format & " " & $b.bits & "-bit |\n")
  result.add("| arch | " & b.arch & " |\n")
  result.add("| kind | " & b.kind & " |\n")
  result.add("| entry | `" & hx(b.entry) & "` |\n")
  result.add("| entropy | " & fmtEntropy(overallEntropy(b)) & " |\n")
  result.add("| compiler | " & b.compiler & " |\n")
  result.add("| packer | " & (if b.packer.len > 0: b.packer else: "-") & " |\n")
  result.add("| verdict | **" & v.band & " (" & $v.score & "/100)** |\n\n")
  if b.sections.len > 0:
    result.add("## sections\n\n| name | va | off | size | entropy | flags |\n|---|---|---|---|---|---|\n")
    for s in b.sections:
      if s.size == 0 and s.vsize == 0: continue
      result.add("| " & s.name & " | " & hx(s.va) & " | " & hx(s.off) & " | " &
                 hx(s.size) & " | " & fmtEntropy(s.entropy) & " | " & s.flags & " |\n")
    result.add("\n")
  if b.imports.len > 0:
    result.add("## imports (" & $b.imports.len & ")\n\n")
    for i in b.imports[0 ..< min(60, b.imports.len)]:
      result.add("- " & (if i.dll.len > 0: i.dll & "!" else: "") &
                 (if i.name.len > 0: i.name else: "ord#" & $i.ordinal) & "\n")
    result.add("\n")
  if crypto.len > 0:
    result.add("## crypto constants\n\n| name | offset | note |\n|---|---|---|\n")
    for h in crypto:
      result.add("| " & h.name & " | `" & hx(h.off) & "` | " & h.note & " |\n")
    result.add("\n")
  result.add("## capabilities\n\n")
  if v.caps.len == 0:
    result.add("no suspicious capability signals\n")
  else:
    result.add("| weight | category | evidence |\n|---|---|---|\n")
    for cap in v.caps:
      result.add("| " & $cap.weight & " | " & catTitle(cap.category) & " | " &
                 cap.evidence.join(", ") & " |\n")
  result.add("\n")
  let iocs = iocStrings(strs)
  if iocs.len > 0:
    result.add("## strings / iocs (" & $iocs.len & ")\n\n")
    for s in iocs[0 ..< min(40, iocs.len)]:
      result.add("- **" & kindName(s.kind) & "** `" & s.value.replace("|", "\\|") & "`\n")
    result.add("\n")
  if funcs.len > 0:
    result.add("## functions (" & $funcs.len & ")\n\n| va | name | size | insns | calls |\n|---|---|---|---|---|\n")
    for f in funcs[0 ..< min(40, funcs.len)]:
      result.add("| " & hx(f.va) & " | " & f.name & " | " & $f.size & " | " &
                 $f.ninsns & " | " & $f.callees.len & " |\n")
    result.add("\n")
