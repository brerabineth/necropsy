## necropsy — the binary post-mortem kit.
## One static binary. Zero dependencies. Zero network. Nothing leaves the machine.
import ncommon, nelf, npe, nmacho, nentropy, nstrings, ncrypto, nfinger,
       ncaps, nimports, ndisasm, nfuncs, nreport, ndiff
import std/[os, strutils, parseopt, tables, algorithm, sets, sequtils]

const VERSION = "0.1.0"

const USAGE = """
necropsy 0.1.0 — the binary post-mortem kit
static triage for ELF, PE and Mach-O binaries. offline. zero dependencies.

usage:
  necropsy analyze <file> [--json out.json] [--md out.md] [--quiet] [--fail-on BAND]
  necropsy sections <file>            section / segment table with entropy
  necropsy entropy <file>             file-wide entropy map
  necropsy strings <file> [--min N] [--kind KIND]   classified strings + IOCs
  necropsy imports <file>             import table + capability tags
  necropsy exports <file>             export / symbol table
  necropsy crypto <file>              embedded crypto constant scan
  necropsy disasm <file> [--addr VA | --func NAME | --entry] [--count N]
  necropsy functions <file>           function discovery + sizes
  necropsy graph <file> --dot out.dot call graph in graphviz DOT
  necropsy diff <fileA> <fileB>       structural diff
  necropsy help | version

exit codes (analyze):
  0 clean   1 low   2 suspect   3 critical   10 --fail-on gate   64 error
nothing is uploaded. nothing is executed. the sample never runs.
"""

type
  Session = object
    b: Binary
    strs: seq[StringRec]
    crypto: seq[CryptoRec]
    v: Verdict
    funcs: seq[FuncRec]

var gColor = true

proc c(code: string): string =
  if gColor: "\x1b[" & code & "m" else: ""

proc kLabel(s: string): string = c("38;5;75") & s & "\x1b[0m"
proc kDim(s: string): string = c("38;5;245") & s & "\x1b[0m"
proc kBad(s: string): string = c("38;5;196") & s & "\x1b[0m"

proc bandExit(band: string): int =
  case band
  of "CRITICAL": 3
  of "SUSPECT": 2
  of "LOW": 1
  else: 0

proc bandRank(band: string): int =
  case band
  of "CRITICAL": 3
  of "SUSPECT": 2
  of "LOW": 1
  else: 0

proc loadSession(path: string, wantFuncs = true): Session =
  result.b = loadFile(path)
  case result.b.format
  of fmtELF: parseElf(result.b)
  of fmtPE: parsePe(result.b)
  of fmtMachO: parseMacho(result.b)
  else:
    raise necroFail("unrecognized format (not ELF / PE / Mach-O)")
  result.strs = result.b.extractStrings(5)
  result.crypto = result.b.scanCrypto()
  let (compiler, packer) = result.b.fingerprint(result.strs)
  result.b.compiler = compiler
  result.b.packer = packer
  result.v = buildVerdict(result.b, result.strs, result.crypto, packer)
  if wantFuncs and result.b.arch == "x86-64":
    result.funcs = result.b.discoverFunctions()

proc die(msg: string): int =
  stderr.writeLine("necropsy: error: " & msg)
  64

proc cmdAnalyze(args: seq[string]): int =
  if args.len == 0: return die("analyze needs a file")
  var path = ""
  var jsonOut, mdOut = ""
  var quiet = false
  var failOn = ""
  var i = 0
  while i < args.len:
    case args[i]
    of "--json":
      inc i
      if i >= args.len: return die("--json needs a path")
      jsonOut = args[i]
    of "--md":
      inc i
      if i >= args.len: return die("--md needs a path")
      mdOut = args[i]
    of "--quiet": quiet = true
    of "--fail-on":
      inc i
      if i >= args.len: return die("--fail-on needs low|suspect|critical")
      failOn = args[i].toLowerAscii
    else:
      if path.len == 0: path = args[i]
      else: return die("unexpected argument: " & args[i])
    inc i
  if path.len == 0: return die("analyze needs a file")
  var s: Session
  try:
    s = loadSession(path)
  except NecroError as e:
    return die(e.msg)
  except CatchableError as e:
    return die(e.msg)
  if not quiet:
    stdout.write(s.b.reportAnsi(s.strs, s.crypto, s.v, s.funcs))
  if jsonOut.len > 0:
    writeFile(jsonOut, s.b.toJsonReport(s.strs, s.crypto, s.v, s.funcs))
    if not quiet: echo "json report -> " & jsonOut
  if mdOut.len > 0:
    writeFile(mdOut, s.b.toMdReport(s.strs, s.crypto, s.v, s.funcs))
    if not quiet: echo "markdown report -> " & mdOut
  var code = bandExit(s.v.band)
  if failOn.len > 0 and (bandRank(s.v.band) >= bandRank(failOn.toUpperAscii())):
    code = 10
  return code

proc cmdSections(args: seq[string]): int =
  var s: Session
  try: s = loadSession(args[^1], wantFuncs = false)
  except NecroError as e: return die(e.msg)
  except CatchableError as e: return die(e.msg)
  echo kLabel("SECTIONS") & kDim("  (" & s.b.displayPath & ")")
  for sec in s.b.sections:
    echo "  " & (sec.name & "                              ")[0 ..< 22] &
      hx(sec.va).align(10) & " " & hx(sec.off).align(10) & " " &
      hx(sec.size).align(10) & "  ent=" & fmtEntropy(sec.entropy) &
      "  " & (if sec.flags == "---": "info" else: sec.flags)
  0

proc cmdEntropy(args: seq[string]): int =
  var s: Session
  try: s = loadSession(args[^1], wantFuncs = false)
  except NecroError as e: return die(e.msg)
  except CatchableError as e: return die(e.msg)
  let m = entropyMap(s.b, 64)
  echo kLabel("ENTROPY MAP") & kDim("  (" & s.b.displayPath & ", 64 buckets)")
  echo "  0.0 " & sparkline(m.mapIt(it.ent)) & " 8.0"
  for bk in m:
    let sec = s.b.sectionNameAt(bk.off)
    if bk.ent >= 7.0:
      echo "  hot " & hx(bk.off) & " ent=" & fmtEntropy(bk.ent) &
        (if sec.len > 0: "  (" & sec & ")" else: "")
  0

proc cmdStrings(args: seq[string]): int =
  var minLen = 5
  var kindFilter = ""
  var path = ""
  var i = 0
  while i < args.len:
    case args[i]
    of "--min": inc i; minLen = parseInt(args[i])
    of "--kind": inc i; kindFilter = args[i].toLowerAscii
    else: path = args[i]
    inc i
  if path.len == 0: return die("strings needs a file")
  var s: Session
  try: s = loadSession(path, wantFuncs = false)
  except NecroError as e: return die(e.msg)
  except CatchableError as e: return die(e.msg)
  for st in s.strs:
    if st.value.len < minLen: continue
    if kindFilter.len > 0 and kindName(st.kind) != kindFilter: continue
    let ktag = case st.kind
      of skUrl, skIp, skDomain: "[ioc ]"
      of skRegistry: "[reg ]"
      of skSus: "[susp]"
      of skPath: "[path]"
      of skB64: "[b64 ]"
      of skGuid: "[guid]"
      else: "[str ]"
    echo "  " & hx(st.off) & " " & ktag & " " & st.value.trunc(100)
  0

proc cmdImports(args: seq[string]): int =
  var s: Session
  try: s = loadSession(args[^1], wantFuncs = false)
  except NecroError as e: return die(e.msg)
  except CatchableError as e: return die(e.msg)
  let hits = s.b.classifyImports()
  var tagged = initTable[string, string]()
  for h in hits: tagged[h.symbol] = h.category
  echo kLabel("IMPORTS") & kDim("  (" & s.b.displayPath & ", " & $s.b.imports.len & ")")
  for imp in s.b.imports:
    var line = "  "
    if imp.dll.len > 0: line &= imp.dll & "!"
    line &= (if imp.name.len > 0: imp.name else: "ordinal#" & $imp.ordinal)
    if tagged.hasKey(imp.name):
      line &= kBad("  [" & tagged[imp.name] & "]")
    echo line
  0

proc cmdExports(args: seq[string]): int =
  var s: Session
  try: s = loadSession(args[^1], wantFuncs = false)
  except NecroError as e: return die(e.msg)
  except CatchableError as e: return die(e.msg)
  echo kLabel("EXPORTS") & kDim("  (" & s.b.displayPath & ", " & $s.b.exportsList.len & ")")
  for e in s.b.exportsList[0 ..< min(200, s.b.exportsList.len)]:
    echo "  " & hx(e.va) & "  " & e.name
  0

proc cmdCrypto(args: seq[string]): int =
  var s: Session
  try: s = loadSession(args[^1], wantFuncs = false)
  except NecroError as e: return die(e.msg)
  except CatchableError as e: return die(e.msg)
  echo kLabel("CRYPTO CONSTANTS") & kDim("  (" & s.b.displayPath & ", " & $s.crypto.len & " hits)")
  for h in s.crypto:
    echo "  " & hx(h.off) & "  " & h.name & kDim("  — " & h.note)
  0

proc cmdDisasm(args: seq[string]): int =
  var path = ""
  var startVa: uint64 = 0
  var haveVa = false
  var funcName = ""
  var useEntry = false
  var count = 40
  var i = 0
  while i < args.len:
    case args[i]
    of "--addr":
      inc i
      if i >= args.len: return die("--addr needs 0xVA")
      startVa = parseHexInt(args[i].replace("0x", "").replace("0X", "")).uint64
      haveVa = true
    of "--func":
      inc i
      if i >= args.len: return die("--func needs a name")
      funcName = args[i]
    of "--entry": useEntry = true
    of "--count":
      inc i
      count = parseInt(args[i])
    else: path = args[i]
    inc i
  if path.len == 0: return die("disasm needs a file")
  var s: Session
  try: s = loadSession(path)
  except NecroError as e: return die(e.msg)
  except CatchableError as e: return die(e.msg)
  if s.b.arch != "x86-64":
    return die("disassembly currently supports x86-64 only (sample is " & s.b.arch & ")")
  if not haveVa and funcName.len == 0 and not useEntry:
    useEntry = true
  var va: uint64 = 0
  if haveVa:
    va = startVa
  elif funcName.len > 0:
    var found = false
    for f in s.funcs:
      if f.name == funcName:
        va = f.va; found = true; break
    if not found:
      return die("function not found: " & funcName)
  else:
    if s.b.entry == 0: return die("no entry point")
    va = s.b.entry
    # entry for PIE files is a VA already; for LC_MAIN it may be file offset:
    if s.b.format == fmtMachO and va < uint64(s.b.data.len) and s.b.vaToOff(va) < 0:
      # LC_MAIN stores entryoff; resolve via __TEXT vmaddr
      for sec in s.b.sections:
        if sec.name == "__TEXT" and sec.va > 0:
          va = sec.va + startVa
          break
  let off = s.b.vaToOff(va)
  if off < 0:
    return die("address " & hx(va) & " is not mapped to file content")
  echo kLabel("DISASM") & kDim("  (" & s.b.displayPath & " @ " & hx(va) & ")")
  var cur = va
  var n = 0
  while n < count:
    let o = s.b.vaToOff(cur)
    if o < 0: break
    var ins = decodeInsn(s.b.data, uint64(o), cur)
    if ins.size <= 0: break
    var hexB = ""
    for j in 0 ..< min(ins.size, 8):
      hexB &= toHex(int(s.b.data[o + j]), 2) & " "
    let bcol = case ins.branch
      of brCall: kBad("call")
      of brJmp: kBad("jmp ")
      of brJcc: "jcc "
      of brRet: kLabel("ret ")
      else: "    "
    echo "  " & hx(cur) & "  " & hexB.align(24) & bcol & " " & ins.text
    cur = cur + uint64(ins.size)
    inc n
  0

proc cmdFunctions(args: seq[string]): int =
  var s: Session
  try: s = loadSession(path = args[^1])
  except NecroError as e: return die(e.msg)
  except CatchableError as e: return die(e.msg)
  echo kLabel("FUNCTIONS") & kDim("  (" & s.b.displayPath & ", " & $s.funcs.len & " discovered)")
  for f in s.funcs[0 ..< min(200, s.funcs.len)]:
    echo "  " & hx(f.va) & "  " & (f.name & "                              ")[0 ..< 20] &
      " " & ($f.size & "b").align(8) & " " & ($f.ninsns & " insns").align(12) &
      " " & ($f.callees.len & " calls")
  0

proc cmdGraph(args: seq[string]): int =
  var path = ""
  var dot = ""
  var i = 0
  while i < args.len:
    case args[i]
    of "--dot":
      inc i
      if i >= args.len: return die("--dot needs a path")
      dot = args[i]
    else: path = args[i]
    inc i
  if path.len == 0: return die("graph needs a file")
  if dot.len == 0: return die("graph needs --dot out.dot")
  var s: Session
  try: s = loadSession(path)
  except NecroError as e: return die(e.msg)
  except CatchableError as e: return die(e.msg)
  if s.funcs.len == 0: return die("no functions discovered")
  s.funcs.writeDot(dot)
  echo "call graph (" & $s.funcs.len & " functions) -> " & dot
  0

proc cmdDiff(args: seq[string]): int =
  var paths: seq[string] = @[]
  for a in args:
    if not a.startsWith("--"): paths.add(a)
  if paths.len != 2: return die("diff needs exactly two files")
  var sa, sb: Session
  try:
    sa = loadSession(paths[0], wantFuncs = false)
    sb = loadSession(paths[1], wantFuncs = false)
  except NecroError as e: return die(e.msg)
  except CatchableError as e: return die(e.msg)
  let d = diffBinaries(sa.b, sb.b, sa.crypto, sb.crypto, sa.v, sb.v)
  echo kLabel("DIFF") & kDim("  " & sa.b.displayPath & "  ->  " & sb.b.displayPath)
  echo "  verdict " & sa.v.band & " " & $sa.v.score & "/100  ->  " & sb.v.band & " " & $sb.v.score & "/100"
  proc blockList(title: string, added, removed: seq[string], cap = 20) =
    if added.len == 0 and removed.len == 0: return
    echo "\n  " & kLabel(title)
    for x in added[0 ..< min(cap, added.len)]:
      echo "  " & kBad("+") & " " & x
    for x in removed[0 ..< min(cap, removed.len)]:
      echo "  " & kDim("-") & " " & x
    if added.len > cap: echo kDim("    ... +" & $(added.len - cap) & " more")
    if removed.len > cap: echo kDim("    ... -" & $(removed.len - cap) & " more")
  blockList("sections", d.secAdded, d.secRemoved)
  blockList("imports", d.impAdded, d.impRemoved)
  blockList("exports", d.expAdded, d.expRemoved)
  blockList("crypto constants", d.cryptoAdded, d.cryptoRemoved)
  echo ""
  0

proc main() =
  var params = commandLineParams()
  # global flags
  var i = 0
  while i < params.len:
    if params[i] == "--no-color":
      gColor = false
      params.delete(i)
    elif params[i] == "--help" or params[i] == "-h":
      echo USAGE
      quit(0)
    else:
      inc i
  if getEnv("NO_COLOR").len > 0: gColor = false
  if params.len == 0:
    echo USAGE
    quit(64)
  let cmd = params[0]
  let rest = params[1 .. ^1]
  case cmd
  of "analyze": quit(cmdAnalyze(rest))
  of "sections": quit(cmdSections(rest))
  of "entropy": quit(cmdEntropy(rest))
  of "strings": quit(cmdStrings(rest))
  of "imports": quit(cmdImports(rest))
  of "exports": quit(cmdExports(rest))
  of "crypto": quit(cmdCrypto(rest))
  of "disasm": quit(cmdDisasm(rest))
  of "functions": quit(cmdFunctions(rest))
  of "graph": quit(cmdGraph(rest))
  of "diff": quit(cmdDiff(rest))
  of "help": echo USAGE; quit(0)
  of "version": echo "necropsy " & VERSION; quit(0)
  else:
    # single-file convenience: necropsy <file> == analyze
    if fileExists(cmd):
      quit(cmdAnalyze(params))
    echo USAGE
    quit(64)
when isMainModule:
  try:
    main()
  except NecroError as e:
    stderr.writeLine("necropsy: error: " & e.msg)
    quit(64)
  except CatchableError as e:
    stderr.writeLine("necropsy: error: " & e.msg)
    quit(64)
