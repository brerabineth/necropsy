## nfuncs.nim — function discovery + call graph from the built-in disassembler.
## Strategy: symbol/entry seeds + E8 call-target harvest + prologue scan,
## then bounded linear walks with overlap boundaries.
import ncommon, nelf, npe, nmacho, ndisasm
import std/[sets, tables, strutils, algorithm, os]

proc vaToOff*(b: Binary, va: uint64): int64 =
  ## Map a virtual address to file offset through parsed sections.
  ## Prefers the most specific match (Mach-O sub-sections over segments).
  result = -1
  var bestSize = uint64.high
  var bestOff: int64 = -1
  for s in b.sections:
    if s.size > 0 and va >= s.va and va < s.va + s.size and (s.va != 0 or va == 0):
      let delta = va - s.va
      if s.off + delta >= uint64(b.data.len): continue
      if s.size < bestSize:
        bestSize = s.size
        bestOff = int64(s.off + delta)
  result = bestOff

proc inText*(b: Binary, va: uint64): bool =
  b.textSize > 0 and va >= b.textStart and va < b.textStart + b.textSize

proc harvestCallTargets*(b: Binary): seq[uint64] =
  ## Cheap linear scan for E8 rel32 (call) patterns inside .text.
  result = @[]
  if b.textSize == 0: return
  let off = b.vaToOff(b.textStart)
  if off < 0: return
  var i = 0
  let n = int(b.textSize)
  let data = b.data
  while i + 5 <= n:
    if data[off + i] == 0xE8:
      let rel = int64(cast[int32](rdN(data, uint64(off + i + 1), 4)))
      let target = b.textStart + uint64(i + 5) + cast[uint64](rel)
      if b.inText(target):
        result.add(target)
    inc i

type
  FuncRec* = object
    name*: string
    va*: uint64
    size*: int
    ninsns*: int
    callees*: seq[uint64]
    memRefs*: seq[uint64]
    badDecode*: int

proc discoverFunctions*(b: Binary): seq[FuncRec] =
  if b.textSize == 0 or b.arch != "x86-64":
    return @[]
  var seeds = initHashSet[uint64]()
  var names = initTable[uint64, string]()
  for s in b.symbols:
    if s.isFunc and b.inText(s.va):
      seeds.incl(s.va)
      if not names.hasKey(s.va): names[s.va] = s.name
  for e in b.exportsList:
    if b.inText(e.va):
      seeds.incl(e.va)
      if not names.hasKey(e.va): names[e.va] = e.name
  if b.inText(b.entry):
    seeds.incl(b.entry)
    if not names.hasKey(b.entry): names[b.entry] = "entry"
  for t in b.harvestCallTargets():
    seeds.incl(t)
  # prologue scan: endbr64 (f3 0f 1e fa), push rbp; mov rbp, rsp (55 48 89 e5)
  let tOff = b.vaToOff(b.textStart)
  if tOff >= 0:
    let d = b.data
    let n = int(b.textSize)
    var i = 0
    while i + 4 <= n:
      if d[tOff + i] == 0xF3 and d[tOff + i + 1] == 0x0F and d[tOff + i + 2] == 0x1E and d[tOff + i + 3] == 0xFA:
        seeds.incl(b.textStart + uint64(i))
      elif d[tOff + i] == 0x55 and d[tOff + i + 1] == 0x48 and d[tOff + i + 2] == 0x89 and d[tOff + i + 3] == 0xE5:
        seeds.incl(b.textStart + uint64(i))
      inc i
  # ordered walk
  var seedList: seq[uint64] = @[]
  for s in seeds: seedList.add(s)
  seedList.sort()
  var covered = initHashSet[uint64]()
  var funcStarts = initHashSet[uint64]()
  result = @[]
  var seedIdx = 0
  while seedIdx < seedList.len:
    let start = seedList[seedIdx]
    inc seedIdx
    if covered.contains(start) or funcStarts.contains(start): continue
    var f = FuncRec(name: names.getOrDefault(start, ""), va: start)
    var va = start
    var guardInsns = 0
    var nopRun = 0
    while true:
      if guardInsns >= 16384: break
      let off = b.vaToOff(va)
      if off < 0: break
      var ins = decodeInsn(b.data, uint64(off), va)
      if ins.size <= 0 or ins.size > 15:
        inc f.badDecode
        break
      # nop-sled / padding detection: 16+ consecutive nops = function tail padding
      if ins.text == "nop":
        inc nopRun
        if nopRun >= 16: break
      else:
        nopRun = 0
      if covered.contains(ins.va) and guardInsns > 0:
        break  # ran into previously decoded territory
      if funcStarts.contains(ins.va) and guardInsns > 0:
        break  # ran into the start of another known function
      covered.incl(ins.va)
      inc f.ninsns
      f.size += ins.size
      if ins.branch == brCall and b.inText(ins.target):
        f.callees.add(ins.target)
        # call target is a function seed for the next rounds
        if not covered.contains(ins.target) and not funcStarts.contains(ins.target):
          seedList.add(ins.target)
          seedList.sort()
      if ins.memRef != 0:
        f.memRefs.add(ins.memRef)
      # boundary conditions
      if ins.branch == brRet: break
      if ins.branch == brJmp:
        # unconditional jmp: stop if target leaves current body window
        if not (ins.target >= start and ins.target <= va + 0x10000 and b.inText(ins.target)):
          break
        # forward intra-function jmp (loop/dispatch): continue but only if target ahead
        if ins.target <= va:
          break
      if ins.branch == brJcc:
        discard
      va = va + uint64(ins.size)
      inc guardInsns
    funcStarts.incl(start)
    if f.ninsns > 0:
      if f.name.len == 0:
        f.name = "sub_" & toHex(int(start), 8).toLowerAscii  # wait: needs va
      result.add(f)
  # fix generated names using va properly
  for i in 0 ..< result.len:
    if result[i].name.len == 0:
      result[i].name = "sub_" & toHex(int(result[i].va), 8).toLowerAscii
  result.sort() do (x, y: FuncRec) -> int:
    cmp(x.va, y.va)

proc writeDot*(funcs: seq[FuncRec], path: string, maxNodes = 1200) =
  var addrs = initHashSet[uint64]()
  for f in funcs: addrs.incl(f.va)
  var f2 = funcs
  if f2.len > maxNodes:
    # keep biggest functions
    f2.sort() do (x, y: FuncRec) -> int:
      cmp(y.size, x.size)
    f2 = f2[0 ..< maxNodes]
    f2.sort() do (x, y: FuncRec) -> int:
      cmp(x.va, y.va)
  var outp = newStringOfCap(64 * 1024)
  outp.add("digraph necropsy {\n")
  outp.add("  graph [rankdir=LR, bgcolor=\"#0d0f12\", fontname=\"monospace\"];\n")
  outp.add("  node [shape=box, style=filled, fillcolor=\"#161a22\", color=\"#4a5568\", fontcolor=\"#d7dae0\", fontname=\"monospace\", fontsize=10];\n")
  outp.add("  edge [color=\"#5c6370\"];\n")
  for f in f2:
    let col = if f.name.startsWith("sub_"): "#161a22" else: "#1d2733"
    outp.add("  n" & hx(f.va)[2 .. ^1] & " [label=\"" & f.name & "\\n" & $f.size & "b\", fillcolor=\"" & col & "\"];\n")
  for f in f2:
    for c in f.callees:
      if addrs.contains(c):
        outp.add("  n" & hx(f.va)[2 .. ^1] & " -> n" & hx(c)[2 .. ^1] & ";\n")
  outp.add("}\n")
  writeFile(path, outp)
