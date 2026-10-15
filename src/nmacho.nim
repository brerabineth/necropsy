## nmacho.nim — Mach-O 64 parser (x86-64 / arm64), from scratch.
import ncommon
import std/[strutils]

const
  LC_SEGMENT_64 = 0x19
  LC_SYMTAB = 0x2
  LC_LOAD_DYLIB = 0xC
  LC_LOAD_WEAK_DYLIB = 0x80000018'u64
  LC_REEXPORT_DYLIB = 0x8000001F'u64
  LC_MAIN = 0x28 or 0x80000000'u64
  CPU_X86_64 = 0x01000007
  CPU_ARM64 = 0x0100000C

proc sectFlags(fl: uint64): string =
  let attr = fl and 0xE0000000'u64  # section attributes high bits are not rwx; derive from type
  # Mach-O does not carry rwx per section like ELF; approximate from type flags
  let typ = fl and 0xFF
  result = "r-"
  if typ == 0: result = "r-"
  # S_ZEROFILL=1 -> no file bytes; S_SYMBOL_STUBS=8 etc. Execution: __TEXT segments are x
  discard attr
  discard typ

proc parseMacho*(b: Binary) =
  let d = b.data
  b.format = fmtMachO
  # canonical: bytes CF FA ED FE (LE) = MH_MAGIC_64
  if d.len < 32:
    raise necroFail("truncated Mach-O header")
  if d[0] == 0xFE and d[1] == 0xED and d[2] == 0xFA and d[3] == 0xCE:
    raise necroFail("32-bit Mach-O not supported (use the 64-bit sample)")
  if not (d[0] == 0xCF and d[1] == 0xFA and d[2] == 0xED and d[3] == 0xFE):
    raise necroFail("not a 64-bit little-endian Mach-O")
  b.bits = 64
  b.endian = "little"
  let cputype = rdU32(d, 4)
  let filetype = rdU32(d, 12)
  b.arch = case cputype
    of CPU_X86_64: "x86-64"
    of CPU_ARM64: "arm64"
    else: "cpu 0x" & cputype.toHex
  b.kind = case filetype
    of 1: "relocatable"
    of 2: "executable"
    of 6: "dylib"
    of 8: "bundle"
    of 13: "dylinker"
    else: "macho(" & $filetype & ")"
  let ncmds = int(rdU32(d, 16))
  var off = 32'u64
  var syms: seq[SymRec] = @[]
  var strtabOff, strtabSize: uint64 = 0
  for i in 0 ..< min(ncmds, 8192):
    if off + 8 > uint64(d.len): break
    let cmd = rdU32(d, off)
    let cmdsize = int(rdU32(d, off + 4))
    if cmdsize < 8 or off + uint64(cmdsize) > uint64(d.len): break
    case cmd
    of LC_SEGMENT_64:
      let segname = block:
        var s = ""
        for j in 0 ..< 16:
          let c = d[int(off + 8) + j]
          if c == 0: break
          s.add(chr(c))
        s
      let vmaddr = rdU64(d, off + 24)
      let vmsize = rdU64(d, off + 32)
      let fileoff = rdU64(d, off + 40)
      let filesize = rdU64(d, off + 48)
      let nsects = int(rdU32(d, off + 64))
      var isExec = false
      var isWrite = false
      # initprot at off+56: VM_PROT_READ=1 WRITE=2 EXEC=4
      let initprot = rdU32(d, off + 56)
      isExec = (initprot and 4) != 0
      isWrite = (initprot and 2) != 0
      let fl = (if isExec: "rx" elif isWrite: "rw" else: "r-")
      if segname == "__PAGEZERO":
        off = off + uint64(cmdsize); continue
      var sent = SectionRec(name: segname, va: vmaddr, off: fileoff,
                            size: filesize, vsize: vmsize, flags: fl)
      if filesize > 0 and fileoff + filesize <= uint64(d.len):
        sent.entropy = shannon(d[int(fileoff) ..< int(fileoff + filesize)])
      b.sections.add(sent)
      var so = off + 72
      for s in 0 ..< min(nsects, 256):
        if so + 80 > uint64(d.len): break
        var sectName = ""
        for j in 0 ..< 16:
          let c = d[int(so) + j]
          if c == 0: break
          sectName.add(chr(c))
        let sAddr = rdU64(d, so + 32)
        let sSize = rdU64(d, so + 40)
        let sOff = rdU32(d, so + 48)
        let sFlags = rdU32(d, so + 60)
        let isZero = (sFlags and 0xFF) == 1  # S_ZEROFILL
        var sub = SectionRec(name: segname & "," & sectName, va: sAddr,
                             off: (if isZero: 0'u64 else: sOff),
                             size: (if isZero: 0'u64 else: sSize),
                             vsize: sSize, flags: fl)
        if not isZero and sSize > 0 and sOff + sSize <= uint64(d.len):
          sub.entropy = shannon(d[int(sOff) ..< int(sOff + sSize)])
        b.sections.add(sub)
        if isExec and sectName == "__text":
          b.textStart = sAddr
          b.textSize = sSize
        so = so + 80
    of LC_SYMTAB:
      let symoff = rdU32(d, off + 8)
      let nsyms = int(rdU32(d, off + 12))
      strtabOff = rdU32(d, off + 16)
      strtabSize = rdU32(d, off + 20)
      for s in 0 ..< min(nsyms, 200_000):
        let so = symoff + uint64(s * 16)
        if so + 16 > uint64(d.len): break
        let nstrx = rdU32(d, so)
        let ntype = d[int(so) + 4]
        let nsect = d[int(so) + 5]
        let nvalue = rdU64(d, so + 8)
        if nstrx == 0 or strtabOff + nstrx >= strtabOff + strtabSize: continue
        var nm = ""
        try: nm = rdCstr(d, strtabOff + nstrx)
        except NecroError: continue
        if nm.len == 0: continue
        let nType2 = ntype and 0x0E
        if nType2 == 0:
          # undefined external -> import
          b.imports.add(ImportRec(dll: "", name: nm, ordinal: 0))
        elif nType2 == 0x0E:  # N_SECT
          let isFunc = (ntype and 0x0F) == 0x0F  # N_ABS no; N_SECT type check via n_desc not reliable
          syms.add(SymRec(name: nm, va: nvalue, size: 0, isFunc: true))
          b.exportsList.add(ExportRec(name: nm, va: nvalue, ordinal: s))
    of LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB:
      let nameOff = int(rdU32(d, off + 8))
      if nameOff > 0 and nameOff < cmdsize:
        var nm = ""
        try: nm = rdCstr(d, off + uint64(nameOff))
        except NecroError: nm = ""
        if nm.len > 0: b.dlls.add(nm)
    of LC_MAIN:
      let entryoff = rdU64(d, off + 8)
      b.entry = entryoff  # file offset of main; VM addr = text vmaddr + entryoff
      if b.textStart == 0:
        b.textStart = entryoff
    else: discard
    off = off + uint64(cmdsize)
  b.symbols = syms
  if b.textStart == 0:
    var best = 0'u64
    for s in b.sections:
      if s.flags == "rx" and s.size > best:
        best = s.size
        b.textStart = s.va
        b.textSize = s.size
