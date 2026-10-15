## ndiff.nim — structural diff between two binaries.
import ncommon, nstrings, ncrypto, ncaps, nentropy
import std/[strutils, sets, algorithm]

type
  DiffResult* = object
    secAdded*: seq[string]
    secRemoved*: seq[string]
    impAdded*: seq[string]
    impRemoved*: seq[string]
    expAdded*: seq[string]
    expRemoved*: seq[string]
    cryptoAdded*: seq[string]
    cryptoRemoved*: seq[string]
    verdictA*: string
    verdictB*: string
    scoreA*: int
    scoreB*: int

proc impKey(i: ImportRec): string =
  var s = ""
  if i.dll.len > 0: s &= i.dll & "!"
  if i.name.len > 0: s &= i.name
  else: s &= "ord#" & $i.ordinal
  s

proc diffBinaries*(a, b: Binary, cryptoA, cryptoB: seq[CryptoRec],
                   vA, vB: Verdict): DiffResult =
  var secA = initHashSet[string]()
  var secB = initHashSet[string]()
  for s in a.sections: secA.incl(s.name)
  for s in b.sections: secB.incl(s.name)
  for s in secA:
    if s notin secB and s.len > 0: result.secRemoved.add(s)
  for s in secB:
    if s notin secA and s.len > 0: result.secAdded.add(s)
  var impA = initHashSet[string]()
  var impB = initHashSet[string]()
  for i in a.imports: impA.incl(i.impKey())
  for i in b.imports: impB.incl(i.impKey())
  for i in impA:
    if i notin impB: result.impRemoved.add(i)
  for i in impB:
    if i notin impA: result.impAdded.add(i)
  var expA = initHashSet[string]()
  var expB = initHashSet[string]()
  for e in a.exportsList: expA.incl(e.name)
  for e in b.exportsList: expB.incl(e.name)
  for e in expA:
    if e notin expB: result.expRemoved.add(e)
  for e in expB:
    if e notin expA: result.expAdded.add(e)
  var cA = initHashSet[string]()
  var cB = initHashSet[string]()
  for c in cryptoA: cA.incl(c.name)
  for c in cryptoB: cB.incl(c.name)
  for c in cA:
    if c notin cB: result.cryptoRemoved.add(c)
  for c in cB:
    if c notin cA: result.cryptoAdded.add(c)
  result.verdictA = vA.band
  result.verdictB = vB.band
  result.scoreA = vA.score
  result.scoreB = vB.score
  result.secAdded.sort(); result.secRemoved.sort()
  result.impAdded.sort(); result.impRemoved.sort()
  result.expAdded.sort(); result.expRemoved.sort()
  result.cryptoAdded.sort(); result.cryptoRemoved.sort()
