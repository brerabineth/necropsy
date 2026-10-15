## nstrings.nim — string extraction with IOC classification.
import ncommon
import std/[strutils, algorithm]

const SUSPICIOUS_WORDS = [
  "passw", "keylog", "backdoor", "shellcode", "ransom", "botnet", "keylogger",
  "credential", "wallet.dat", "seed phrase", "keystore", "cookies.sqlite",
  "login data", "web data", "local state", "\\temp\\", "/tmp/.", "cmd.exe",
  "powershell", "-enc ", "frombase64", "virtualalloc", "writeprocessmemory",
  "createremotethread", "schtasks", "vssadmin", "bcdedit", "shadow copy",
  "discord.com/api/webhooks", "api.telegram.org", "pastebin.com/raw",
  "xmrig", "mining", "stratum+tcp", ".onion", "mimikatz", "sekurlsa"
]

proc isDigitCh(c: char): bool = c >= '0' and c <= '9'
proc isAlphaL(c: char): bool = c >= 'a' and c <= 'z'
proc isAlphaU(c: char): bool = c >= 'A' and c <= 'Z'
proc isAlnum(c: char): bool = isDigitCh(c) or isAlphaL(c) or isAlphaU(c)

proc looksLikeIp(s: string): bool =
  var parts = s.split('.')
  if parts.len != 4: return false
  for p in parts:
    if p.len == 0 or p.len > 3: return false
    for c in p:
      if not isDigitCh(c): return false
    if p.len > 1 and p[0] == '0': return false
    if parseInt(p) > 255: return false
  true

proc looksLikeDomain(s: string): bool =
  ## domain-ish, rejects version numbers and short fragments
  if s.len < 4 or s.len > 253: return false
  if ' ' in s or '/' in s or ':' in s: return false
  let parts = s.split('.')
  if parts.len < 2: return false
  let tld = parts[^1]
  if tld.len < 2 or tld.len > 12: return false
  for c in tld:
    if not (isAlphaL(c) or isDigitCh(c)): return false
  var labels = 0
  for p in parts:
    if p.len == 0 or p.len > 63: return false
    for c in p:
      if not (isAlnum(c) or c == '-' or c == '_'): return false
    inc labels
  # reject x.y.z version-like (all numeric labels)
  var numeric = 0
  for p in parts:
    var allNum = p.len > 0
    for c in p:
      if not isDigitCh(c): allNum = false; break
    if allNum: inc numeric
  if numeric == labels: return false
  true

proc classify(s: string): StrKind =
  result = skAscii
  let low = s.toLowerAscii
  if s.startsWith("http://") or s.startsWith("https://") or s.startsWith("ftp://"):
    return skUrl
  if low.startsWith("hxxp://") or low.startsWith("hxxps://"):
    return skUrl
  if looksLikeIp(s): return skIp
  if low.startsWith("hklm\\") or low.startsWith("hkey_") or low.startsWith("hkcu\\"):
    return skRegistry
  if "currentversion\\run" in low or "currentversion\\explorer" in low:
    return skRegistry
  if s.startsWith("C:\\") or s.startsWith("c:\\") or s.startsWith("%") or
     s.startsWith("\\\\") or s.startsWith("/etc/") or s.startsWith("/usr/") or
     s.startsWith("/proc/") or s.startsWith("/dev/") or s.startsWith("/home/") or
     s.startsWith("/var/") or s.startsWith("/opt/"):
    return skPath
  if s.len >= 32 and s.len <= 40 and s.count(':') == 4 and
     (s[8] == '-' and s[13] == '-' and s[18] == '-' and s[23] == '-'):
    return skGuid
  if s.len >= 24 and s.len mod 4 == 0:
    var b64ok = true
    var eqSeen = false
    for c in s:
      if c == '=': eqSeen = true
      elif not (isAlnum(c) or c == '+' or c == '/'):
        b64ok = false; break
      elif eqSeen: b64ok = false; break
    if b64ok: return skB64
  for w in SUSPICIOUS_WORDS:
    if w in low: return skSus
  if looksLikeDomain(s): return skDomain

proc extractStrings*(b: Binary, minLen = 5): seq[StringRec] =
  ## ASCII runs + UTF-16LE runs, classified. Offsets are file offsets.
  result = @[]
  let d = b.data
  var i = 0
  var cur = ""
  var start = 0
  let n = d.len
  template flush() {.dirty.} =
    if cur.len >= minLen:
      let k = classify(cur)
      result.add(StringRec(off: uint64(start), kind: k, value: cur))
    cur.setLen(0)
  while i < n:
    let c = d[i]
    if printableChar(c):
      if cur.len == 0: start = i
      cur.add(chr(c))
      inc i
    else:
      flush()
      # UTF-16LE detection: printable,0x00,printable,0x00 (min run 4 pairs)
      if c == 0 and i + 1 < n and i > 0 and printableChar(d[i - 1]) and
         i + 3 < n and printableChar(d[i + 1]) and d[i + 2] == 0 and printableChar(d[i + 3]):
        # scan backwards to find run start
        var s0 = i - 1
        while s0 >= 2 and printableChar(d[s0 - 2]) and d[s0 - 1] == 0:
          s0 = s0 - 2
        var u = ""
        var j = s0
        while j + 1 < n and printableChar(d[j]) and d[j + 1] == 0:
          u.add(chr(d[j]))
          j += 2
        if u.len >= max(6, minLen + 1):
          result.add(StringRec(off: uint64(s0), kind: classify(u), value: u))
        i = j
      else:
        inc i
  flush()
  result.sort() do (x, y: StringRec) -> int:
    cmp(x.off, y.off)

proc kindName*(k: StrKind): string =
  case k
  of skAscii: "ascii"
  of skUrl: "url"
  of skIp: "ip"
  of skDomain: "domain"
  of skPath: "path"
  of skRegistry: "registry"
  of skGuid: "guid"
  of skB64: "base64"
  of skSus: "suspicious"

proc iocStrings*(strs: seq[StringRec]): seq[StringRec] =
  for s in strs:
    if s.kind in {skUrl, skIp, skDomain, skRegistry, skB64}: result.add(s)
