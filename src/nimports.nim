## nimports.nim — suspicious import taxonomy (no external rule files).
## Maps imports to ATT&CK-style capability categories with weights.
import ncommon
import std/[strutils, tables, algorithm]

type
  CapHit* = object
    category*: string
    symbol*: string
    dll*: string

# category -> base weight (applied once present), amplified +4 per extra hit, capped
const CAT_WEIGHTS = {
  "process-injection": 30,
  "anti-analysis": 18,
  "credential-access": 22,
  "persistence": 20,
  "screen-capture": 20,
  "clipboard": 10,
  "memory-access": 15,
  "dynamic-loading": 8,
  "network": 12,
  "process-execution": 10,
  "privilege": 8,
  "services": 12,
  "reconnaissance": 8,
  "thread-control": 6,
  "filesystem": 3,
}.toTable

const RULE_TABLE = block:
  ## symbol (lowercase) -> category
  var t = initTable[string, string]()
  let inject = ["virtualallocex", "writeprocessmemory", "createremotethread",
    "ntmapviewofsection", "ntunmapviewofsection", "zwunmapviewofsection",
    "queueuserapc", "ntqueueapcthread", "setthreadcontext", "rtlcreateuserthread",
    "mapviewoffile"]
  for x in inject: t[x] = "process-injection"
  let antidebug = ["isdebuggerpresent", "checkremotedebuggerpresent", "outputdebugstringa",
    "outputdebugstringw", "ntqueryinformationprocess", "ntsetinformationthread",
    "debugactiveprocess", "ptrace", "ntquerysysteminformation", "dbgprint"]
  for x in antidebug: t[x] = "anti-analysis"
  let exec = ["createprocessa", "createprocessw", "winexec", "shellexecutea",
    "shellexecutew", "system", "popen", "execve", "execvp", "execl", "posix_spawn"]
  for x in exec: t[x] = "process-execution"
  let pers = ["regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "regcreatekeyexw"]
  for x in pers: t[x] = "persistence"
  let cred = ["getasynckeystate", "getkeystate", "setwindowshookexa", "setwindowshookexw",
    "lsaenumeratelogonsessions", "credenumeratea", "credenumeratew", "cryptunprotectdata",
    "logonusera", "logonuserw", "ntqueryinformationtoken"]
  for x in cred: t[x] = "credential-access"
  let net = ["wsastartup", "socket", "connect", "send", "recv", "sendto", "wsasocketa",
    "wsasocketw", "getaddrinfo", "gethostbyname", "internetopena", "internetopenw",
    "internetconnecta", "httpopenrequesta", "httpsendrequesta", "urldownloadtofilea",
    "urldownloadtofilew", "winhttpopen", "winhttpconnect", "winhttpsendrequest",
    "inet_addr", "bind", "listen", "accept", "htons", "ntohs"]
  for x in net: t[x] = "network"
  let screen = ["getdc", "getwindowdc", "createcompatibledc", "bitblt", "stretchblt",
    "getdibits", "xgetimage", "getforegroundwindow", "cgdisplaycreateimage"]
  for x in screen: t[x] = "screen-capture"
  let clip = ["openclipboard", "getclipboarddata", "setclipboarddata", "emptyclipboard"]
  for x in clip: t[x] = "clipboard"
  let mem = ["readprocessmemory", "virtualprotectex"]
  for x in mem: t[x] = "memory-access"
  let dyn = ["loadlibrarya", "loadlibraryw", "getprocaddress", "dlopen", "dlsym",
    "loadlibraryexa", "ldrregisterdllexportcallback"]
  for x in dyn: t[x] = "dynamic-loading"
  let priv = ["adjusttokenprivileges", "openprocesstoken", "setuid", "setgid",
    "lookupprivilegevaluea", "lookupprivilegevaluew"]
  for x in priv: t[x] = "privilege"
  let svc = ["createservicea", "createservicew", "startservicea", "startservicew",
    "openscmanagera", "openscmanagerw", "controlservice"]
  for x in svc: t[x] = "services"
  let recon = ["getcomputernamea", "getcomputernamew", "getusernamea", "getusernamew",
    "getsysteminfo", "globalmemorystatusex", "getversionexa", "getversionexw",
    "getsystemmetrics", "process32first", "process32firstw", "process32next",
    "process32nextw", "module32first", "module32next", "uname", "sysinfo",
    "gethostname", "enumprocesses"]
  for x in recon: t[x] = "reconnaissance"
  let thread = ["createthread", "suspendthread", "resumethread", "terminatethread",
    "setwindowlongptra", "setwindowlongptrw"]
  for x in thread: t[x] = "thread-control"
  let filesys = ["createfilea", "createfilew", "writefile", "deletefilea", "deletefilew",
    "movefilea", "copyfilea", "setfileattributesa", "fopen", "fwrite", "unlink",
    "remove", "mkdir", "createdirectorya", "createdirectoryw"]
  for x in filesys: t[x] = "filesystem"
  let misc = ["virtualalloc", "virtualprotect", "mprotect"]
  for x in misc: t[x] = "memory-alloc"
  t

proc catBaseWeight*(cat: string): int =
  if cat == "memory-alloc": 4
  elif CAT_WEIGHTS.hasKey(cat): CAT_WEIGHTS[cat]
  else: 0

proc classifyImports*(b: Binary): seq[CapHit] =
  result = @[]
  for imp in b.imports:
    var key = imp.name.toLowerAscii
    # Mach-O decorates with a leading underscore
    while key.len > 0 and key[0] == '_':
      key = key[1 ..^ 1]
    if key.len == 0: continue
    if RULE_TABLE.hasKey(key):
      result.add(CapHit(category: RULE_TABLE[key], symbol: imp.name, dll: imp.dll))
  # unix: mprotect/dlopen etc appear as dynsym imports; already covered by bare names

proc exportsByAddr*(b: Binary, va: uint64): string =
  for e in b.exportsList:
    if e.va == va: return e.name
  ""
