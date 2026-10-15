#!/usr/bin/env bash
# necropsy end-to-end test suite (local). POSIX-ish, no external deps.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
BIN="$ROOT/bin/necropsy"
FIX="$ROOT/test/fixtures"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
PASS=0
FAIL=0

say()  { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS+1)); say "  ok: $1"; }
bad()  { FAIL=$((FAIL+1)); say "  FAIL: $1"; }
check() { # check <desc> <cmd...>
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi
}
contains() { # contains <desc> <needle> <file>
  if grep -qF -- "$2" "$3" 2>/dev/null; then ok "$1"; else bad "$1 (missing: $2)"; fi
}
notcontains() {
  if grep -qF -- "$2" "$3" 2>/dev/null; then bad "$1 (found: $2)"; else ok "$1"; fi
}
runout() { # runout <ignored> <cmd...> — captures stdout+stderr, echoes exit code
  shift
  "$@" >"$TMP/out.txt" 2>"$TMP/err.txt"
  echo $? > "$TMP/code.txt"
  cat "$TMP/out.txt" "$TMP/err.txt" > "$TMP/all.txt"
}

say "== build fixtures =="
gcc -O0 -o "$FIX/benign" "$FIX/benign.c" 2>/dev/null || { bad "gcc benign"; exit 1; }
gcc -O0 -o "$FIX/suspicious" "$FIX/suspicious.c" 2>/dev/null || { bad "gcc suspicious"; exit 1; }
python3 "$FIX/gen_fixtures.py" >/dev/null 2>&1 || { bad "fixture gen"; exit 1; }
ok "fixtures built"

say "== analyze: verdicts + exit codes =="
LINUX=0; [ "$(uname)" = "Linux" ] && LINUX=1
runout x "$BIN" --no-color analyze "$FIX/benign"
[ "$(cat "$TMP/code.txt")" = "0" ] && ok "benign exit 0" || bad "benign exit (got $(cat "$TMP/code.txt"))"
contains "benign CLEAN" "CLEAN" "$TMP/all.txt"
if [ "$LINUX" = "1" ]; then
contains "benign compiler gcc" "GCC" "$TMP/all.txt"
fi

runout x "$BIN" --no-color analyze "$FIX/suspicious"
[ "$(cat "$TMP/code.txt")" = "2" ] && ok "suspicious exit 2" || bad "suspicious exit (got $(cat "$TMP/code.txt"))"
contains "suspicious SUSPECT" "SUSPECT" "$TMP/all.txt"
contains "suspicious AES" "AES S-box" "$TMP/all.txt"
contains "suspicious sha256 k" "SHA-256" "$TMP/all.txt"
contains "suspicious persistence" "persistence markers" "$TMP/all.txt"
contains "suspicious c2 url" "http://185.220.101.47/gate.php" "$TMP/all.txt"

runout x "$BIN" --no-color analyze "$FIX/pe64_minimal.exe"
[ "$(cat "$TMP/code.txt")" = "3" ] && ok "pe64 exit 3" || bad "pe64 exit (got $(cat "$TMP/code.txt"))"
contains "pe64 CRITICAL" "CRITICAL" "$TMP/all.txt"
contains "pe64 injection" "process injection" "$TMP/all.txt"
contains "pe64 import" "kernel32.dll!VirtualAllocEx" "$TMP/all.txt"
contains "pe64 crypto" "AES S-box" "$TMP/all.txt"

runout x "$BIN" --no-color analyze "$FIX/macho64_minimal"
[ "$(cat "$TMP/code.txt")" = "1" ] && ok "macho exit 1" || bad "macho exit (got $(cat "$TMP/code.txt"))"
contains "macho anti-analysis" "anti analysis" "$TMP/all.txt"
contains "macho _ptrace" "_ptrace" "$TMP/all.txt"

say "== malformed inputs =="
runout x "$BIN" analyze "$FIX/corrupt_truncated.elf"
[ "$(cat "$TMP/code.txt")" = "64" ] && ok "truncated exit 64" || bad "truncated exit (got $(cat "$TMP/code.txt"))"
runout x "$BIN" analyze "$FIX/random.bin"
[ "$(cat "$TMP/code.txt")" = "64" ] && ok "random exit 64" || bad "random exit (got $(cat "$TMP/code.txt"))"
runout x "$BIN" analyze "$FIX/empty.bin"
[ "$(cat "$TMP/code.txt")" = "64" ] && ok "empty exit 64" || bad "empty exit (got $(cat "$TMP/code.txt"))"
contains "error is clean text" "necropsy: error:" "$TMP/err.txt"

say "--fail-on gate =="
runout x "$BIN" --no-color analyze "$FIX/benign" --fail-on low
[ "$(cat "$TMP/code.txt")" = "0" ] && ok "gate clean stays 0" || bad "gate clean (got $(cat "$TMP/code.txt"))"
runout x "$BIN" --no-color analyze "$FIX/suspicious" --fail-on low
[ "$(cat "$TMP/code.txt")" = "10" ] && ok "gate low -> 10" || bad "gate low (got $(cat "$TMP/code.txt"))"
runout x "$BIN" --no-color analyze "$FIX/suspicious" --fail-on critical
[ "$(cat "$TMP/code.txt")" = "2" ] && ok "gate critical not reached -> 2" || bad "gate critical (got $(cat "$TMP/code.txt"))"

say "== json + markdown reports =="
runout x "$BIN" --no-color analyze "$FIX/suspicious" --quiet --json "$TMP/r1.json" --md "$TMP/r.md"
[ "$(cat "$TMP/code.txt")" = "2" ] && ok "quiet keeps exit" || bad "quiet exit"
python3 -c "import json;d=json.load(open('$TMP/r1.json'));assert d['verdict']['band']=='SUSPECT';assert d['format'].startswith('fmt');assert 'AES S-box' in [c['name'] for c in d['crypto']]" && ok "json valid + fields" || bad "json invalid"
grep -q "| verdict |" "$TMP/r.md" && ok "md has verdict" || bad "md verdict"
runout x "$BIN" --no-color analyze "$FIX/suspicious" --quiet --json "$TMP/r2.json"
cmp -s "$TMP/r1.json" "$TMP/r2.json" && ok "json deterministic" || bad "json not deterministic"

say "== sections / entropy / strings =="
runout x "$BIN" --no-color sections "$FIX/suspicious"
contains "sections entropy col" "ent=" "$TMP/all.txt"
runout x "$BIN" --no-color entropy "$FIX/suspicious"
contains "entropy sparkline" "0.0" "$TMP/all.txt"
if [ "$LINUX" = "1" ]; then
contains "sections .text" ".text" "$TMP/all.txt"
contains "entropy hot rodata" "hot" "$TMP/all.txt"
fi
runout x "$BIN" --no-color strings "$FIX/suspicious" --kind url
contains "strings url" "http://185.220.101.47/gate.php" "$TMP/all.txt"
runout x "$BIN" --no-color strings "$FIX/suspicious" --kind url --min 60
notcontains "min filters short" "gate.php" "$TMP/all.txt"
runout x "$BIN" --no-color strings "$FIX/suspicious" --kind registry
contains "registry hit" 'CurrentVersion\Run' "$TMP/all.txt"

say "== imports / exports / crypto =="
runout x "$BIN" --no-color imports "$FIX/pe64_minimal.exe"
contains "import tagged" "[process-injection]" "$TMP/all.txt"
contains "import dll" "ws2_32.dll!socket" "$TMP/all.txt"
runout x "$BIN" --no-color exports "$BIN"
grep -qcE "^  0x[0-9a-f]+  " "$TMP/all.txt" && ok "exports rows" || bad "exports rows"
runout x "$BIN" --no-color crypto "$FIX/pe64_minimal.exe"
contains "crypto sbox" "AES S-box" "$TMP/all.txt"
runout x "$BIN" --no-color crypto "$FIX/suspicious"
contains "crypto sha256" "SHA-256 round constants" "$TMP/all.txt"

say "== disasm =="
if [ "$LINUX" = "1" ]; then
runout x "$BIN" --no-color disasm "$FIX/suspicious" --func main --count 30
contains "disasm prologue" "push rbp" "$TMP/all.txt"
contains "disasm call" "call" "$TMP/all.txt"
fi
runout x "$BIN" --no-color disasm "$FIX/macho64_minimal" --addr 0x10000 --count 5
contains "macho disasm main" "mov eax, 0x2a" "$TMP/all.txt"
runout x "$BIN" --no-color disasm "$FIX/suspicious" --addr 0x11b5 --count 4
NG=$(grep -cE "^  0x[0-9a-f]{16} " "$TMP/all.txt")
[ "$NG" -ge 4 ] && ok "disasm advances" || bad "disasm advance (got $NG insns)"
runout x "$BIN" --no-color disasm "$FIX/suspicious" --addr 0xdeadbeef --count 2
[ "$(cat "$TMP/code.txt")" = "64" ] && ok "bad addr -> 64" || bad "bad addr (got $(cat "$TMP/code.txt"))"

say "== functions / graph =="
if [ "$LINUX" = "1" ]; then
runout x "$BIN" --no-color functions "$FIX/suspicious"
contains "functions main" "main" "$TMP/all.txt"
contains "functions simple_hash" "simple_hash" "$TMP/all.txt"
fi
runout x "$BIN" --no-color graph "$FIX/suspicious" --dot "$TMP/g.dot"
grep -q "digraph necropsy" "$TMP/g.dot" && ok "dot header" || bad "dot header"
grep -qE "n[0-9a-f]+ -> n[0-9a-f]+" "$TMP/g.dot" && ok "dot edges" || bad "dot edges"
runout x "$BIN" --no-color functions "$BIN"
grep -q "FUNCTIONS" "$TMP/all.txt" && ok "self-analysis survives" || bad "self-analysis crash"

say "== diff =="
runout x "$BIN" --no-color diff "$FIX/benign" "$FIX/suspicious"
[ "$(cat "$TMP/code.txt")" = "0" ] && ok "diff exit 0" || bad "diff exit (got $(cat "$TMP/code.txt"))"
contains "diff verdict line" "CLEAN" "$TMP/all.txt"
contains "diff crypto" "crypto constants" "$TMP/all.txt"

say "== usage errors =="
runout x "$BIN"
[ "$(cat "$TMP/code.txt")" = "64" ] && ok "no args -> 64" || bad "no args (got $(cat "$TMP/code.txt"))"
runout x "$BIN" analyze /nonexistent/file
[ "$(cat "$TMP/code.txt")" = "64" ] && ok "missing file -> 64" || bad "missing file (got $(cat "$TMP/code.txt"))"
runout x "$BIN" version
grep -q "necropsy 0.1.0" "$TMP/all.txt" && ok "version" || bad "version"
runout x "$BIN" help
grep -q "binary post-mortem kit" "$TMP/all.txt" && ok "help" || bad "help"

say "== path hygiene =="
for f in "$TMP"/r.md "$TMP/g.dot"; do
  if grep -q "/home/z" "$f" 2>/dev/null; then bad "host path leak in $f"; else ok "no host paths in $(basename "$f")"; fi
done
runout x "$BIN" --no-color analyze "$FIX/suspicious" --quiet --json "$TMP/hygiene.json"
if grep -q "/home/z" "$TMP/hygiene.json"; then bad "host path in json"; else ok "no host paths in json"; fi

say ""
say "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = "0" ]
