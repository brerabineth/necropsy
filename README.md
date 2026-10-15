# necropsy

```
  _  _ ___ ___  _  _ ___ _____ ___  _
 | \| | __|   \| \| | __|_   _/ _ \| |
 | .` | _|| |) | .` | _|  | || (_) | |__
 |_|\_|___|___|___|\_\_|___| |_| \___/|____|
          the binary post-mortem kit
```

Static triage for dead binaries. **ELF. PE. Mach-O. One native binary. Zero dependencies. Zero network.**

Drop a sample in, get the post-mortem out: format forensics, entropy cartography,
import taxonomy, embedded crypto constants, classified strings, capability verdict —
and a **built-in x86-64 disassembler** with function discovery and call-graph export.
Nothing is uploaded. Nothing is executed. The sample never runs.

```
$ necropsy analyze sample.exe

CAPABILITIES — CRITICAL 100/100 [exit 3]
   38  process injection  <- kernel32.dll!VirtualAllocEx, kernel32.dll!WriteProcessMemory,
                             kernel32.dll!CreateRemoteThread
   25  packing            <- UPX
   20  network            <- ws2_32.dll!socket, ws2_32.dll!connect, ws2_32.dll!send
   20  embedded crypto    <- AES S-box, SHA-256 round constants
```

## why

A whole category of "binary intelligence" products wants you to upload your sample to
someone else's cloud before you learn anything about it. That is backwards. The most
interesting binaries — stolen samples, vendor drop, CTF artifact, supply-chain payload —
are exactly the ones that should never leave your machine.

necropsy is the opposite design: a single static executable that reads the sample as
bytes and answers the first-contact questions locally, in milliseconds, with no
runtime, no interpreter, no rules DB download, no account, no telemetry.

|                             | necropsy          | upload-AI SaaS      | heavy IDEs (ghidra/r2/BN) | capa |
|-----------------------------|-------------------|---------------------|---------------------------|------|
| works fully offline          | yes               | no                  | yes                       | rules needed |
| install                      | one file          | account + browser   | multi-GB                  | python env |
| first verdict                | milliseconds      | upload latency      | minutes (load/analyze)    | seconds |
| disassembly                  | built-in x86-64   | cloud               | full multi-arch           | viacapstone |
| embedded crypto detection    | yes               | varies              | manual                    | no |
| entropy + packer heuristics  | yes               | varies              | plugins                   | no |
| call graph export            | graphviz DOT      | varies              | yes                       | no |
| JSON / Markdown machine out  | yes               | api tier            | scripted                  | json |
| your sample leaves the disk  | **never**         | **always**          | no                        | no |

Heavy IDEs still win for deep interactive work — necropsy is the first five minutes,
sharpened.

## what it reads

- **ELF** 32/64-bit, little and big endian: sections, dynamic symbols, `.dynsym`
  imports/exports, `.comment` compiler stamp, gopclntab detection
- **PE** 32/32+ (incl. .NET flag): section table, full import table walk, export
  directory, Rich header decoding (exact MSVC/VS version), subsystem
- **Mach-O** 64-bit: segments + sections, `LC_SYMTAB`, `LC_LOAD_DYLIB*`, undefined
  external imports

## what it reports

- **entropy** — per-section Shannon entropy plus a 64-bucket file map with hot-region flags
- **strings** — ASCII + UTF-16LE runs classified as url / ip / domain / path / registry /
  guid / base64 / suspicious
- **crypto constants** — AES S-box, SHA-256/MD5, ChaCha sigma, Blowfish P-array, TEA delta,
  CRC-32/32C, NIST P-256, secp256k1, Curve25519/Ed25519, DER/ASN.1 markers — with file offsets
- **imports** — every import tagged against an ATT&CK-style taxonomy: process-injection,
  anti-analysis, credential-access, persistence, screen-capture, network, ...
- **compiler / packer fingerprint** — GCC, Clang, MSVC (rich header version decode), MinGW,
  Go, Rust, Nim; UPX, MPRESS, VMProtect, Themida, entropy-based packing heuristics
- **disassembly** — built-in x86-64 disassembler (no capstone): length-accurate decode,
  Intel syntax, RIP-relative resolution, branch targets
- **functions** — discovery via symbol seeds + call-target harvest + prologue scan,
  per-function size/insn/call counts
- **call graph** — graphviz DOT export, colored, filtered
- **verdict** — weighted capability score 0-100, banded CLEAN / LOW / SUSPECT / CRITICAL,
  script-friendly exit codes (0/1/2/3, 10 for `--fail-on` gates)

## commands

```
necropsy analyze <file>   [--json out.json] [--md out.md] [--quiet] [--fail-on BAND]
necropsy sections  <file>
necropsy entropy   <file>
necropsy strings   <file> [--min N] [--kind url|ip|domain|registry|b64|sus|...]
necropsy imports   <file>
necropsy exports   <file>
necropsy crypto    <file>
necropsy disasm    <file> [--addr VA | --func NAME | --entry] [--count N]
necropsy functions <file>
necropsy graph     <file> --dot out.dot
necropsy diff      <fileA> <fileB>
```

Every parser is bounds-checked by construction: truncated, corrupted or hostile headers
produce a clean `necropsy: error: ...` on stderr and exit 64 — never a crash, never a
read past the buffer. The tool dissects itself happily (621 functions found at last count).

## verdict model

Each capability category carries a base weight, amplified by distinct evidence.
Crypto constants and suspicious strings add smaller bonuses; packer signatures add 25.
The sum is capped at 100 and banded:

| band     | score | exit |
|----------|-------|------|
| CLEAN    | < 10  | 0    |
| LOW      | < 30  | 1    |
| SUSPECT  | < 60  | 2    |
| CRITICAL | >= 60 | 3    |

`--fail-on low|suspect|critical` forces exit 10 when the band is reached — wire it
into mail-gate or sandbox triage scripts and let the exit code do the talking.

## build

Nim 2.x, no dependencies beyond the standard library:

```
make            # nim c -d:release --mm:orc
make test       # builds fixtures + 61-assertion e2e suite
```

## notes

- disassembly currently covers x86-64; unknown opcodes render as `.byte 0xNN` and never
  desync length tracking
- Mach-O fat binaries, 32-bit Mach-O and PE ARM64T are parsed as format errors, not crashes
- the scanner never flags itself: language-fingerprint needles are assembled at runtime
  so they don't exist as contiguous strings in `.rodata`

## license

MIT — see [LICENSE](LICENSE).
