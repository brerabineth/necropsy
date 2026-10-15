## ncrypto.nim — embedded cryptographic constant identification.
## Scans raw bytes for well-known algorithm fingerprints, reports file offsets.
import ncommon
import std/[strutils, algorithm]

type SigEntry* = object
  name*: string
  bytes: seq[byte]
  note*: string

proc hxBytes(s: string): seq[byte] =
  ## hex string -> bytes (spaces ignored)
  var clean = ""
  for c in s:
    if c != ' ': clean.add(c)
  for i in countup(0, clean.len - 2, 2):
    result.add(byte(parseHexInt(clean[i .. i + 1])))

proc ascBytes(s: string): seq[byte] =
  for c in s: result.add(byte(ord(c)))

const TABLE: array[18, SigEntry] = [
  SigEntry(name: "AES S-box",
    bytes: hxBytes("63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76"),
    note: "AES substitution table (encryption)"),
  SigEntry(name: "AES inverse S-box",
    bytes: hxBytes("52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb"),
    note: "AES substitution table (decryption)"),
  SigEntry(name: "SHA-256 round constants",
    bytes: hxBytes("42 8a 2f 98 71 37 44 91 b5 c0 fbcf e9 b5 dba5"),
    note: "SHA-256 K[0..3]"),
  SigEntry(name: "SHA-256 H vector",
    bytes: hxBytes("6a 09 e6 67 bb 67 ae 85 3c 6e f3 72 a5 4f f5 3a"),
    note: "SHA-256 initial hash state"),
  SigEntry(name: "MD5 / SHA-1 / RIPEMD-160 init",
    bytes: hxBytes("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
    note: "legacy digest initializer"),
  SigEntry(name: "MD5 T-table start",
    bytes: hxBytes("78 a4 6a d7"), note: "MD5 K[0]"),
  SigEntry(name: "ChaCha/Salsa constant",
    bytes: ascBytes("expand 32-byte k"), note: "ChaCha20/Salsa20 sigma"),
  SigEntry(name: "ChaCha constant (16-bit)",
    bytes: ascBytes("expand 16-byte k"), note: "ChaCha12/8 variant"),
  SigEntry(name: "Blowfish P-array",
    bytes: hxBytes("24 3f 6a 88 85 a3 08 d3"), note: "Blowfish P[0..1]"),
  SigEntry(name: "TEA/XTEA delta",
    bytes: hxBytes("b9 79 37 9e"), note: "0x9E3779B9 LE (golden ratio)"),
  SigEntry(name: "CRC-32 (IEEE) table",
    bytes: hxBytes("96 30 07 77"), note: "CRC32 table entry LE"),
  SigEntry(name: "CRC-32C (Castagnoli) table",
    bytes: hxBytes("57 76 07 f2"), note: "CRC32C table entry LE"),
  SigEntry(name: "NIST P-256 prime",
    bytes: hxBytes("ff ff ff ff 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 ff ff ff ff ff ff ff ff ff ff ff ff"),
    note: "NIST P-256 field prime"),
  SigEntry(name: "secp256k1 prime",
    bytes: hxBytes("ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff fe ff ff fc 2f"),
    note: "secp256k1 field prime (Bitcoin)"),
  SigEntry(name: "Curve25519 prime",
    bytes: hxBytes("7f ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ed"),
    note: "2^255-19 field prime (X25519/Ed25519)"),
  SigEntry(name: "Ed25519 base point x",
    bytes: hxBytes("21 69 36 d3 cd 6e 53 fe c0 a4 e2 31 fd d6 dc 5c 69 2c c7 60 95 25 a7 b2 c9 56 2d 60 8f 25 d5 1a"),
    note: "Ed25519 standard base point"),
  SigEntry(name: "RSA/ASN.1 PKCS#1 prefix",
    bytes: hxBytes("30 31 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00"),
    note: "DER-encoded RSA public key AlgorithmIdentifier"),
  SigEntry(name: "ASN.1 EC prime field OID",
    bytes: hxBytes("06 07 2a 86 48 ce 3d 01 01"), note: "prime-field EC parameters OID")
]

proc scanCrypto*(b: Binary): seq[CryptoRec] =
  result = @[]
  let d = b.data
  for sig in TABLE:
    var i = 0
    var hits = 0
    let L = sig.bytes.len
    while i + L <= d.len and hits < 8:
      var ok = true
      for j in 0 ..< L:
        if d[i + j] != sig.bytes[j]:
          ok = false; break
      if ok:
        result.add(CryptoRec(name: sig.name, off: uint64(i), note: sig.note))
        inc hits
        i += L  # non-overlapping forward
      else:
        inc i
  result.sort() do (x, y: CryptoRec) -> int:
    cmp(x.off, y.off)

proc cryptoVerdictBonus*(hits: seq[CryptoRec]): tuple[score: int, summary: string] =
  ## Weight: strong indicators (tables, curves) count more than ambiguous deltas.
  var strong = 0
  var names: seq[string] = @[]
  for h in hits:
    if "TEA/XTEA" in h.name or "CRC" in h.name or "MD5 T-table" in h.name or "init" in h.name:
      continue  # ambiguous constants
    if not (h.name in names):
      names.add(h.name)
    if "AES" in h.name or "ChaCha" in h.name or "SHA-256" in h.name or
       "Blowfish" in h.name or "25519" in h.name or "P-256" in h.name or
       "secp256k1" in h.name:
      inc strong
  var score = min(20, names.len * 5 + strong * 3)
  if names.len > 0 and score < 8: score = 8
  return (score, names.join(", "))
