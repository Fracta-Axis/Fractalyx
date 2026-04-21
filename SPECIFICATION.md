# FYX File Format Specification

**Media Type Name:** `application`  
**Media Subtype Name:** `vnd.fractalyx.fyx`  
**Required Parameters:** none  
**Optional Parameters:** none  
**Encoding Considerations:** Binary  
**File Extension:** `.fyx`  
**Magic Number:** `4D 46 53 55 76 34` (offset 0, 6 bytes) — ASCII `MFSUv4`  
**Specification Version:** 2.0.0  
**Date:** 2026-04-21  
**Author / Change Controller:** Fracta-Axis  
**Repository:** https://github.com/Fracta-Axis/Fractalyx  
**Contact:** https://github.com/Fracta-Axis  

---

## Abstract

This document specifies the `.fyx` binary file format used by the Fractalyx encryption system. The format defines a self-identifying, authenticated, password-protected container for arbitrary binary data. Two sub-formats are defined: **FractalShield v4** (primary, multi-layer deniable encryption, magic `MFSUv4`) and **MFSU Standard v3** (legacy, single-layer authenticated encryption, magic `MFSUv3`). All cryptographic material is derived from the **Unified Fractal-Stochastic Model (MFSU)** combined with SHA-3 and HMAC primitives.

---

## 1. Conventions Used in This Document

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

All multi-byte integer fields are stored in **big-endian** (network) byte order unless otherwise noted.

The notation `A ‖ B` denotes the concatenation of byte strings A and B.

---

## 2. Magic Number and Format Identification

A conforming implementation **MUST** identify `.fyx` files exclusively by inspecting the first 6 bytes of the file (the Magic Number). File extension alone **MUST NOT** be used as the sole identification mechanism.

### 2.1 Registered Magic Numbers

| Sub-format | Offset | Length | Hex Value | ASCII | Version Byte (offset 6) |
|---|---|---|---|---|---|
| FractalShield v4 | 0 | 6 bytes | `4D 46 53 55 76 34` | `MFSUv4` | `0x04` |
| MFSU Standard v3 | 0 | 6 bytes | `4D 46 53 55 76 33` | `MFSUv3` | `0x03` |

### 2.2 Detection Algorithm

```
bytes magic_v4 = { 0x4D, 0x46, 0x53, 0x55, 0x76, 0x34 }  // "MFSUv4"
bytes magic_v3 = { 0x4D, 0x46, 0x53, 0x55, 0x76, 0x33 }  // "MFSUv3"

if file.length < 7:
    REJECT — file too short

if file[0:6] == magic_v4 AND file[6] == 0x04:
    → FractalShield v4  (primary .fyx format)
elif file[0:6] == magic_v3 AND file[6] == 0x03:
    → MFSU Standard v3  (legacy .fyx format)
else:
    REJECT — not a valid .fyx file
```

A parser **MUST** reject any file whose first 6 bytes do not match one of the registered magic sequences. A parser **MUST** reject any file whose version byte (offset 6) does not match the expected value for the identified sub-format.

---

## 3. Normative Constants

The following constants are **normative**. Any implementation claiming conformance with this specification **MUST** use these exact values. Deviation from any constant produces files that are **not** interoperable with the reference implementation.

### 3.1 MFSU Mathematical Constants

```
DELTA_F   = 0.921          # Fractional dissipation coefficient
BETA      = 1.079          # Fractional Laplacian exponent  (= 2.0 - DELTA_F)
HURST     = 0.541          # Hurst exponent of fractional Gaussian noise
DF_PROJ   = 2.921          # Fractal dimension of projected field (= 2.0 + DELTA_F)
GAMMA_NL  = 0.921          # Non-linear coupling constant (= DELTA_F)
SIGMA_ETA = 0.1            # Noise amplitude
```

### 3.2 KDF Constants

```
KDF_N = 2048               # Spatial grid points for KDF field evolution
KDF_M = 256                # KDF evolution steps (scratchpad depth)
```

### 3.3 Keystream Constants

```
KS_N  = 512                # Spatial grid points for keystream field evolution
```

### 3.4 Format Constants

```
# FractalShield v4
MAGIC_V4       = 4D 46 53 55 76 34       # "MFSUv4"  (6 bytes)
VERSION_V4     = 04                      # 1 byte
REAL_MAGIC     = 4D 46 53 55 04          # "MFSU\x04" (5 bytes) — real-layer sentinel
ORDER_SALT_FS  = 4D 46 53 55 5F 4F 52 44 45 52 5F 53 41 4C 54 5F
                                         # "MFSU_ORDER_SALT_" (16 bytes, fixed)

# MFSU Standard v3
MAGIC_V3       = 4D 46 53 55 76 33       # "MFSUv3"  (6 bytes)
VERSION_V3     = 03                      # 1 byte
IV_LEN         = 16                      # bytes
SALT_LEN       = 16                      # bytes
MAC_SALT_LEN   = 16                      # bytes
MAC_LEN        = 32                      # bytes
BLOCK_SIZE     = 16                      # bytes (PKCS7 block boundary)
```

---

## 4. Governing Mathematical Model — MFSU

All cryptographic key material in `.fyx` files is derived from numerical integration of the following Stochastic Partial Differential Equation (SPDE), known as the **Unified Fractal-Stochastic Model (MFSU)**:

```
dψ/dt = -δF·(-Δ)^(β/2)ψ  +  γ|ψ|²ψ  +  σ·η(x,t)
```

Where:
- `ψ(x,t)` is a complex-valued field discretized over N spatial points.
- `(-Δ)^(β/2)` is the fractional Laplacian operator, computed spectrally: `F[(-Δ)^(α/2)f](k) = |k|^α · F[f](k)`.
- `η(x,t)` is fractional Gaussian noise with Hurst exponent H = 0.541, power spectrum `S(k) ~ |k|^(-(2H+1))`.
- `γ|ψ|²ψ` is a cubic non-linear term producing chaotic sensitivity to initial conditions.

### 4.1 Time Integration (Euler Scheme)

```
ψ_{n+1} = ψ_n + dt · [ -δF·(-Δ)^(β/2)ψ_n  +  γ|ψ_n|²ψ_n  +  σ·η ]
ψ_{n+1} = ψ_{n+1} / max(|ψ_{n+1}|_∞, 1.0)      ← time-constant normalization
```

The normalization `max(|ψ|, 1)` is applied **unconditionally** (no conditional branch). Implementations **MUST NOT** use a conditional branch of the form `if max > 1: normalize`, as this introduces a timing side-channel.

---

## 5. Cryptographic Primitives

### 5.1 Memory-Hard Key Derivation Function (MFSU-KDF)

**Inputs:** `password` (UTF-8 string), `salt` (16 bytes, uniformly random), `key_len` (integer, default 96).  
**Output:** `key_len` bytes of key material.

**Phase 1 — Scratchpad fill:**

```
h          = SHA3-512(password_utf8 || 0x00 || salt)       // 64 bytes
ψ_0        = CSPRNG(seed=h[0:32], shape=(KDF_N,), dtype=complex128)
scratchpad = array shape (KDF_M, KDF_N), dtype=complex128

for step in 0 .. KDF_M-1:
    ψ = MFSU_STEP(ψ, h, step, dt=0.001)
    scratchpad[step] = ψ
```

RAM requirement: `KDF_N × KDF_M × 16 bytes = 2048 × 256 × 16 = 8,388,608 bytes (~8 MB)`.

**Phase 2 — Non-linear mixing:**

```
ψ_mix = scratchpad[KDF_M - 1]

for step in 0 .. KDF_M-1:
    idx   = floor(|Re(ψ_mix[0])| × 10⁹) mod KDF_M    // state-dependent, unpredictable
    ψ_mix = ψ_mix + 0.001 × scratchpad[idx]
    ψ_mix = ψ_mix / max(|ψ_mix|_∞, 1.0)
```

**Phase 3 — Condensation and expansion:**

```
state_bytes = int64(Re(ψ_mix)×10¹⁰).bytes || int64(Im(ψ_mix)×10¹⁰).bytes
k_raw       = SHA3-512(state_bytes || h)               // 64 bytes

if key_len <= 64:
    return k_raw[0:key_len]

// HKDF-Expand (SHA3-256, counter mode)
result = b""; prev = b""; counter = 1
while len(result) < key_len:
    prev   = SHA3-256(prev || k_raw || uint8(counter))
    result = result || prev
    counter += 1
return result[0:key_len]
```

**Performance (reference hardware, Python 3):**

| Metric | Value |
|---|---|
| RAM per attempt | ~8 MB |
| Time per attempt | ~0.5 s |
| GPU parallelism (RTX 4090 / 24 GB) | ~3,000 threads max |

### 5.2 Keystream Generator (MFSU-KS)

**Inputs:** `derived_key` (64 bytes), `iv` (16 bytes), `length` (integer).  
**Output:** `length` bytes of pseudorandom keystream.

```
h          = SHA3-512(derived_key || iv)
n_steps    = 48 + (h[0] mod 64)                        // key-dependent: 48..112
mixer_key  = SHA3-256(derived_key[32:64] || iv)
ψ          = CSPRNG(seed=h[0:32], shape=(KS_N,), dtype=complex128)
ψ[0:64]   *= (h[0:64].as_float/255.0 + 0.5)           // amplitude modulation

raw_buf = []
for step in 0 .. n_steps-1:
    ψ = MFSU_STEP(ψ, h, step, dt=0.01)
    raw_buf += (int64(Re(ψ)×10⁴) & 0xFF)              // Layer 1: fractal entropy
    raw_buf += (int64(Im(ψ)×10⁴) & 0xFF)
    if len(raw_buf) >= length: break

// Layer 2: SHA3-256 whitener (REQUIRED for uniformity)
for i in 0 .. length step 32:
    block_key  = SHA3-256(mixer_key || uint32_BE(counter))
    output[i:] = raw_buf[i:i+32] XOR block_key
    counter   += 1

return output[0:length]
```

The whitener is **REQUIRED**. Without it, raw fractal output fails uniformity (χ² ≈ 1752, p ≈ 0). With whitener: χ² ≈ 254, p = 0.49.

### 5.3 PKCS7 Padding

Block size is `BLOCK_SIZE = 16` bytes.

- **Pad:** append `n` bytes of value `n`, where `n = BLOCK_SIZE - (len(data) mod BLOCK_SIZE)`, `1 ≤ n ≤ 16`.
- **Unpad:** read last byte as `n`. Verify `1 ≤ n ≤ 16` and that the last `n` bytes all equal `n`. If verification fails, implementations **MUST** raise an error.

### 5.4 Authentication — HMAC-SHA3-256 (Encrypt-then-MAC)

All `.fyx` files use the **Encrypt-then-MAC** construction. The MAC **MUST** be verified before any decryption is attempted. Implementations **MUST** use a constant-time comparison function (e.g., `hmac.compare_digest`) to prevent timing oracles.

---

## 6. Binary Format — FractalShield v4 (Primary Sub-Format)

### 6.1 Complete File Layout

```
Offset      Size        Field
──────────  ──────────  ──────────────────────────────────────────────────
0           6 bytes     MAGIC         4D 46 53 55 76 34  ("MFSUv4")
6           1 byte      VERSION       04
7           1 byte      LEVEL         FractalShield level: 01, 02, or 03
8           1 byte      N_LAYERS      Number of layers: 3, 4, or 5
9           16 bytes    SALT_G        Global salt (cryptographically random)
25          16 bytes    IV_ORD        IV for layer-order encryption (random)
41          2 bytes     ORD_LEN       Big-endian uint16: byte length of ORDER_ENC
43          ORD_LEN     ORDER_ENC     Encrypted, PKCS7-padded layer order array
43+OL       32 bytes    MAC           HMAC-SHA3-256(HEADER || LAYER_BLOB)
75+OL       variable    LAYER_BLOB    N layers in shuffled order (see §6.3)
```

`OL` = value of `ORD_LEN`.  
`HEADER` = bytes `[0 .. 43+OL-1]` (all bytes before MAC).

### 6.2 Field Definitions

| Field | Offset | Size | Type | Description |
|---|---|---|---|---|
| MAGIC | 0 | 6 | bytes | `4D 46 53 55 76 34` — format sentinel |
| VERSION | 6 | 1 | uint8 | `0x04` — FractalShield version |
| LEVEL | 7 | 1 | uint8 | Shield level; valid values: `1`, `2`, `3` |
| N_LAYERS | 8 | 1 | uint8 | Layer count; `3` (L1), `4` (L2), `5` (L3) |
| SALT_G | 9 | 16 | bytes | Random salt; used to derive MAC key |
| IV_ORD | 25 | 16 | bytes | Random IV for ORDER_ENC encryption |
| ORD_LEN | 41 | 2 | uint16-BE | Byte length of ORDER_ENC field |
| ORDER_ENC | 43 | ORD_LEN | bytes | PKCS7-padded order array, encrypted with MFSU-KS |
| MAC | 43+OL | 32 | bytes | HMAC-SHA3-256 over `HEADER || LAYER_BLOB` |
| LAYER_BLOB | 75+OL | variable | bytes | Concatenated encrypted layers |

### 6.3 Layer Blob Structure

LAYER_BLOB is the concatenation of N equal-length layer records written in shuffled order:

```
Each layer record (total = 32 + L bytes):
    SALT_i    16 bytes    Per-layer KDF salt (random)
    IV_i      16 bytes    Per-layer IV (random)
    CTEXT_i    L bytes    Encrypted layer payload
```

All layer records **MUST** have identical ciphertext length `L`:
```
L = (len(LAYER_BLOB) / N_LAYERS) - 32
```

### 6.4 FractalShield Levels

| Level | N_LAYERS | KDF_M sequence | User latency | Attacker cost multiplier |
|---|---|---|---|---|
| 1 — Standard | 3 | `[256, 512, 1024]` | ~0.5 s | 3.5× |
| 2 — Reinforced | 4 | `[256, 512, 1024, 2048]` | ~0.7 s | 7.5× |
| 3 — Maximum | 5 | `[256, 512, 1024, 2048, 4096]` | ~1.3 s | 15.5× |

### 6.5 Real Layer Sentinel

The real layer plaintext is prefixed with `REAL_MAGIC = 4D 46 53 55 04` (`"MFSU\x04"`, 5 bytes) before PKCS7 padding. Decoy layers contain cryptographically random bytes of the same padded length and are statistically indistinguishable from the real layer.

### 6.6 Layer Order Encryption

```
order_plain = PKCS7( bytes(shuffled_order_array) )
km_ord      = MFSU-KDF(password, ORDER_SALT_FS, key_len=96)
ks_ord      = MFSU-KS(km_ord[0:64], IV_ORD, len(order_plain))
ORDER_ENC   = order_plain XOR ks_ord
```

### 6.7 MAC Derivation

```
km_g     = MFSU-KDF(password, SALT_G, key_len=96)
mac_key  = km_g[0:32]
MAC      = HMAC-SHA3-256(mac_key, HEADER || LAYER_BLOB)
```

### 6.8 Per-Layer Encryption

```
if i == 0 (real layer):
    data = PKCS7( REAL_MAGIC || plaintext )
else (decoy layer i):
    h_d  = SHA3-256(password_bytes || uint8(i) || SALT_i)
    data = CSPRNG(seed=h_d[0:32], length=L)

km_i    = MFSU-KDF(password, SALT_i, key_len=96)
ks_i    = MFSU-KS(km_i[0:64], IV_i, len(data))
CTEXT_i = data XOR ks_i
```

### 6.9 Decryption Procedure

```
1. MUST verify file[0:6] == MAGIC_V4 and file[6] == 0x04  — REJECT otherwise
2. Parse header fields per §6.2
3. km_g = MFSU-KDF(password, SALT_G, key_len=96); mac_key = km_g[0:32]
4. Compute mac_c = HMAC-SHA3-256(mac_key, HEADER || LAYER_BLOB)
5. if NOT constant_time_equal(MAC, mac_c): REJECT with generic error
6. Decrypt ORDER_ENC per §6.6 to recover shuffled_order
7. For each layer record in LAYER_BLOB in document order:
   a. Extract SALT_i, IV_i, CTEXT_i
   b. Determine logical layer index from shuffled_order
   c. km_i = MFSU-KDF(password, SALT_i); ks_i = MFSU-KS(km_i[0:64], IV_i, len(CTEXT_i))
   d. pt = CTEXT_i XOR ks_i
   e. if pt[0:5] == REAL_MAGIC: return PKCS7_unpad(pt[5:])
8. REJECT — real layer not found
```

---

## 7. Binary Format — MFSU Standard v3 (Legacy Sub-Format)

### 7.1 Complete File Layout

```
Offset  Size        Field
──────  ──────────  ──────────────────────────────────────────────────────
0       6 bytes     MAGIC         4D 46 53 55 76 33  ("MFSUv3")
6       1 byte      VERSION       03
7       16 bytes    IV            Encryption IV (random)
23      16 bytes    SALT          KDF salt (random)
39      16 bytes    MSALT         MAC salt (random, independent of SALT)
55      32 bytes    MAC           HMAC-SHA3-256 (Encrypt-then-MAC)
87      N bytes     CTEXT         PKCS7-padded plaintext XOR keystream
```

Total fixed header size: **87 bytes**.

### 7.2 Field Definitions

| Field | Offset | Size | Type | Description |
|---|---|---|---|---|
| MAGIC | 0 | 6 | bytes | `4D 46 53 55 76 33` — format sentinel |
| VERSION | 6 | 1 | uint8 | `0x03` |
| IV | 7 | 16 | bytes | Random IV; unique per encryption operation |
| SALT | 23 | 16 | bytes | Random KDF salt; unique per encryption operation |
| MSALT | 39 | 16 | bytes | Random MAC salt; cryptographically independent of SALT |
| MAC | 55 | 32 | bytes | HMAC-SHA3-256 over `IV || SALT || MSALT || CTEXT` |
| CTEXT | 87 | N | bytes | `PKCS7(plaintext) XOR MFSU-KS(enc_key, IV, len)` |

### 7.3 Key Material Derivation

```
key_material (96B) = MFSU-KDF(password, SALT, key_len=96)
enc_key      (64B) = key_material[0:64]
mac_key_base (32B) = key_material[64:96]
mac_key      (32B) = SHA3-256(mac_key_base || MSALT)
```

### 7.4 Encryption

```
padded = PKCS7(plaintext)
ks     = MFSU-KS(enc_key, IV, len(padded))
CTEXT  = padded XOR ks
MAC    = HMAC-SHA3-256(mac_key, IV || SALT || MSALT || CTEXT)
```

### 7.5 Decryption Procedure

```
1. MUST verify len(file) >= 88 and file[0:6] == MAGIC_V3 and file[6] == 0x03
2. Parse IV, SALT, MSALT, MAC, CTEXT per §7.2
3. Derive enc_key, mac_key per §7.3
4. Compute mac_c = HMAC-SHA3-256(mac_key, IV || SALT || MSALT || CTEXT)
5. if NOT constant_time_equal(MAC, mac_c): REJECT with generic error
6. ks     = MFSU-KS(enc_key, IV, len(CTEXT))
7. padded = CTEXT XOR ks
8. return PKCS7_unpad(padded)
```

---

## 8. Security Considerations

*This section fulfills the REQUIRED security considerations for IANA media type registration per [RFC 6838] §4.6.*

### 8.1 Confidentiality

The MFSU-KDF requires approximately 8 MB of working memory and ~0.5 s per derivation attempt on contemporary hardware. This memory-hard property limits GPU-accelerated brute-force attacks to approximately 3,000 parallel threads on a 24 GB GPU, compared to millions per second for direct hash-based KDFs (e.g., PBKDF2-SHA256). The keystream output is computationally indistinguishable from uniformly random bytes when the SHA3-256 whitener layer is applied (χ² ≈ 254, p = 0.49 at 2,048 bytes).

### 8.2 Integrity and Authenticity

HMAC-SHA3-256 in Encrypt-then-MAC mode protects every byte of ciphertext and all non-secret header fields. A single tampered byte causes MAC verification to fail before any decryption is attempted. Implementations **MUST** use constant-time MAC comparison. Implementations **MUST** return a generic error on authentication failure; error messages **MUST NOT** distinguish between wrong password and corrupted file, as this would create a decryption oracle.

### 8.3 Deniability (FractalShield v4 Only)

A `.fyx` v4 file contains N equal-length, statistically identical ciphertext layers. Without the correct password:

- The layer order cannot be recovered (encrypted with MFSU-KS under a fixed salt and random IV).
- Decoy layers are indistinguishable from the real layer under ciphertext-only analysis.
- An adversary cannot determine whether a password attempt succeeded or which layer, if any, contains real plaintext.

At Level 3 (5 layers, KDF_M up to 4,096 steps), exhaustive search costs 15.5× the effort of a single decryption.

### 8.4 Timing Side-Channels

- Field normalization **MUST** unconditionally compute `ψ / max(|ψ|, 1)`. A conditional branch `if max > 1: normalize` **MUST NOT** be used, as it leaks information about the field magnitude.
- MAC comparison **MUST** use a constant-time function.
- Error responses on authentication failure **MUST** follow the same code path regardless of whether failure was caused by a wrong password or file corruption.

### 8.5 IV and Salt Uniqueness

Each encryption operation **MUST** generate fresh values for all IV and salt fields using a Cryptographically Secure Pseudo-Random Number Generator (CSPRNG). Reuse of an (IV, derived_key) pair destroys keystream confidentiality. Reuse of SALT enables KDF pre-computation.

### 8.6 Password Strength

The security of this format is directly bounded by the entropy of the user-supplied password. The memory-hard KDF provides no protection against passwords with negligible entropy. Implementations **SHOULD** reject passwords shorter than 8 characters and **SHOULD** advise users to choose passphrases with high entropy.

### 8.7 Formal Audit Status and Limitations

The MFSU cryptographic architecture has **not** been independently audited or formally verified as of the date of this specification. The fractal field functions as a proprietary entropy source; the final security guarantee rests on the established primitives SHA-3 and HMAC-SHA3-256. Users requiring formally audited cryptography **SHOULD** treat this format as experimental until an independent security audit is published. This format **MUST NOT** be used for classified, national-security, or legally mandated data protection without prior independent audit.

### 8.8 Downgrade and Version Confusion Attacks

Implementations **MUST** reject files with unknown magic bytes or unknown version bytes and **MUST NOT** silently fall back to a weaker version. If a v3 file is presented where v4 is expected, an explicit version mismatch error **MUST** be returned.

### 8.9 Applicability and Scope

This format is intended for general-purpose file encryption by individual users and applications. It is not designed for network transport, streaming decryption, or random-access seeking within encrypted content.

---

## 9. Version History

| Version | Magic (hex) | Sub-format | Key changes |
|---|---|---|---|
| v1 | `4D 46 53 55 76 31` | Prototype | No IV; KDF = direct SHA-512; no MAC |
| v2 | `4D 46 53 55 76 32` | Standard | IV 16B; MAC salt separated; PKCS7; timing branch present |
| v3 | `4D 46 53 55 76 33` | MFSU Standard | Memory-hard KDF ~8 MB; time-constant normalization; Merkle-Damgard fractal hash |
| v4 | `4D 46 53 55 76 34` | FractalShield | Multi-layer deniable encryption; encrypted layer order; per-layer KDF cost scaling |

Implementations **MUST NOT** produce v1 or v2 output. Implementations **MAY** accept v3 for backward compatibility.

---

## 10. IANA Considerations

This document requests registration of the following media type per [RFC 6838]:

```
Type name:               application
Subtype name:            vnd.fractalyx.fyx
Required parameters:     none
Optional parameters:     none
Encoding considerations: binary
Security considerations: See Section 8 of this specification
Interoperability
 considerations:         See Sections 6.9 and 7.5
Published specification: This document
                         https://github.com/Fracta-Axis/FractalyxwebLite
Applications that use
 this media type:        Fractalyx encryption application;
                         any conforming implementation of this specification
Fragment identifier
 considerations:         none
Additional information:
    Magic number(s):     4D 46 53 55 76 34  (offset 0, 6 bytes)  — primary (MFSUv4)
                         4D 46 53 55 76 33  (offset 0, 6 bytes)  — legacy  (MFSUv3)
    File extension(s):   .fyx
    Macintosh file
     type code(s):       none
Person & email address
 to contact for further
 information:            Fracta-Axis — https://github.com/Fracta-Axis
Intended usage:          LIMITED USE
Restrictions on usage:   none
Author:                  Fracta-Axis
Change controller:       Fracta-Axis
```

---

## 11. Implementation Requirements Summary

A conforming implementation:

1. **MUST** identify sub-format by magic bytes at offset 0 (§2).
2. **MUST** reject files with unknown magic bytes or unknown version bytes (§2.2).
3. **MUST** verify the MAC before any decryption attempt (§5.4, §6.9, §7.5).
4. **MUST** use constant-time MAC comparison (§8.4).
5. **MUST** generate fresh CSPRNG values for all IV and salt fields on every encryption (§8.5).
6. **MUST** apply the SHA3-256 whitener in MFSU-KS (§5.2).
7. **MUST** use unconditional normalization `ψ / max(|ψ|, 1)` — no conditional branch (§4.1, §8.4).
8. **MUST** use the exact normative constants defined in §3.
9. **MUST NOT** reveal in error messages whether failure was due to wrong password or file corruption (§8.2).
10. **MUST NOT** produce v1 or v2 format output (§9).

---

## 12. Reference Implementation

The canonical reference implementation is `app.py` in:

```
https://github.com/Fracta-Axis/Fractalyx
```

Language: Python 3.10+  
Dependencies: `streamlit`, `numpy`, `scipy`, `matplotlib`, `pandas`  
License: Apache-2.0 

---

## 13. License

This specification is released under the **MIT License**.

```
Copyright (c) 2026 Fracta-Axis

Permission is hereby granted, free of charge, to any person obtaining a copy
of this specification and associated documentation, to deal in the specification
without restriction, including without limitation the rights to use, copy,
modify, merge, publish, distribute, sublicense, and/or sell copies of the
specification, and to permit persons to whom the specification is furnished
to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the specification.
```

---

*End of FYX File Format Specification *