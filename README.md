# jjspassende

[![Node.js Version](https://img.shields.io/node/v/jjspassende)](https://nodejs.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg)](https://github.com/prettier/prettier)
[![npm version](https://img.shields.io/npm/v/jjspassende)](https://www.npmjs.com/package/jjspassende)
[![npm project](https://img.shields.io/badge/npm-jjspassende-blue)](https://www.npmjs.com/package/jjspassende)
[![Developer](https://img.shields.io/badge/developer-J%20Code-blueviolet)](#)

<br>

<img src="docs/images/jjspassende-logo.png" alt="jjspassende">

<br>

**jjspassende** is a high‑performance, multi‑pattern cryptographic library for JavaScript (Node.js) that goes far beyond standard encryption. It offers 14 unique patterns spanning AEAD, stream ciphers, block ciphers, and key derivation – all wrapped in a simple, consistent API. Every pattern uses its own distinct combination of algorithms and constructions, making your ciphertext immediately recognisable and self‑describing.

It is a faithful JavaScript port of the Python [jpassende](https://github.com/JCode-JCode/jpassende) library: packages produced by one are decodable by the other (same key), because both use the same wire format, algorithms, and key‑derivation parameters.

---

## Quick Start – Encrypt & Decrypt in Two Lines

```javascript
const { JPassende } = require('jjspassende');

const jp = new JPassende();

const result = jp.encode("Hello, World!", "vail", "my_secret");
console.log(result.encoded); // base85-encoded package (string)

const original = jp.decode(result.encoded, "vail", "my_secret");
console.log(original.decoded); // 'Hello, World!'
```

`encode()` returns a `CryptoResult` (`{ encoded, pattern, layer, needsKey, elapsed, timestamp }`) and `decode()` returns a `DecodeResult` (`{ decoded, pattern, layer, verified, elapsed }`) – mirroring the Python `CryptoResult` / `DecodeResult` dataclasses. Pass `result.encoded` (not `result` itself) into `decode()`.

---

## Main Capabilities

· **AEAD Patterns** – vail (AES‑256‑GCM), phnx (ChaCha20‑Poly1305), nixl (ChaCha20 + independent BLAKE2‑based HMAC). All three provide authenticated encryption with associated data (AAD) support.

· **Stream Patterns** – strx (BLAKE2‑based keystream), rvrs (SHA‑3 feedback mode), lfsr (dual‑state SHA‑3 / BLAKE2 generator). Byte‑by‑byte encryption without padding, ideal for streaming data.

· **Block Patterns** – aegs (AES‑CTR + HMAC), cblk (AES‑CBC + HMAC), cfbb (AES‑CFB‑128 + HMAC), ofbb (AES‑OFB + HMAC). Standard block cipher modes, each individually authenticated.

· **Derivation Patterns** – hkdf (HMAC‑based Extract‑and‑Expand), scrt (scrypt), pbk2 (PBKDF2‑SHA‑512), blk3 (Merkle‑tree commitment). Password hashing, key material generation, and data integrity commitments.

· **Security Layers** – Every pattern supports three selectable security layers: STANDARD (300k PBKDF2 iterations), FORTIFIED (600k), and QUANTUM (1.2M). You control the trade‑off between speed and brute‑force resistance.

· **Binary & Text I/O** – `options.outputRaw` returns a `Buffer` instead of a base‑encoded string. `options.inputRaw` accepts raw bytes (`Buffer`) directly, so you can encrypt binary files, images, or any byte sequence.

· **Cross‑Instance / Cross‑Language Decryption** – Packages carry all the metadata (magic, version, pattern ID, salt, nonce) needed for decryption. Any `JPassende` instance – JavaScript or Python – can decrypt, provided it has the same key.

· **Self‑Describing Packages** – The binary format includes a magic header, version byte, pattern identifier, and optional AAD. No more guessing which algorithm was used.

· **LRU Key Cache** – PBKDF2 derivations are cached (simple `Map`-based LRU) to avoid redundant work when the same password is reused.

· **Invalid Package Detection** – A dedicated `InvalidPackageError` is raised when the package structure, magic, or version is invalid.

· **Zero Plaintext Password Storage** – Cache keys are derived from a BLAKE2b hash of (password + salt + parameters), never from the password itself.

---

## Pattern Status

The patterns nixl, strx, rvrs, lfsr, aegs, cblk, cfbb, ofbb, hkdf, scrt, pbk2, and blk3 are custom constructions created exclusively for jjspassende/jpassende. They are currently experimental and under active development – their internal design may evolve as we gather feedback and perform further security analysis. The patterns vail (AES‑256‑GCM) and phnx (ChaCha20‑Poly1305) use standardized, well‑vetted algorithms and are considered stable. If you plan to use the experimental patterns in production, we strongly recommend performing your own security review and staying updated with new releases.

---

## Installation

```bash
npm install jjspassende
```

jjspassende depends on Node.js's built‑in `crypto` module and the `blakejs` package (used for BLAKE2b keyed hashing to stay bit‑compatible with the Python implementation).

---

## More Examples

Encrypting Binary Data (Buffer I/O via `inputRaw` / `outputRaw`)

```javascript
const { JPassende } = require('jjspassende');
const fs = require('fs');

const jp = new JPassende();
const image = fs.readFileSync('photo.png');

const encPkg = jp.encode(image, 'nixl', 'secret', { inputRaw: true, outputRaw: true });

const decBytes = jp.decode(encPkg.encoded, 'nixl', 'secret', { inputRaw: true, outputRaw: true });

fs.writeFileSync('photo_decrypted.png', decBytes.decoded);
```

## Choosing a Security Layer

```javascript
const { JPassende, SecurityLayer } = require('jjspassende');

const jp = new JPassende();

const result = jp.encode('Sensitive data', 'phnx', 'strong', { layer: SecurityLayer.QUANTUM });
console.log(result.layer); // 'QUANTUM'
```

## Using AAD (Additional Authenticated Data)

```javascript
const { JPassende } = require('jjspassende');

const jp = new JPassende();
const aad = Buffer.from('user-id:12345');

const result = jp.encode('Hello', 'vail', 'secret', { aad });
const decoded = jp.decode(result.encoded, 'vail', 'secret', { aad });
console.log(decoded.decoded); // 'Hello'
```

## Key Derivation

```javascript
const { JPassende, SecurityLayer } = require('jjspassende');

const jp = new JPassende();

// HKDF as a first-class pattern (produces a self-describing package, like Python's jp.encode(..., 'hkdf', ...))
const derived = jp.encode('master-seed', 'hkdf', 'secret', { length: 32 });
console.log(derived.encoded.slice(0, 30) + '...');

const verified = jp.decode(derived.encoded, 'hkdf', 'secret');
console.log(verified.decoded.slice(0, 20) + '...');

// Lower-level, standalone helpers (no packaging/versioning, just raw KDF output)
const hkdfBytes = jp.deriveKeyHKDF('master-seed', 'salt', 'info', 32);
const pbkdf2Bytes = jp.deriveKeyPBKDF2('password', 'salt', 300000, 32);
```

## List All Available Patterns

```javascript
const { JPassende } = require('jjspassende');

const jp = new JPassende();
console.log(jp.listPatterns());
// ['vail', 'phnx', 'nixl', 'strx', 'rvrs', 'lfsr', 'aegs', 'cblk', 'cfbb', 'ofbb', 'hkdf', 'scrt', 'pbk2', 'blk3']
```

---

## Error Handling

```javascript
const { JPassende, InvalidPackageError } = require('jjspassende');

const jp = new JPassende();

try {
  jp.decode('not-valid-data', 'vail', 'secret');
} catch (err) {
  if (err instanceof InvalidPackageError) {
    console.error('Package error:', err.message);
  } else {
    console.error('Other error:', err.message);
  }
}
```

---

## Python Port

jjspassende also has an official Python port called **jpassende**, offering the same patterns and API design, and it's what jjspassende itself was ported from.

· **GitHub repository:**
https://github.com/JCode-JCode/jpassende

· **PyPI page:**
jpassende is also available via PyPI.

For full usage details, installation instructions, and examples, check out the jpassende README in its own repository.

---

## Issues and Contributions

Bug reports and feature requests are welcome via GitHub Issues. Pull requests should maintain the existing code style and include tests where appropriate.

---

## Links

· **GitHub repository:**
https://github.com/JCode-JCode/jjspassende

· **npm page:**
https://www.npmjs.com/package/jjspassende

---

## License

This project is licensed under the Apache License 2.0 – see the LICENSE file for details.

---

Designed and built with love by **J Code❤️**
