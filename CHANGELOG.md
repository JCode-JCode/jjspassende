# Changelog

All notable changes to **jjspassende** are documented in this file.

---

## [1.1.0] - 2026-09-14

**· Fixed** – `lfsr`/`dlfsr` used to hash once per **byte** of input and only use the first byte of each digest. Both functions now consume the entire digest as a 32‑byte keystream block per chunk, matching the fixed `jpassende` (Python) implementation and restoring cross‑language compatibility for this pattern.

**· Changed** – `pack` and `packDerivation` (`src/utils.js`) no longer build intermediate `header`/`parts`/`tag` variables; the header, AAD block, and body are appended directly to a single `pkg` accumulator, mirroring the equivalent `_pack`/`_pack_derivation` refactor in `jpassende`. Output format and byte layout are unchanged.

**· Changed** – `lfsr`/`dlfsr` write new keystream state directly into `stateA`/`stateB` instead of through temporary variables, matching the equivalent change in `jpassende`.

**· Added** – README section documenting the official Python port, **jpassende**.

---

## [1.0.0] - Initial Release

**· Added** – Initial release of jjspassende with 14 patterns across four categories: AEAD (`vail`, `phnx`, `nixl`), Stream (`strx`, `rvrs`, `lfsr`), Block (`aegs`, `cblk`, `cfbb`, `ofbb`), and Derivation (`hkdf`, `scrt`, `pbk2`, `blk3`).

**· Added** – Three selectable security layers (`STANDARD`, `FORTIFIED`, `QUANTUM`) controlling PBKDF2 iteration counts.

**· Added** – Self‑describing binary package format (magic header, version byte, pattern ID, optional AAD), wire‑compatible with the Python `jpassende` package.

**· Added** – Simple `Map`-based LRU cache for PBKDF2 key derivations.

**· Added** – `InvalidPackageError` for malformed or corrupted packages.