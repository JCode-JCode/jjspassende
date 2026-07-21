// Copyright 2026 J Code
// SPDX-License-Identifier: Apache-2.0
const crypto = require('crypto');
const blake = require('blakejs');
const { InvalidPackageError } = require('./exceptions');

function toBytes(data) {
  if (typeof data === 'string') return Buffer.from(data, 'utf8');
  if (Buffer.isBuffer(data)) return data;
  return Buffer.from(data);
}

function toStr(data) {
  if (Buffer.isBuffer(data)) return data.toString('utf8');
  return String(data);
}

function toBuffer(data) {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof Uint8Array) return Buffer.from(data);
  return Buffer.from(data);
}

function secureBytes(size = 32) {
  return crypto.randomBytes(size);
}

function validateNonempty(data, name = 'data') {
  const b = toBytes(data);
  if (b.length === 0) throw new Error(`Input ${name} cannot be empty.`);
}

function validateKey(key, pattern = '') {
  if (!key || (typeof key === 'string' && key.length === 0)) {
    throw new Error(`Key must not be empty for pattern '${pattern}'.`);
  }
}

function xorBytes(a, b) {
  if (a.length !== b.length) throw new Error(`Length mismatch in XOR: ${a.length} vs ${b.length}`);
  const result = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) result[i] = a[i] ^ b[i];
  return result;
}

function mac(key, data) {
  const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key);
  const dataBuf = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const result = blake.blake2b(dataBuf, keyBuf, 32);
  return Buffer.from(result);
}

const MAGIC = Buffer.from('jpas', 'utf8');
const VERSION = 1;

function pack(patternId, flags, salt, nonce, ciphertext, aad = null, macKey = null) {
  const header = Buffer.alloc(7);
  MAGIC.copy(header, 0);
  header.writeUInt8(VERSION, 4);
  header.writeUInt8(patternId, 5);
  header.writeUInt8(flags, 6);

  const parts = [header];
  if (aad && aad.length > 0) {
    const aadLen = Buffer.alloc(4);
    aadLen.writeUInt32BE(aad.length, 0);
    parts.push(aadLen);
    parts.push(Buffer.isBuffer(aad) ? aad : Buffer.from(aad));
  }
  parts.push(Buffer.isBuffer(salt) ? salt : Buffer.from(salt));
  if (nonce && nonce.length > 0) {
    parts.push(Buffer.isBuffer(nonce) ? nonce : Buffer.from(nonce));
  }
  parts.push(Buffer.isBuffer(ciphertext) ? ciphertext : Buffer.from(ciphertext));

  let pkg = Buffer.concat(parts);
  if (macKey) {
    const tag = mac(macKey, pkg);
    pkg = Buffer.concat([pkg, tag]);
  }
  return pkg;
}

function unpack(pkg, patternId, expectedNonceSize = 0, hasMac = true) {
  if (!pkg || pkg.length === 0) throw new InvalidPackageError('Invalid package – empty');
  if (pkg.length < 7) throw new InvalidPackageError('Invalid package – too short for header');
  if (!pkg.subarray(0, 4).equals(MAGIC)) throw new InvalidPackageError('Invalid magic bytes');
  if (pkg[4] !== VERSION) throw new InvalidPackageError(`Unsupported version: ${pkg[4]}`);
  if (pkg[5] !== patternId) throw new InvalidPackageError('Pattern mismatch');

  const flags = pkg[6];
  let pos = 7;
  let aad = null;

  if (flags & 0x01) {
    if (pkg.length < pos + 4) throw new InvalidPackageError('Invalid package – missing AAD length');
    const aadLen = pkg.readUInt32BE(pos);
    pos += 4;
    if (pkg.length < pos + aadLen) throw new InvalidPackageError('Invalid package – truncated AAD');
    aad = pkg.subarray(pos, pos + aadLen);
    pos += aadLen;
  }

  if (pkg.length < pos + 32) throw new InvalidPackageError('Invalid package – missing salt');
  const salt = pkg.subarray(pos, pos + 32);
  pos += 32;

  let nonce = Buffer.alloc(0);
  if (expectedNonceSize > 0) {
    if (pkg.length < pos + expectedNonceSize) {
      throw new InvalidPackageError(`Invalid package – truncated nonce (expected ${expectedNonceSize} bytes)`);
    }
    nonce = Buffer.from(pkg.subarray(pos, pos + expectedNonceSize));
    pos += expectedNonceSize;
  }

  const macSize = hasMac ? 32 : 0;
  const ciphertextLen = pkg.length - pos - macSize;
  if (ciphertextLen < 0) throw new InvalidPackageError('Invalid package – body too short');
  const ciphertext = pkg.subarray(pos, pos + ciphertextLen);
  pos += ciphertextLen;

  let macVal = null;
  if (hasMac) {
    if (pkg.length < pos + 32) throw new InvalidPackageError('Invalid package – missing MAC');
    macVal = pkg.subarray(pos, pos + 32);
    pos += 32;
  }

  if (pos !== pkg.length) throw new InvalidPackageError('Invalid package – trailing data after payload');
  return { aad, salt, nonce, ciphertext, macVal };
}

function packDerivation(patternId, flags, salt, derivedData, verification, aad = null) {
  const header = Buffer.alloc(7);
  MAGIC.copy(header, 0);
  header.writeUInt8(VERSION, 4);
  header.writeUInt8(patternId, 5);
  header.writeUInt8(flags, 6);

  const parts = [header];
  if (aad && aad.length > 0) {
    const aadLen = Buffer.alloc(4);
    aadLen.writeUInt32BE(aad.length, 0);
    parts.push(aadLen);
    parts.push(Buffer.isBuffer(aad) ? aad : Buffer.from(aad));
  }
  parts.push(Buffer.isBuffer(salt) ? salt : Buffer.from(salt));
  parts.push(Buffer.isBuffer(derivedData) ? derivedData : Buffer.from(derivedData));
  parts.push(Buffer.isBuffer(verification) ? verification : Buffer.from(verification));
  return Buffer.concat(parts);
}

function unpackDerivation(pkg, patternId) {
  if (!pkg || pkg.length === 0) throw new InvalidPackageError('Invalid derivation package – empty');
  if (pkg.length < 7) throw new InvalidPackageError('Invalid package – too short for header');
  if (!pkg.subarray(0, 4).equals(MAGIC)) throw new InvalidPackageError('Invalid magic bytes');
  if (pkg[4] !== VERSION) throw new InvalidPackageError(`Unsupported version: ${pkg[4]}`);
  if (pkg[5] !== patternId) throw new InvalidPackageError('Pattern mismatch');

  const flags = pkg[6];
  let pos = 7;
  let aad = null;

  if (flags & 0x01) {
    if (pkg.length < pos + 4) throw new InvalidPackageError('Invalid package – missing AAD length');
    const aadLen = pkg.readUInt32BE(pos);
    pos += 4;
    if (pkg.length < pos + aadLen) throw new InvalidPackageError('Invalid package – truncated AAD');
    aad = pkg.subarray(pos, pos + aadLen);
    pos += aadLen;
  }

  if (pkg.length < pos + 32) throw new InvalidPackageError('Invalid derivation package – missing salt');
  const salt = pkg.subarray(pos, pos + 32);
  pos += 32;

  const derivedLen = pkg.length - pos - 16;
  if (derivedLen < 0) throw new InvalidPackageError('Invalid derivation package – missing verification');
  const derived = pkg.subarray(pos, pos + derivedLen);
  pos += derivedLen;
  const verification = pkg.subarray(pos, pos + 16);
  pos += 16;

  if (pos !== pkg.length) throw new InvalidPackageError('Invalid derivation package – trailing data');
  return { aad, salt, derived, verification };
}

module.exports = {
  toBytes,
  toStr,
  toBuffer,
  secureBytes,
  validateNonempty,
  validateKey,
  xorBytes,
  mac,
  MAGIC,
  VERSION,
  pack,
  unpack,
  packDerivation,
  unpackDerivation,
  InvalidPackageError
};