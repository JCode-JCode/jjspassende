// Copyright 2026 J Code
// SPDX-License-Identifier: Apache-2.0
const crypto = require('crypto');
const b85 = require('../b85');
const blake = require('blakejs');
const { toBytes, toStr, toBuffer, secureBytes, validateNonempty, validateKey, packDerivation, unpackDerivation } = require('../utils');
const { SecurityLayer } = require('../enums');

const PATTERN_IDS = { hkdf: 10, scrt: 11, pbk2: 12, blk3: 13 };

function hkdfExtract(ikm, salt) {
  return crypto.createHmac('sha512', salt).update(ikm).digest();
}

function hkdfExpand(prk, info, length) {
  const hashLen = 64;
  const okm = Buffer.alloc(length);
  let t = Buffer.alloc(0);
  let pos = 0;
  let i = 0;
  while (pos < length) {
    i++;
    const hmac = crypto.createHmac('sha512', prk);
    const input = Buffer.concat([t, info, Buffer.from([i])]);
    hmac.update(input);
    t = hmac.digest();
    const bytesToCopy = Math.min(t.length, length - pos);
    t.copy(okm, pos, 0, bytesToCopy);
    pos += bytesToCopy;
  }
  return okm;
}

const DerivationMixin = {
  _hkdf(data, key, layer, aad, inputRaw, outputRaw, options) {
    const length = (options && options.length) || 64;
    const maxLen = 255 * 64;
    if (length > maxLen) {
      throw new Error(`Requested HKDF output length (${length}) exceeds maximum allowed (${maxLen})`);
    }

    let dataBytes = inputRaw ? toBytes(data) : toBytes(data);
    if (!inputRaw) validateNonempty(data);
    validateKey(key, 'hkdf');

    const salt = secureBytes(32);
    const keyBytes = this._deriveKey(key, salt, 32, layer);
    const prk = hkdfExtract(dataBytes, salt);
    const derived = hkdfExpand(prk, Buffer.from('jpassende:hkdf:v1'), length);
    
    const verification = blake.blake2b(Buffer.concat([derived, keyBytes]), null, 16);
    
    const pkg = packDerivation(PATTERN_IDS.hkdf, aad ? 0x01 : 0x00, salt, derived, Buffer.from(verification), aad);
    return outputRaw ? pkg : b85.encode(pkg);
  },

  _dhkdf(encoded, key, layer, aad, inputRaw, outputRaw) {
    let pkg;
    if (inputRaw) {
      pkg = toBytes(encoded);
    } else {
      if (!encoded) throw new Error('Encoded data cannot be empty.');
      const str = Buffer.isBuffer(encoded) ? encoded.toString('utf8') : encoded;
      pkg = toBuffer(b85.decode(str));
    }
    validateKey(key, 'hkdf');
    const { aad: pkgAad, salt, derived, verification } = unpackDerivation(pkg, PATTERN_IDS.hkdf);
    if (aad !== null && !aad.equals(pkgAad)) throw new Error('AAD mismatch');

    const keyBytes = this._deriveKey(key, salt, 32, layer);
    const expected = blake.blake2b(Buffer.concat([derived, keyBytes]), null, 16);
    if (!crypto.timingSafeEqual(verification, Buffer.from(expected))) {
      throw new Error('Verification failed');
    }
    return outputRaw ? derived : derived.toString('hex');
  },

  _scrt(data, key, layer, aad, inputRaw, outputRaw, options) {
    let dataBytes = inputRaw ? toBytes(data) : toBytes(data);
    if (!inputRaw) validateNonempty(data);
    validateKey(key, 'scrt');
    const salt = secureBytes(32);
    const keyBytes = this._deriveKey(key, salt, 32, layer);
    const N = layer === SecurityLayer.STANDARD ? 16384 : (layer === SecurityLayer.FORTIFIED ? 131072 : 1048576);
    const derived = crypto.scryptSync(dataBytes, salt, 64, { N, r: 8, p: 1 });
    const verification = crypto.createHmac('sha3-512', keyBytes).update(derived).digest().subarray(0, 16);
    const pkg = packDerivation(PATTERN_IDS.scrt, aad ? 0x01 : 0x00, salt, derived, verification, aad);
    return outputRaw ? pkg : b85.encode(pkg);
  },

  _dscrt(encoded, key, layer, aad, inputRaw, outputRaw) {
    let pkg;
    if (inputRaw) {
      pkg = toBytes(encoded);
    } else {
      if (!encoded) throw new Error('Encoded data cannot be empty.');
      const str = Buffer.isBuffer(encoded) ? encoded.toString('utf8') : encoded;
      pkg = toBuffer(b85.decode(str));
    }
    validateKey(key, 'scrt');
    const { aad: pkgAad, salt, derived, verification } = unpackDerivation(pkg, PATTERN_IDS.scrt);
    if (aad !== null && !aad.equals(pkgAad)) throw new Error('AAD mismatch');

    const keyBytes = this._deriveKey(key, salt, 32, layer);
    const expected = crypto.createHmac('sha3-512', keyBytes).update(derived).digest().subarray(0, 16);
    if (!crypto.timingSafeEqual(verification, expected)) throw new Error('Verification failed');
    return outputRaw ? derived : derived.toString('hex');
  },

  _pbk2(data, key, layer, aad, inputRaw, outputRaw, options) {
    let dataBytes = inputRaw ? toBytes(data) : toBytes(data);
    if (!inputRaw) validateNonempty(data);
    validateKey(key, 'pbk2');
    const salt = secureBytes(32);
    const keyBytes = this._deriveKey(key, salt, 32, layer);
    const iterations = layer === SecurityLayer.STANDARD ? 300000 : (layer === SecurityLayer.FORTIFIED ? 600000 : 1200000);
    const derived = crypto.pbkdf2Sync(dataBytes, salt, iterations, 64, 'sha512');
    const verification = crypto.createHmac('blake2s256', keyBytes).update(derived).digest().subarray(0, 16);
    const pkg = packDerivation(PATTERN_IDS.pbk2, aad ? 0x01 : 0x00, salt, derived, verification, aad);
    return outputRaw ? pkg : b85.encode(pkg);
  },

  _dpbk2(encoded, key, layer, aad, inputRaw, outputRaw) {
    let pkg;
    if (inputRaw) {
      pkg = toBytes(encoded);
    } else {
      if (!encoded) throw new Error('Encoded data cannot be empty.');
      const str = Buffer.isBuffer(encoded) ? encoded.toString('utf8') : encoded;
      pkg = toBuffer(b85.decode(str));
    }
    validateKey(key, 'pbk2');
    const { aad: pkgAad, salt, derived, verification } = unpackDerivation(pkg, PATTERN_IDS.pbk2);
    if (aad !== null && !aad.equals(pkgAad)) throw new Error('AAD mismatch');

    const keyBytes = this._deriveKey(key, salt, 32, layer);
    const expected = crypto.createHmac('blake2s256', keyBytes).update(derived).digest().subarray(0, 16);
    if (!crypto.timingSafeEqual(verification, expected)) throw new Error('Verification failed');
    return outputRaw ? derived : derived.toString('hex');
  },

  _blk3(data, key, layer, aad, inputRaw, outputRaw, options) {
    let dataBytes = inputRaw ? toBytes(data) : toBytes(data);
    if (!inputRaw) validateNonempty(data);
    validateKey(key, 'blk3');
    const salt = secureBytes(32);
    const keyBytes = this._deriveKey(key, salt, 32, layer);

    const blockSize = 64;
    let tree = [];
    for (let i = 0; i < dataBytes.length; i += blockSize) {
      const block = dataBytes.subarray(i, Math.min(i + blockSize, dataBytes.length));
      const h = blake.blake2b(Buffer.concat([block, keyBytes]), null, 32);
      tree.push(Buffer.from(h));
    }
    while (tree.length > 1) {
      const newLevel = [];
      for (let i = 0; i < tree.length; i += 2) {
        const combined = Buffer.concat([tree[i], i + 1 < tree.length ? tree[i + 1] : tree[i]]);
        newLevel.push(Buffer.from(blake.blake2b(Buffer.concat([combined, keyBytes]), null, 32)));
      }
      tree = newLevel;
    }
    const root = tree.length > 0 ? tree[0] : Buffer.from(blake.blake2b(keyBytes, null, 32));
    const verification = crypto.createHmac('sha3-256', keyBytes).update(Buffer.concat([root, salt])).digest().subarray(0, 16);
    const pkg = packDerivation(PATTERN_IDS.blk3, aad ? 0x01 : 0x00, salt, root, verification, aad);
    return outputRaw ? pkg : b85.encode(pkg);
  },

  _dblk3(encoded, key, layer, aad, inputRaw, outputRaw) {
    let pkg;
    if (inputRaw) {
      pkg = toBytes(encoded);
    } else {
      if (!encoded) throw new Error('Encoded data cannot be empty.');
      const str = Buffer.isBuffer(encoded) ? encoded.toString('utf8') : encoded;
      pkg = toBuffer(b85.decode(str));
    }
    validateKey(key, 'blk3');
    const { aad: pkgAad, salt, derived: root, verification } = unpackDerivation(pkg, PATTERN_IDS.blk3);
    if (aad !== null && !aad.equals(pkgAad)) throw new Error('AAD mismatch');

    const keyBytes = this._deriveKey(key, salt, 32, layer);
    const expected = crypto.createHmac('sha3-256', keyBytes).update(Buffer.concat([root, salt])).digest().subarray(0, 16);
    if (!crypto.timingSafeEqual(verification, expected)) throw new Error('Verification failed');
    return outputRaw ? root : root.toString('hex');
  }
};

module.exports = DerivationMixin;