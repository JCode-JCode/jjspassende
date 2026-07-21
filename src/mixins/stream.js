// Copyright 2026 J Code
// SPDX-License-Identifier: Apache-2.0
const crypto = require('crypto');
const b85 = require('../b85');
const blake = require('blakejs');
const { toBytes, toStr, toBuffer, secureBytes, validateNonempty, validateKey, xorBytes, pack, unpack, mac } = require('../utils');
const { SecurityLayer } = require('../enums');

const PATTERN_IDS = { strx: 3, rvrs: 4, lfsr: 5 };

function blake2bKeystream(key, nonce, counter, length) {
    const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key);
    const nonceBuf = Buffer.isBuffer(nonce) ? nonce : Buffer.from(nonce);
    const counterBuf = Buffer.alloc(16);
    counterBuf.writeBigUInt64LE(BigInt(counter), 0);
    const input = Buffer.concat([nonceBuf, counterBuf]);
    const full = blake.blake2b(input, keyBuf, 64);
    return Buffer.from(full).subarray(0, length);
}

const StreamMixin = {
    _strx(data, key, layer, aad, inputRaw, outputRaw, options) {
        let dataBytes = inputRaw ? toBytes(data) : toBytes(data);
        if (!inputRaw) validateNonempty(data);
        validateKey(key, 'strx');
        const salt = secureBytes(32);
        const [encKey, macKey] = this._deriveKeys(key, salt, layer);
        const nonce = secureBytes(16);

        const result = Buffer.alloc(dataBytes.length);
        let counter = 0;
        for (let i = 0; i < dataBytes.length; i += 64) {
            const chunk = dataBytes.subarray(i, Math.min(i + 64, dataBytes.length));
            const keystream = blake2bKeystream(encKey, nonce, counter, chunk.length);
            const xored = xorBytes(chunk, keystream);
            xored.copy(result, i);
            counter++;
        }

        const pkg = pack(PATTERN_IDS.strx, aad ? 0x01 : 0x00, salt, nonce, result, aad, macKey);
        return outputRaw ? pkg : b85.encode(pkg);
    },

    _dstrx(encoded, key, layer, aad, inputRaw, outputRaw) {
        let pkg;
        if (inputRaw) {
            pkg = toBytes(encoded);
        } else {
            if (!encoded) throw new Error('Encoded data cannot be empty.');
            const str = Buffer.isBuffer(encoded) ? encoded.toString('utf8') : encoded;
            pkg = toBuffer(b85.decode(str));
        }
        validateKey(key, 'strx');
        const { aad: pkgAad, salt, nonce, ciphertext, macVal } = unpack(pkg, PATTERN_IDS.strx, 16, true);
        if (aad !== null && !aad.equals(pkgAad)) throw new Error('AAD mismatch');

        const [encKey, macKey] = this._deriveKeys(key, salt, layer);
        const toVerify = pkg.subarray(0, pkg.length - 32);
        if (macVal && !crypto.timingSafeEqual(macVal, mac(macKey, toVerify))) {
            throw new Error('MAC verification failed');
        }

        const result = Buffer.alloc(ciphertext.length);
        let counter = 0;
        for (let i = 0; i < ciphertext.length; i += 64) {
            const chunk = ciphertext.subarray(i, Math.min(i + 64, ciphertext.length));
            const keystream = blake2bKeystream(encKey, nonce, counter, chunk.length);
            const xored = xorBytes(chunk, keystream);
            xored.copy(result, i);
            counter++;
        }
        return outputRaw ? result : toStr(result);
    },

    _rvrs(data, key, layer, aad, inputRaw, outputRaw, options) {
        let dataBytes = inputRaw ? toBytes(data) : toBytes(data);
        if (!inputRaw) validateNonempty(data);
        validateKey(key, 'rvrs');
        const salt = secureBytes(32);
        const [encKey, macKey] = this._deriveKeys(key, salt, layer);
        const nonce = secureBytes(16);

        const blockSize = 32;
        const result = Buffer.alloc(dataBytes.length);
        let prev = nonce;
        for (let i = 0; i < dataBytes.length; i += blockSize) {
            const chunk = dataBytes.subarray(i, Math.min(i + blockSize, dataBytes.length));
            const keystream = crypto.createHash('sha3-256').update(Buffer.concat([encKey, prev])).digest().subarray(0, chunk.length);
            const cipherChunk = xorBytes(chunk, keystream);
            cipherChunk.copy(result, i);
            prev = cipherChunk;
        }

        const pkg = pack(PATTERN_IDS.rvrs, aad ? 0x01 : 0x00, salt, nonce, result, aad, macKey);
        return outputRaw ? pkg : b85.encode(pkg);
    },

    _drvrs(encoded, key, layer, aad, inputRaw, outputRaw) {
        let pkg;
        if (inputRaw) {
            pkg = toBytes(encoded);
        } else {
            if (!encoded) throw new Error('Encoded data cannot be empty.');
            const str = Buffer.isBuffer(encoded) ? encoded.toString('utf8') : encoded;
            pkg = toBuffer(b85.decode(str));
        }
        validateKey(key, 'rvrs');
        const { aad: pkgAad, salt, nonce, ciphertext, macVal } = unpack(pkg, PATTERN_IDS.rvrs, 16, true);
        if (aad !== null && !aad.equals(pkgAad)) throw new Error('AAD mismatch');

        const [encKey, macKey] = this._deriveKeys(key, salt, layer);
        const toVerify = pkg.subarray(0, pkg.length - 32);
        if (macVal && !crypto.timingSafeEqual(macVal, mac(macKey, toVerify))) {
            throw new Error('MAC verification failed');
        }

        const blockSize = 32;
        const result = Buffer.alloc(ciphertext.length);
        let prev = nonce;
        for (let i = 0; i < ciphertext.length; i += blockSize) {
            const chunk = ciphertext.subarray(i, Math.min(i + blockSize, ciphertext.length));
            const keystream = crypto.createHash('sha3-256').update(Buffer.concat([encKey, prev])).digest().subarray(0, chunk.length);
            const plainChunk = xorBytes(chunk, keystream);
            plainChunk.copy(result, i);
            prev = chunk;
        }
        return outputRaw ? result : toStr(result);
    },

    _lfsr(data, key, layer, aad, inputRaw, outputRaw, options) {
        let dataBytes = inputRaw ? toBytes(data) : toBytes(data);
        if (!inputRaw) validateNonempty(data);
        validateKey(key, 'lfsr');
        const salt = secureBytes(32);
        const [encKey, macKey] = this._deriveKeys(key, salt, layer);
        const nonce = secureBytes(16);

        let stateA = crypto.createHash('sha3-256').update(Buffer.concat([encKey, nonce])).digest();
        let stateB = blake.blake2b(Buffer.concat([encKey, nonce]), null, 32);
        const result = Buffer.alloc(dataBytes.length);
        for (let i = 0; i < dataBytes.length; i++) {
            const keyByte = stateA[0] ^ stateB[0];
            result[i] = dataBytes[i] ^ keyByte;
            stateA = crypto.createHash('sha3-256').update(stateA).digest();
            stateB = blake.blake2b(stateB, null, 32);
        }

        const pkg = pack(PATTERN_IDS.lfsr, aad ? 0x01 : 0x00, salt, nonce, result, aad, macKey);
        return outputRaw ? pkg : b85.encode(pkg);
    },

    _dlfsr(encoded, key, layer, aad, inputRaw, outputRaw) {
        let pkg;
        if (inputRaw) {
            pkg = toBytes(encoded);
        } else {
            if (!encoded) throw new Error('Encoded data cannot be empty.');
            const str = Buffer.isBuffer(encoded) ? encoded.toString('utf8') : encoded;
            pkg = toBuffer(b85.decode(str));
        }
        validateKey(key, 'lfsr');
        const { aad: pkgAad, salt, nonce, ciphertext, macVal } = unpack(pkg, PATTERN_IDS.lfsr, 16, true);
        if (aad !== null && !aad.equals(pkgAad)) throw new Error('AAD mismatch');

        const [encKey, macKey] = this._deriveKeys(key, salt, layer);
        const toVerify = pkg.subarray(0, pkg.length - 32);
        if (macVal && !crypto.timingSafeEqual(macVal, mac(macKey, toVerify))) {
            throw new Error('MAC verification failed');
        }

        let stateA = crypto.createHash('sha3-256').update(Buffer.concat([encKey, nonce])).digest();
        let stateB = blake.blake2b(Buffer.concat([encKey, nonce]), null, 32);
        const result = Buffer.alloc(ciphertext.length);
        for (let i = 0; i < ciphertext.length; i++) {
            const keyByte = stateA[0] ^ stateB[0];
            result[i] = ciphertext[i] ^ keyByte;
            stateA = crypto.createHash('sha3-256').update(stateA).digest();
            stateB = blake.blake2b(stateB, null, 32);
        }
        return outputRaw ? result : toStr(result);
    }
};

module.exports = StreamMixin;