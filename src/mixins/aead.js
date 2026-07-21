// Copyright 2026 J Code
// SPDX-License-Identifier: Apache-2.0
const crypto = require('crypto');
const b85 = require('../b85');
const blake = require('blakejs');
const { toBytes, toStr, toBuffer, secureBytes, validateNonempty, validateKey, toBuffer: _toBuffer, pack, unpack, mac } = require('../utils');
const { SecurityLayer } = require('../enums');

const PATTERN_IDS = { vail: 0, phnx: 1, nixl: 2 };

function chacha20Xor(key, nonce, data, counter = 0) {
    const counterBuf = Buffer.alloc(4);
    counterBuf.writeUInt32LE(counter >>> 0, 0);
    const iv = Buffer.concat([counterBuf, Buffer.isBuffer(nonce) ? nonce : Buffer.from(nonce)]);
    const cipher = crypto.createCipheriv('chacha20', key, iv);
    return Buffer.concat([cipher.update(Buffer.isBuffer(data) ? data : Buffer.from(data)), cipher.final()]);
}

const AeadMixin = {
    _vail(data, key, layer, aad, inputRaw, outputRaw, options) {
        let dataBytes = inputRaw ? toBytes(data) : toBytes(data);
        if (!inputRaw) validateNonempty(data);
        validateKey(key, 'vail');
        const salt = secureBytes(32);
        const keyBytes = this._deriveKey(key, salt, 32, layer);
        const nonce = secureBytes(12);

        const cipher = crypto.createCipheriv('aes-256-gcm', keyBytes, nonce, { authTagLength: 16 });
        if (aad) cipher.setAAD(Buffer.isBuffer(aad) ? aad : Buffer.from(aad));
        const ct = Buffer.concat([cipher.update(dataBytes), cipher.final()]);
        const tag = cipher.getAuthTag();
        const ctTag = Buffer.concat([ct, tag]);

        const pkg = pack(PATTERN_IDS.vail, aad ? 0x01 : 0x00, salt, nonce, ctTag, aad);
        return outputRaw ? pkg : b85.encode(pkg);
    },

    _dvail(encoded, key, layer, aad, inputRaw, outputRaw) {
        let pkg;
        if (inputRaw) {
            pkg = toBytes(encoded);
        } else {
            if (!encoded) throw new Error('Encoded data cannot be empty.');
            const rawStr = Buffer.isBuffer(encoded) ? encoded.toString('utf8') : encoded;
            const str = rawStr.trim();
            pkg = toBuffer(b85.decode(str));
        }
        if (!pkg || pkg.length === 0) throw new Error('Decoded package is empty');
        validateKey(key, 'vail');
        const { aad: pkgAad, salt, nonce, ciphertext, macVal } = unpack(pkg, PATTERN_IDS.vail, 12, false);
        if (aad !== null && !aad.equals(pkgAad)) throw new Error('AAD mismatch');

        const keyBytes = this._deriveKey(key, salt, 32, layer);
        const decipher = crypto.createDecipheriv('aes-256-gcm', keyBytes, nonce, { authTagLength: 16 });
        if (pkgAad) decipher.setAAD(Buffer.isBuffer(pkgAad) ? pkgAad : Buffer.from(pkgAad));
        decipher.setAuthTag(ciphertext.subarray(ciphertext.length - 16));
        try {
            const plain = Buffer.concat([decipher.update(ciphertext.subarray(0, ciphertext.length - 16)), decipher.final()]);
            return outputRaw ? plain : toStr(plain);
        } catch (err) {
            throw new Error('GCM authentication failed');
        }
    },

    _phnx(data, key, layer, aad, inputRaw, outputRaw, options) {
        let dataBytes = inputRaw ? toBytes(data) : toBytes(data);
        if (!inputRaw) validateNonempty(data);
        validateKey(key, 'phnx');
        const salt = secureBytes(32);
        const keyBytes = this._deriveKey(key, salt, 32, layer);
        const nonce = secureBytes(12);

        const cipher = crypto.createCipheriv('chacha20-poly1305', keyBytes, nonce, { authTagLength: 16 });
        if (aad) cipher.setAAD(Buffer.isBuffer(aad) ? aad : Buffer.from(aad));
        const ct = Buffer.concat([cipher.update(dataBytes), cipher.final()]);
        const tag = cipher.getAuthTag();
        const ctTag = Buffer.concat([ct, tag]);

        const pkg = pack(PATTERN_IDS.phnx, aad ? 0x01 : 0x00, salt, nonce, ctTag, aad);
        return outputRaw ? pkg : b85.encode(pkg);
    },

    _dphnx(encoded, key, layer, aad, inputRaw, outputRaw) {
        let pkg;
        if (inputRaw) {
            pkg = toBytes(encoded);
        } else {
            if (!encoded) throw new Error('Encoded data cannot be empty.');
            const rawStr = Buffer.isBuffer(encoded) ? encoded.toString('utf8') : encoded;
            const str = rawStr.trim();
            pkg = toBuffer(b85.decode(str));
        }
        if (!pkg || pkg.length === 0) throw new Error('Decoded package is empty');
        validateKey(key, 'phnx');
        const { aad: pkgAad, salt, nonce, ciphertext, macVal } = unpack(pkg, PATTERN_IDS.phnx, 12, false);
        if (aad !== null && !aad.equals(pkgAad)) throw new Error('AAD mismatch');

        const keyBytes = this._deriveKey(key, salt, 32, layer);
        const decipher = crypto.createDecipheriv('chacha20-poly1305', keyBytes, nonce, { authTagLength: 16 });
        if (pkgAad) decipher.setAAD(Buffer.isBuffer(pkgAad) ? pkgAad : Buffer.from(pkgAad));
        decipher.setAuthTag(ciphertext.subarray(ciphertext.length - 16));
        try {
            const plain = Buffer.concat([decipher.update(ciphertext.subarray(0, ciphertext.length - 16)), decipher.final()]);
            return outputRaw ? plain : toStr(plain);
        } catch (err) {
            throw new Error('Poly1305 authentication failed');
        }
    },

    _nixl(data, key, layer, aad, inputRaw, outputRaw, options) {
        let dataBytes = inputRaw ? toBytes(data) : toBytes(data);
        if (!inputRaw) validateNonempty(data);
        validateKey(key, 'nixl');
        const salt = secureBytes(32);
        const [encKey, macKey] = this._deriveKeys(key, salt, layer);
        const nonce = secureBytes(12);

        const ciphertext = chacha20Xor(encKey, nonce, dataBytes, 0);

        const pkg = pack(PATTERN_IDS.nixl, aad ? 0x01 : 0x00, salt, nonce, ciphertext, aad, macKey);
        return outputRaw ? pkg : b85.encode(pkg);
    },

    _dnixl(encoded, key, layer, aad, inputRaw, outputRaw) {
        let pkg;
        if (inputRaw) {
            pkg = toBytes(encoded);
        } else {
            if (!encoded) throw new Error('Encoded data cannot be empty.');
            const rawStr = Buffer.isBuffer(encoded) ? encoded.toString('utf8') : encoded;
            const str = rawStr.trim();
            pkg = toBuffer(b85.decode(str));
        }
        if (!pkg || pkg.length === 0) throw new Error('Decoded package is empty');
        validateKey(key, 'nixl');

        const { aad: pkgAad, salt, nonce, ciphertext, macVal } = unpack(pkg, PATTERN_IDS.nixl, 12, true);
        if (aad !== null && !aad.equals(pkgAad)) throw new Error('AAD mismatch');

        const [encKey, macKey] = this._deriveKeys(key, salt, layer);
        const toVerify = pkg.subarray(0, pkg.length - 32);
        if (!macVal || !crypto.timingSafeEqual(macVal, mac(macKey, toVerify))) {
            throw new Error('MAC verification failed');
        }

        try {
            const plain = chacha20Xor(encKey, nonce, ciphertext, 0);
            return outputRaw ? plain : toStr(plain);
        } catch (err) {
            throw new Error(`ChaCha20 decryption failed: ${err.message}`);
        }
    }
};

module.exports = AeadMixin;
