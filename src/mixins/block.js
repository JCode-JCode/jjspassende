// Copyright 2026 J Code
// SPDX-License-Identifier: Apache-2.0
const crypto = require('crypto');
const { toBytes, toStr, toBuffer, secureBytes, validateNonempty, validateKey, pack, unpack, mac } = require('../utils');
const { SecurityLayer } = require('../enums');

const PATTERN_IDS = { aegs: 6, cblk: 7, cfbb: 8, ofbb: 9 };

function pad(data, blockSize = 16) {
    const padLen = blockSize - (data.length % blockSize);
    const padding = Buffer.alloc(padLen, padLen);
    return Buffer.concat([data, padding]);
}

function unpad(data) {
    if (data.length === 0) throw new Error('Invalid padding');
    const padLen = data[data.length - 1];
    if (padLen < 1 || padLen > 16) throw new Error('Invalid padding');
    for (let i = data.length - padLen; i < data.length; i++) {
        if (data[i] !== padLen) throw new Error('Invalid padding');
    }
    return data.subarray(0, data.length - padLen);
}

const BlockMixin = {
    _aegs(data, key, layer, aad, inputRaw, outputRaw, options) {
        let dataBytes = inputRaw ? toBytes(data) : toBytes(data);
        if (!inputRaw) validateNonempty(data);
        validateKey(key, 'aegs');
        const salt = secureBytes(32);
        const [encKey, macKey] = this._deriveKeys(key, salt, layer);
        const iv = secureBytes(16);

        const padded = pad(dataBytes);
        const cipher = crypto.createCipheriv('aes-256-ctr', encKey, iv);
        const ciphertext = Buffer.concat([cipher.update(padded), cipher.final()]);

        const pkg = pack(PATTERN_IDS.aegs, aad ? 0x01 : 0x00, salt, iv, ciphertext, aad, macKey);
        return outputRaw ? pkg : pkg.toString('base64');
    },

    _daegs(encoded, key, layer, aad, inputRaw, outputRaw) {
        let pkg;
        if (inputRaw) {
            pkg = toBytes(encoded);
        } else {
            if (!encoded) throw new Error('Encoded data cannot be empty.');
            const str = Buffer.isBuffer(encoded) ? encoded.toString('utf8') : encoded;
            pkg = Buffer.from(str, 'base64');
        }
        validateKey(key, 'aegs');
        const { aad: pkgAad, salt, nonce: iv, ciphertext, macVal } = unpack(pkg, PATTERN_IDS.aegs, 16, true);
        if (aad !== null && !aad.equals(pkgAad)) throw new Error('AAD mismatch');

        const [encKey, macKey] = this._deriveKeys(key, salt, layer);
        const toVerify = pkg.subarray(0, pkg.length - 32);
        if (!macVal || !crypto.timingSafeEqual(macVal, mac(macKey, toVerify))) {
            throw new Error('MAC verification failed');
        }

        const decipher = crypto.createDecipheriv('aes-256-ctr', encKey, iv);
        const padded = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        const plain = unpad(padded);
        return outputRaw ? plain : toStr(plain);
    },

    _cblk(data, key, layer, aad, inputRaw, outputRaw, options) {
        let dataBytes = inputRaw ? toBytes(data) : toBytes(data);
        if (!inputRaw) validateNonempty(data);
        validateKey(key, 'cblk');
        const salt = secureBytes(32);
        const [encKey, macKey] = this._deriveKeys(key, salt, layer);
        const iv = secureBytes(16);

        const padded = pad(dataBytes);
        const cipher = crypto.createCipheriv('aes-256-cbc', encKey, iv);
        cipher.setAutoPadding(false);
        const ciphertext = Buffer.concat([cipher.update(padded), cipher.final()]);

        const pkg = pack(PATTERN_IDS.cblk, aad ? 0x01 : 0x00, salt, iv, ciphertext, aad, macKey);
        return outputRaw ? pkg : pkg.toString('base64');
    },

    _dcblk(encoded, key, layer, aad, inputRaw, outputRaw) {
        let pkg;
        if (inputRaw) {
            pkg = toBytes(encoded);
        } else {
            if (!encoded) throw new Error('Encoded data cannot be empty.');
            const str = Buffer.isBuffer(encoded) ? encoded.toString('utf8') : encoded;
            pkg = Buffer.from(str, 'base64');
        }
        validateKey(key, 'cblk');
        const { aad: pkgAad, salt, nonce: iv, ciphertext, macVal } = unpack(pkg, PATTERN_IDS.cblk, 16, true);
        if (aad !== null && !aad.equals(pkgAad)) throw new Error('AAD mismatch');

        const [encKey, macKey] = this._deriveKeys(key, salt, layer);
        const toVerify = pkg.subarray(0, pkg.length - 32);
        if (!macVal || !crypto.timingSafeEqual(macVal, mac(macKey, toVerify))) {
            throw new Error('MAC verification failed');
        }

        const decipher = crypto.createDecipheriv('aes-256-cbc', encKey, iv);
        decipher.setAutoPadding(false);
        const padded = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        const plain = unpad(padded);
        return outputRaw ? plain : toStr(plain);
    },

    _cfbb(data, key, layer, aad, inputRaw, outputRaw, options) {
        let dataBytes = inputRaw ? toBytes(data) : toBytes(data);
        if (!inputRaw) validateNonempty(data);
        validateKey(key, 'cfbb');
        const salt = secureBytes(32);
        const [encKey, macKey] = this._deriveKeys(key, salt, layer);
        const iv = secureBytes(16);

        const cipher = crypto.createCipheriv('aes-256-cfb', encKey, iv);
        const ciphertext = Buffer.concat([cipher.update(dataBytes), cipher.final()]);

        const pkg = pack(PATTERN_IDS.cfbb, aad ? 0x01 : 0x00, salt, iv, ciphertext, aad, macKey);
        return outputRaw ? pkg : pkg.toString('base64');
    },

    _dcfbb(encoded, key, layer, aad, inputRaw, outputRaw) {
        let pkg;
        if (inputRaw) {
            pkg = toBytes(encoded);
        } else {
            if (!encoded) throw new Error('Encoded data cannot be empty.');
            const str = Buffer.isBuffer(encoded) ? encoded.toString('utf8') : encoded;
            pkg = Buffer.from(str, 'base64');
        }
        validateKey(key, 'cfbb');
        const { aad: pkgAad, salt, nonce: iv, ciphertext, macVal } = unpack(pkg, PATTERN_IDS.cfbb, 16, true);
        if (aad !== null && !aad.equals(pkgAad)) throw new Error('AAD mismatch');

        const [encKey, macKey] = this._deriveKeys(key, salt, layer);
        const toVerify = pkg.subarray(0, pkg.length - 32);
        if (!macVal || !crypto.timingSafeEqual(macVal, mac(macKey, toVerify))) {
            throw new Error('MAC verification failed');
        }

        const decipher = crypto.createDecipheriv('aes-256-cfb', encKey, iv);
        const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        return outputRaw ? plain : toStr(plain);
    },

    _ofbb(data, key, layer, aad, inputRaw, outputRaw, options) {
        let dataBytes = inputRaw ? toBytes(data) : toBytes(data);
        if (!inputRaw) validateNonempty(data);
        validateKey(key, 'ofbb');
        const salt = secureBytes(32);
        const [encKey, macKey] = this._deriveKeys(key, salt, layer);
        const iv = secureBytes(16);

        const cipher = crypto.createCipheriv('aes-256-ofb', encKey, iv);
        const ciphertext = Buffer.concat([cipher.update(dataBytes), cipher.final()]);

        const pkg = pack(PATTERN_IDS.ofbb, aad ? 0x01 : 0x00, salt, iv, ciphertext, aad, macKey);
        return outputRaw ? pkg : pkg.toString('base64');
    },

    _dofbb(encoded, key, layer, aad, inputRaw, outputRaw) {
        let pkg;
        if (inputRaw) {
            pkg = toBytes(encoded);
        } else {
            if (!encoded) throw new Error('Encoded data cannot be empty.');
            const str = Buffer.isBuffer(encoded) ? encoded.toString('utf8') : encoded;
            pkg = Buffer.from(str, 'base64');
        }
        validateKey(key, 'ofbb');
        const { aad: pkgAad, salt, nonce: iv, ciphertext, macVal } = unpack(pkg, PATTERN_IDS.ofbb, 16, true);
        if (aad !== null && !aad.equals(pkgAad)) throw new Error('AAD mismatch');

        const [encKey, macKey] = this._deriveKeys(key, salt, layer);
        const toVerify = pkg.subarray(0, pkg.length - 32);
        if (!macVal || !crypto.timingSafeEqual(macVal, mac(macKey, toVerify))) {
            throw new Error('MAC verification failed');
        }

        const decipher = crypto.createDecipheriv('aes-256-ofb', encKey, iv);
        const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        return outputRaw ? plain : toStr(plain);
    }
};

module.exports = BlockMixin;