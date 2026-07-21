// Copyright 2026 J Code
// SPDX-License-Identifier: Apache-2.0
const crypto = require('crypto');
const AeadMixin = require('./mixins/aead');
const StreamMixin = require('./mixins/stream');
const BlockMixin = require('./mixins/block');
const DerivationMixin = require('./mixins/derivation');
const { SecurityLayer, PatternCategory } = require('./enums');
const { InvalidPackageError } = require('./exceptions');
const { CryptoResult, DecodeResult } = require('./datatypes');

class JPassende {
  static PATTERNS = {
    vail: { category: PatternCategory.AEAD },
    phnx: { category: PatternCategory.AEAD },
    nixl: { category: PatternCategory.AEAD },
    strx: { category: PatternCategory.STREAM },
    rvrs: { category: PatternCategory.STREAM },
    lfsr: { category: PatternCategory.STREAM },
    aegs: { category: PatternCategory.BLOCK },
    cblk: { category: PatternCategory.BLOCK },
    cfbb: { category: PatternCategory.BLOCK },
    ofbb: { category: PatternCategory.BLOCK },
    hkdf: { category: PatternCategory.DERIVATION },
    scrt: { category: PatternCategory.DERIVATION },
    pbk2: { category: PatternCategory.DERIVATION },
    blk3: { category: PatternCategory.DERIVATION }
  };

  static PATTERN_IDS = {
    vail: 0, phnx: 1, nixl: 2, strx: 3,
    rvrs: 4, lfsr: 5, aegs: 6, cblk: 7,
    cfbb: 8, ofbb: 9, hkdf: 10, scrt: 11,
    pbk2: 12, blk3: 13
  };

  constructor(enableLogging = false) {
    this._saltSize = 32;
    this._macSize = 32;
    this._defaultNonce = 12;
    this._deriveCache = new Map();
    this._maxCacheEntries = 128;
    this._logging = enableLogging;

    Object.assign(this, AeadMixin);
    Object.assign(this, StreamMixin);
    Object.assign(this, BlockMixin);
    Object.assign(this, DerivationMixin);

    this._encryptors = {
      vail: this._vail.bind(this),
      phnx: this._phnx.bind(this),
      nixl: this._nixl.bind(this),
      strx: this._strx.bind(this),
      rvrs: this._rvrs.bind(this),
      lfsr: this._lfsr.bind(this),
      aegs: this._aegs.bind(this),
      cblk: this._cblk.bind(this),
      cfbb: this._cfbb.bind(this),
      ofbb: this._ofbb.bind(this),
      hkdf: this._hkdf.bind(this),
      scrt: this._scrt.bind(this),
      pbk2: this._pbk2.bind(this),
      blk3: this._blk3.bind(this)
    };
    this._decryptors = {
      vail: this._dvail.bind(this),
      phnx: this._dphnx.bind(this),
      nixl: this._dnixl.bind(this),
      strx: this._dstrx.bind(this),
      rvrs: this._drvrs.bind(this),
      lfsr: this._dlfsr.bind(this),
      aegs: this._daegs.bind(this),
      cblk: this._dcblk.bind(this),
      cfbb: this._dcfbb.bind(this),
      ofbb: this._dofbb.bind(this),
      hkdf: this._dhkdf.bind(this),
      scrt: this._dscrt.bind(this),
      pbk2: this._dpbk2.bind(this),
      blk3: this._dblk3.bind(this)
    };
  }

  _deriveKey(password, salt, length = 32, layer = SecurityLayer.STANDARD) {
    let layerNum = layer;
    if (typeof layerNum !== 'number' || layerNum < 1 || layerNum > 3) {
      layerNum = SecurityLayer.STANDARD;
    }

    const lengthBuf = Buffer.alloc(4);
    lengthBuf.writeUInt32BE(length, 0);
    const layerBuf = Buffer.alloc(4);
    layerBuf.writeUInt32BE(layerNum, 0);
    const hashInput = Buffer.concat([
      Buffer.from(password, 'utf8'),
      salt,
      lengthBuf,
      layerBuf
    ]);
    const cacheKey = crypto.createHash('blake2b512').update(hashInput).digest().subarray(0, 16).toString('hex');

    if (this._deriveCache.has(cacheKey)) {
      const entry = this._deriveCache.get(cacheKey);
      this._deriveCache.delete(cacheKey);
      this._deriveCache.set(cacheKey, entry);
      if (this._logging) console.debug('[jpassende] Cache hit for key derivation');
      return entry;
    }

    const iterations = {
      [SecurityLayer.STANDARD]: 300000,
      [SecurityLayer.FORTIFIED]: 600000,
      [SecurityLayer.QUANTUM]: 1200000
    };
    const iterCount = iterations[layerNum] || 300000;
    if (this._logging) console.debug(`[jpassende] Deriving key with PBKDF2 (iterations=${iterCount})`);
    const derived = crypto.pbkdf2Sync(password, salt, iterCount, length, 'sha512');

    if (this._deriveCache.size >= this._maxCacheEntries) {
      const firstKey = this._deriveCache.keys().next().value;
      this._deriveCache.delete(firstKey);
    }
    this._deriveCache.set(cacheKey, derived);
    return derived;
  }

  _deriveKeys(key, salt, layer) {
    const baseKey = this._deriveKey(key, salt, 32, layer);
    let material = crypto.hkdfSync('sha256', baseKey, salt, Buffer.from('jpassende:keys:v2'), 64);
    if (!Buffer.isBuffer(material)) material = Buffer.from(material);
    return [material.slice(0, 32), material.slice(32, 64)];
  }

  _nonceSizeFor(pattern) {
    if (['vail', 'phnx', 'nixl'].includes(pattern)) return 12;
    if (['aegs', 'cblk', 'cfbb', 'ofbb', 'strx', 'rvrs', 'lfsr'].includes(pattern)) return 16;
    return 0;
  }

  encode(data, pattern, key, options = {}) {
    if (!JPassende.PATTERNS[pattern]) {
      throw new Error(`Unknown pattern: ${pattern}`);
    }
    const {
      layer = SecurityLayer.STANDARD,
      aad = null,
      outputRaw = false,
      inputRaw = false,
      length = 64,
      ...rest
    } = options;

    const encryptor = this._encryptors[pattern];
    const start = Date.now() / 1000;
    const encoded = encryptor(data, key, layer, aad, inputRaw, outputRaw, { length, ...rest });
    const elapsed = (Date.now() / 1000) - start;
    return new CryptoResult({
      encoded,
      pattern,
      layer: this._layerName(layer),
      needsKey: !!key,
      elapsed
    });
  }

  decode(encoded, pattern, key, options = {}) {
    if (!JPassende.PATTERNS[pattern]) {
      throw new Error(`Unknown pattern: ${pattern}`);
    }
    const {
      layer = SecurityLayer.STANDARD,
      aad = null,
      outputRaw = false,
      inputRaw = false,
      ...rest
    } = options;

    const decryptor = this._decryptors[pattern];
    const start = Date.now() / 1000;
    const decoded = decryptor(encoded, key, layer, aad, inputRaw, outputRaw);
    const elapsed = (Date.now() / 1000) - start;
    return new DecodeResult({
      decoded,
      pattern,
      layer: this._layerName(layer),
      verified: true,
      elapsed
    });
  }

  deriveKeyHKDF(ikm, salt, info, length = 32) {
    const saltBuf = Buffer.isBuffer(salt) ? salt : Buffer.from(salt, 'utf8');
    const infoBuf = Buffer.isBuffer(info) ? info : Buffer.from(info, 'utf8');
    const ikmBuf = Buffer.isBuffer(ikm) ? ikm : Buffer.from(ikm, 'utf8');
    return crypto.hkdfSync('sha512', ikmBuf, saltBuf, infoBuf, length);
  }

  deriveKeyPBKDF2(password, salt, iterations = 300000, length = 32) {
    const saltBuf = Buffer.isBuffer(salt) ? salt : Buffer.from(salt, 'utf8');
    return crypto.pbkdf2Sync(password, saltBuf, iterations, length, 'sha512');
  }

  _layerName(layer) {
    const names = {
      [SecurityLayer.STANDARD]: 'STANDARD',
      [SecurityLayer.FORTIFIED]: 'FORTIFIED',
      [SecurityLayer.QUANTUM]: 'QUANTUM'
    };
    return names[layer] || 'STANDARD';
  }

  listPatterns() {
    return Object.keys(JPassende.PATTERNS);
  }
}

module.exports = { JPassende, SecurityLayer, PatternCategory, InvalidPackageError, CryptoResult, DecodeResult };