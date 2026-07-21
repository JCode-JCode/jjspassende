// Copyright 2026 J Code
// SPDX-License-Identifier: Apache-2.0
class CryptoResult {
  constructor({ encoded, pattern, layer, needsKey, elapsed = 0, timestamp = Date.now() / 1000 }) {
    this.encoded = encoded;
    this.pattern = pattern;
    this.layer = layer;
    this.needsKey = needsKey;
    this.timestamp = timestamp;
    this.elapsed = elapsed;
  }
}

class DecodeResult {
  constructor({ decoded, pattern, layer, verified, elapsed = 0 }) {
    this.decoded = decoded;
    this.pattern = pattern;
    this.layer = layer;
    this.verified = verified;
    this.elapsed = elapsed;
  }
}

module.exports = { CryptoResult, DecodeResult };