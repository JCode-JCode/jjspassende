// Copyright 2026 J Code
// SPDX-License-Identifier: Apache-2.0
const B85_ALPHABET =
  '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~';

const B85_DECODE_MAP = (() => {
  const map = new Array(256).fill(-1);
  for (let i = 0; i < B85_ALPHABET.length; i++) {
    map[B85_ALPHABET.charCodeAt(i)] = i;
  }
  return map;
})();

function encode(buf) {
  if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf);
  const padding = (4 - (buf.length % 4)) % 4;
  const padded = padding > 0 ? Buffer.concat([buf, Buffer.alloc(padding)]) : buf;

  let out = '';
  for (let i = 0; i < padded.length; i += 4) {
    let word = padded.readUInt32BE(i);
    const digits = new Array(5);
    for (let d = 4; d >= 0; d--) {
      digits[d] = word % 85;
      word = Math.floor(word / 85);
    }
    for (let d = 0; d < 5; d++) out += B85_ALPHABET[digits[d]];
  }

  if (padding > 0) {
    out = out.slice(0, out.length - padding);
  }
  return out;
}

function decode(data) {
  const str = Buffer.isBuffer(data) ? data.toString('latin1') : data;
  const padding = (5 - (str.length % 5)) % 5;
  const padded = padding > 0 ? str + '~'.repeat(padding) : str;

  const words = [];
  for (let i = 0; i < padded.length; i += 5) {
    let acc = 0;
    for (let j = 0; j < 5; j++) {
      const code = padded.charCodeAt(i + j);
      const val = code < 256 ? B85_DECODE_MAP[code] : -1;
      if (val === -1) {
        throw new Error(`bad base85 character at position ${i + j}`);
      }
      acc = acc * 85 + val;
    }
    if (acc > 0xffffffff) {
      throw new Error(`base85 overflow in hunk starting at byte ${i}`);
    }
    const b = Buffer.alloc(4);
    b.writeUInt32BE(acc >>> 0, 0);
    words.push(b);
  }

  let result = Buffer.concat(words);
  if (padding > 0) {
    result = result.subarray(0, result.length - padding);
  }
  return result;
}

module.exports = { encode, decode };
