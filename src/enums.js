// Copyright 2026 J Code
// SPDX-License-Identifier: Apache-2.0
const SecurityLayer = Object.freeze({
  STANDARD: 1,
  FORTIFIED: 2,
  QUANTUM: 3
});

const PatternCategory = Object.freeze({
  AEAD: 'AEAD',
  STREAM: 'STREAM',
  BLOCK: 'BLOCK',
  DERIVATION: 'DERIVATION'
});

module.exports = { SecurityLayer, PatternCategory };