// Copyright 2026 J Code
// SPDX-License-Identifier: Apache-2.0
class InvalidPackageError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidPackageError';
  }
}

module.exports = { InvalidPackageError };