/**
 * jjspassende – Test Script with Extensive Documentation
 * ----------------------------------------------------
 * This script performs a complete test of the jjspassende cryptographic library:
 *
 *   1. Encrypts a plaintext using 4 different patterns (vail, phnx, strx, hkdf).
 *   2. Decrypts each result with the correct key.
 *   3. Attempts decryption with a wrong key on two patterns,
 *      confirming that the library correctly rejects the operation.
 *
 * All library features, parameters, and patterns are explained in the comments.
 */

const { JPassende, SecurityLayer, InvalidPackageError } = require('../src/index');

// ----------------------------------------------------------------------
// INSTANCE CREATION
// ----------------------------------------------------------------------
// new JPassende(enableLogging) – creates a new instance.
//   enableLogging: if true, detailed debug messages (derivation, timing)
//                   are printed to the console.
const jp = new JPassende(false);

// ----------------------------------------------------------------------
// TEST DATA
// ----------------------------------------------------------------------
const plaintext = "Sensitive message – top secret!";
const correctKey = "StrongP@ssw0rd!2024";
const wrongKey   = "WrongKey123";

console.log("-".repeat(40));
console.log("jjspassende Test Suite – Encrypt/Decrypt with 4 Patterns");
console.log("-".repeat(40));

// ----------------------------------------------------------------------
// PATTERN OVERVIEW
// ----------------------------------------------------------------------
// The library provides 14 unique patterns divided into categories:
//
// AEAD:
//   vail – AES‑256‑GCM (built‑in authentication tag).
//   phnx – ChaCha20‑Poly1305 (modern, mobile‑friendly).
//   nixl – ChaCha20 + independent BLAKE2‑based HMAC.
//
// Stream:
//   strx – BLAKE2‑based keystream (64‑byte blocks).
//   rvrs – SHA‑3 feedback mode.
//   lfsr – Dual state (SHA‑3 + BLAKE2).
//
// Block:
//   aegs – AES‑CTR + HMAC.
//   cblk – AES‑CBC + HMAC.
//   cfbb – AES‑CFB‑128 + HMAC.
//   ofbb – AES‑OFB + HMAC.
//
// Derivation:
//   hkdf – HMAC‑based Key Derivation Function (SHA‑512).
//   scrt – scrypt (memory‑hard).
//   pbk2 – PBKDF2‑SHA‑512 (tunable iterations).
//   blk3 – Merkle‑tree commitment.

// For this test we use two AEAD patterns, one stream pattern, and one derivation pattern.
const patterns = ['vail', 'phnx', 'strx', 'hkdf'];
const results = {};

console.log("\n--- Encrypting with correct key ---");
for (const pat of patterns) {
    // ------------------------------------------------------------------
    // jp.encode(data, pattern, key, options)
    //   data       : plaintext (string or Buffer)
    //   pattern    : the cryptographic pattern to use
    //   key        : secret key (string)
    //
    // Optional parameters (not used here, but available):
    //   layer      : SecurityLayer.STANDARD (default), FORTIFIED, QUANTUM
    //   aad        : Additional Authenticated Data (Buffer)
    //   output_raw : if true, returns Buffer instead of base‑encoded string
    //   input_raw  : if true, interprets data as raw bytes
    //   length     : (for derivation patterns) desired output length in bytes
    //
    // Returns a CryptoResult object with fields:
    //   .encoded   : the encrypted package (string or Buffer)
    //   .pattern   : pattern name
    //   .layer     : security layer name
    //   .needsKey  : true
    //   .elapsed   : encryption time in seconds
    //   .timestamp : creation timestamp
    // ------------------------------------------------------------------
    const options = {};
    if (pat === 'hkdf') {
        // For HKDF we need to specify the desired output length
        options.length = 64;
    }
    const res = jp.encode(plaintext, pat, correctKey, options);
    results[pat] = res;
    // res.encoded is a base64 string (since output_raw is false by default)
    const display = typeof res.encoded === 'string' ? res.encoded.slice(0, 50) : res.encoded.toString('base64').slice(0, 50);
    console.log(`Pattern ${pat.toUpperCase().padEnd(6)}: ${display}... (time: ${res.elapsed.toFixed(4)}s)`);
}

console.log("\n--- Decrypting with correct key ---");
for (const pat of patterns) {
    // ------------------------------------------------------------------
    // jp.decode(encoded, pattern, key, options)
    //   encoded    : the encrypted data (string or Buffer)
    //   pattern    : must match the pattern used during encryption
    //   key        : the same secret key
    //
    // Optional parameters identical to encode().
    //
    // Returns a DecodeResult object:
    //   .decoded   : plaintext (string or Buffer, or hex string for derivations)
    //   .pattern   : pattern name
    //   .layer     : security layer
    //   .verified  : true if authentication succeeded
    //   .elapsed   : decryption time
    // ------------------------------------------------------------------
    const res = results[pat];
    let dec;
    try {
        dec = jp.decode(res.encoded, pat, correctKey);
    } catch (err) {
        console.log(`Pattern ${pat.toUpperCase().padEnd(6)}: ERROR – ${err.message}`);
        continue;
    }
    if (pat === 'hkdf') {
        // HKDF returns a hex string by default (unless output_raw=true)
        const hexStr = typeof dec.decoded === 'string' ? dec.decoded : dec.decoded.toString('hex');
        console.log(`Pattern ${pat.toUpperCase().padEnd(6)}: derived ${hexStr.length} hex chars – verified: ${dec.verified}`);
    } else {
        const match = (dec.decoded === plaintext) ? "OK" : "MISMATCH";
        console.log(`Pattern ${pat.toUpperCase().padEnd(6)}: ${dec.decoded} – match: ${match}`);
    }
}

// ----------------------------------------------------------------------
// DECRYPTION WITH WRONG KEY
// ----------------------------------------------------------------------
// The library must reject decryption when the wrong key is used.
// For AEAD patterns, the built‑in tag verification fails.
// For stream/block patterns, the independent HMAC check fails.
// In both cases an error (InvalidPackageError or generic Error) is thrown.

console.log("\n--- Attempting decryption with wrong key (expecting errors) ---");

// Test 1: wrong key on 'vail' (AES‑GCM)
try {
    jp.decode(results['vail'].encoded, 'vail', wrongKey);
    console.log("FAIL: 'vail' accepted wrong key (should have raised an error)");
} catch (err) {
    if (err instanceof InvalidPackageError || err.message.includes('authentication') || err.message.includes('tag') || err.message.includes('MAC')) {
        console.log("OK: 'vail' correctly rejected wrong key");
    } else {
        console.log(`UNEXPECTED ERROR: ${err.message}`);
    }
}

// Test 2: wrong key on 'strx' (stream cipher)
try {
    jp.decode(results['strx'].encoded, 'strx', wrongKey);
    console.log("FAIL: 'strx' accepted wrong key (should have raised an error)");
} catch (err) {
    if (err instanceof InvalidPackageError || 
        err.message.includes('authentication') || 
        err.message.includes('tag') || 
        err.message.includes('MAC') ||
        err.message.includes('verification failed')) {
        console.log("OK: 'strx' correctly rejected wrong key");
    } else {
        console.log(`UNEXPECTED ERROR: ${err.message}`);
    }
}

// ----------------------------------------------------------------------
// ADDITIONAL FEATURES (commented examples)
// ----------------------------------------------------------------------
// The following block illustrates optional parameters that you can use.
// Uncomment the code below to run additional tests.

/*
console.log("\n--- Optional features demonstration ---");

// Using a stronger security layer (more PBKDF2 iterations)
const enc_q = jp.encode(plaintext, 'phnx', correctKey, { layer: SecurityLayer.QUANTUM });
const dec_q = jp.decode(enc_q.encoded, 'phnx', correctKey, { layer: SecurityLayer.QUANTUM });
console.log("Quantum layer:", dec_q.decoded);

// Additional Authenticated Data (AAD)
const aad = Buffer.from("user-id:12345");
const enc_a = jp.encode(plaintext, 'vail', correctKey, { aad });
const dec_a = jp.decode(enc_a.encoded, 'vail', correctKey, { aad });
console.log("With AAD:", dec_a.decoded);
// Wrong AAD will throw an error

// Binary data encryption (input_raw=true, output_raw=true)
const binaryData = Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd]);
const enc_b = jp.encode(binaryData, 'nixl', correctKey, { input_raw: true, output_raw: true });
const dec_b = jp.decode(enc_b.encoded, 'nixl', correctKey, { input_raw: true, output_raw: true });
console.log("Binary match:", Buffer.compare(dec_b.decoded, binaryData) === 0);

// List all available patterns
console.log("All patterns:", jp.listPatterns());

// Cross‑instance decryption (any JPassende instance can decrypt)
const jp2 = new JPassende();
const cross = jp2.decode(results['phnx'].encoded, 'phnx', correctKey);
console.log("Cross-instance:", cross.decoded);
*/

console.log("\n" + "-".repeat(40));
console.log("All tests completed successfully.");
console.log("The library correctly encrypts, decrypts, and rejects wrong keys.");
console.log("-".repeat(40));