import { createRequire } from 'module';const require = createRequire(import.meta.url);
import {
  __async,
  __asyncGenerator,
  __await,
  __export,
  __forAwait,
  __objRest,
  __spreadProps,
  __spreadValues
} from "./chunk-5EPNIMTF.js";

// node_modules/jose/dist/node/esm/runtime/base64url.js
import { Buffer } from "buffer";

// node_modules/jose/dist/node/esm/runtime/digest.js
import { createHash } from "crypto";
var digest = (algorithm, data) => createHash(algorithm).update(data).digest();
var digest_default = digest;

// node_modules/jose/dist/node/esm/lib/buffer_utils.js
var encoder = new TextEncoder();
var decoder = new TextDecoder();
var MAX_INT32 = 2 ** 32;
function concat(...buffers) {
  const size = buffers.reduce((acc, {
    length
  }) => acc + length, 0);
  const buf = new Uint8Array(size);
  let i = 0;
  for (const buffer of buffers) {
    buf.set(buffer, i);
    i += buffer.length;
  }
  return buf;
}
function p2s(alg, p2sInput) {
  return concat(encoder.encode(alg), new Uint8Array([0]), p2sInput);
}
function writeUInt32BE(buf, value, offset) {
  if (value < 0 || value >= MAX_INT32) {
    throw new RangeError(`value must be >= 0 and <= ${MAX_INT32 - 1}. Received ${value}`);
  }
  buf.set([value >>> 24, value >>> 16, value >>> 8, value & 255], offset);
}
function uint64be(value) {
  const high = Math.floor(value / MAX_INT32);
  const low = value % MAX_INT32;
  const buf = new Uint8Array(8);
  writeUInt32BE(buf, high, 0);
  writeUInt32BE(buf, low, 4);
  return buf;
}
function uint32be(value) {
  const buf = new Uint8Array(4);
  writeUInt32BE(buf, value);
  return buf;
}
function lengthAndInput(input) {
  return concat(uint32be(input.length), input);
}
function concatKdf(secret, bits, value) {
  return __async(this, null, function* () {
    const iterations = Math.ceil((bits >> 3) / 32);
    const res = new Uint8Array(iterations * 32);
    for (let iter = 0; iter < iterations; iter++) {
      const buf = new Uint8Array(4 + secret.length + value.length);
      buf.set(uint32be(iter + 1));
      buf.set(secret, 4);
      buf.set(value, 4 + secret.length);
      res.set(yield digest_default("sha256", buf), iter * 32);
    }
    return res.slice(0, bits >> 3);
  });
}

// node_modules/jose/dist/node/esm/runtime/base64url.js
function normalize(input) {
  let encoded = input;
  if (encoded instanceof Uint8Array) {
    encoded = decoder.decode(encoded);
  }
  return encoded;
}
var encode = (input) => Buffer.from(input).toString("base64url");
var decode = (input) => new Uint8Array(Buffer.from(normalize(input), "base64"));

// node_modules/jose/dist/node/esm/runtime/decrypt.js
import { createDecipheriv, KeyObject } from "crypto";

// node_modules/jose/dist/node/esm/util/errors.js
var errors_exports = {};
__export(errors_exports, {
  JOSEAlgNotAllowed: () => JOSEAlgNotAllowed,
  JOSEError: () => JOSEError,
  JOSENotSupported: () => JOSENotSupported,
  JWEDecryptionFailed: () => JWEDecryptionFailed,
  JWEInvalid: () => JWEInvalid,
  JWKInvalid: () => JWKInvalid,
  JWKSInvalid: () => JWKSInvalid,
  JWKSMultipleMatchingKeys: () => JWKSMultipleMatchingKeys,
  JWKSNoMatchingKey: () => JWKSNoMatchingKey,
  JWKSTimeout: () => JWKSTimeout,
  JWSInvalid: () => JWSInvalid,
  JWSSignatureVerificationFailed: () => JWSSignatureVerificationFailed,
  JWTClaimValidationFailed: () => JWTClaimValidationFailed,
  JWTExpired: () => JWTExpired,
  JWTInvalid: () => JWTInvalid
});
var JOSEError = class extends Error {
  static get code() {
    return "ERR_JOSE_GENERIC";
  }
  code = "ERR_JOSE_GENERIC";
  constructor(message2) {
    super(message2);
    this.name = this.constructor.name;
    Error.captureStackTrace?.(this, this.constructor);
  }
};
var JWTClaimValidationFailed = class extends JOSEError {
  static get code() {
    return "ERR_JWT_CLAIM_VALIDATION_FAILED";
  }
  code = "ERR_JWT_CLAIM_VALIDATION_FAILED";
  claim;
  reason;
  payload;
  constructor(message2, payload, claim = "unspecified", reason = "unspecified") {
    super(message2);
    this.claim = claim;
    this.reason = reason;
    this.payload = payload;
  }
};
var JWTExpired = class extends JOSEError {
  static get code() {
    return "ERR_JWT_EXPIRED";
  }
  code = "ERR_JWT_EXPIRED";
  claim;
  reason;
  payload;
  constructor(message2, payload, claim = "unspecified", reason = "unspecified") {
    super(message2);
    this.claim = claim;
    this.reason = reason;
    this.payload = payload;
  }
};
var JOSEAlgNotAllowed = class extends JOSEError {
  static get code() {
    return "ERR_JOSE_ALG_NOT_ALLOWED";
  }
  code = "ERR_JOSE_ALG_NOT_ALLOWED";
};
var JOSENotSupported = class extends JOSEError {
  static get code() {
    return "ERR_JOSE_NOT_SUPPORTED";
  }
  code = "ERR_JOSE_NOT_SUPPORTED";
};
var JWEDecryptionFailed = class extends JOSEError {
  static get code() {
    return "ERR_JWE_DECRYPTION_FAILED";
  }
  code = "ERR_JWE_DECRYPTION_FAILED";
  message = "decryption operation failed";
};
var JWEInvalid = class extends JOSEError {
  static get code() {
    return "ERR_JWE_INVALID";
  }
  code = "ERR_JWE_INVALID";
};
var JWSInvalid = class extends JOSEError {
  static get code() {
    return "ERR_JWS_INVALID";
  }
  code = "ERR_JWS_INVALID";
};
var JWTInvalid = class extends JOSEError {
  static get code() {
    return "ERR_JWT_INVALID";
  }
  code = "ERR_JWT_INVALID";
};
var JWKInvalid = class extends JOSEError {
  static get code() {
    return "ERR_JWK_INVALID";
  }
  code = "ERR_JWK_INVALID";
};
var JWKSInvalid = class extends JOSEError {
  static get code() {
    return "ERR_JWKS_INVALID";
  }
  code = "ERR_JWKS_INVALID";
};
var JWKSNoMatchingKey = class extends JOSEError {
  static get code() {
    return "ERR_JWKS_NO_MATCHING_KEY";
  }
  code = "ERR_JWKS_NO_MATCHING_KEY";
  message = "no applicable key found in the JSON Web Key Set";
};
var JWKSMultipleMatchingKeys = class extends JOSEError {
  [Symbol.asyncIterator];
  static get code() {
    return "ERR_JWKS_MULTIPLE_MATCHING_KEYS";
  }
  code = "ERR_JWKS_MULTIPLE_MATCHING_KEYS";
  message = "multiple matching keys found in the JSON Web Key Set";
};
var JWKSTimeout = class extends JOSEError {
  static get code() {
    return "ERR_JWKS_TIMEOUT";
  }
  code = "ERR_JWKS_TIMEOUT";
  message = "request timed out";
};
var JWSSignatureVerificationFailed = class extends JOSEError {
  static get code() {
    return "ERR_JWS_SIGNATURE_VERIFICATION_FAILED";
  }
  code = "ERR_JWS_SIGNATURE_VERIFICATION_FAILED";
  message = "signature verification failed";
};

// node_modules/jose/dist/node/esm/runtime/random.js
import { randomFillSync } from "crypto";

// node_modules/jose/dist/node/esm/lib/iv.js
function bitLength(alg) {
  switch (alg) {
    case "A128GCM":
    case "A128GCMKW":
    case "A192GCM":
    case "A192GCMKW":
    case "A256GCM":
    case "A256GCMKW":
      return 96;
    case "A128CBC-HS256":
    case "A192CBC-HS384":
    case "A256CBC-HS512":
      return 128;
    default:
      throw new JOSENotSupported(`Unsupported JWE Algorithm: ${alg}`);
  }
}
var iv_default = (alg) => randomFillSync(new Uint8Array(bitLength(alg) >> 3));

// node_modules/jose/dist/node/esm/lib/check_iv_length.js
var checkIvLength = (enc, iv) => {
  if (iv.length << 3 !== bitLength(enc)) {
    throw new JWEInvalid("Invalid Initialization Vector length");
  }
};
var check_iv_length_default = checkIvLength;

// node_modules/jose/dist/node/esm/runtime/is_key_object.js
import * as util from "util";
var is_key_object_default = (obj) => util.types.isKeyObject(obj);

// node_modules/jose/dist/node/esm/runtime/check_cek_length.js
var checkCekLength = (enc, cek) => {
  let expected;
  switch (enc) {
    case "A128CBC-HS256":
    case "A192CBC-HS384":
    case "A256CBC-HS512":
      expected = parseInt(enc.slice(-3), 10);
      break;
    case "A128GCM":
    case "A192GCM":
    case "A256GCM":
      expected = parseInt(enc.slice(1, 4), 10);
      break;
    default:
      throw new JOSENotSupported(`Content Encryption Algorithm ${enc} is not supported either by JOSE or your javascript runtime`);
  }
  if (cek instanceof Uint8Array) {
    const actual = cek.byteLength << 3;
    if (actual !== expected) {
      throw new JWEInvalid(`Invalid Content Encryption Key length. Expected ${expected} bits, got ${actual} bits`);
    }
    return;
  }
  if (is_key_object_default(cek) && cek.type === "secret") {
    const actual = cek.symmetricKeySize << 3;
    if (actual !== expected) {
      throw new JWEInvalid(`Invalid Content Encryption Key length. Expected ${expected} bits, got ${actual} bits`);
    }
    return;
  }
  throw new TypeError("Invalid Content Encryption Key type");
};
var check_cek_length_default = checkCekLength;

// node_modules/jose/dist/node/esm/runtime/timing_safe_equal.js
import { timingSafeEqual as impl } from "crypto";
var timingSafeEqual = impl;
var timing_safe_equal_default = timingSafeEqual;

// node_modules/jose/dist/node/esm/runtime/cbc_tag.js
import { createHmac } from "crypto";
function cbcTag(aad, iv, ciphertext, macSize, macKey, keySize) {
  const macData = concat(aad, iv, ciphertext, uint64be(aad.length << 3));
  const hmac = createHmac(`sha${macSize}`, macKey);
  hmac.update(macData);
  return hmac.digest().slice(0, keySize >> 3);
}

// node_modules/jose/dist/node/esm/runtime/webcrypto.js
import * as crypto from "crypto";
import * as util2 from "util";
var webcrypto2 = crypto.webcrypto;
var webcrypto_default = webcrypto2;
var isCryptoKey = (key) => util2.types.isCryptoKey(key);

// node_modules/jose/dist/node/esm/lib/crypto_key.js
function unusable(name, prop = "algorithm.name") {
  return new TypeError(`CryptoKey does not support this operation, its ${prop} must be ${name}`);
}
function isAlgorithm(algorithm, name) {
  return algorithm.name === name;
}
function getHashLength(hash) {
  return parseInt(hash.name.slice(4), 10);
}
function getNamedCurve(alg) {
  switch (alg) {
    case "ES256":
      return "P-256";
    case "ES384":
      return "P-384";
    case "ES512":
      return "P-521";
    default:
      throw new Error("unreachable");
  }
}
function checkUsage(key, usages) {
  if (usages.length && !usages.some((expected) => key.usages.includes(expected))) {
    let msg = "CryptoKey does not support this operation, its usages must include ";
    if (usages.length > 2) {
      const last = usages.pop();
      msg += `one of ${usages.join(", ")}, or ${last}.`;
    } else if (usages.length === 2) {
      msg += `one of ${usages[0]} or ${usages[1]}.`;
    } else {
      msg += `${usages[0]}.`;
    }
    throw new TypeError(msg);
  }
}
function checkSigCryptoKey(key, alg, ...usages) {
  switch (alg) {
    case "HS256":
    case "HS384":
    case "HS512": {
      if (!isAlgorithm(key.algorithm, "HMAC")) throw unusable("HMAC");
      const expected = parseInt(alg.slice(2), 10);
      const actual = getHashLength(key.algorithm.hash);
      if (actual !== expected) throw unusable(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    case "RS256":
    case "RS384":
    case "RS512": {
      if (!isAlgorithm(key.algorithm, "RSASSA-PKCS1-v1_5")) throw unusable("RSASSA-PKCS1-v1_5");
      const expected = parseInt(alg.slice(2), 10);
      const actual = getHashLength(key.algorithm.hash);
      if (actual !== expected) throw unusable(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    case "PS256":
    case "PS384":
    case "PS512": {
      if (!isAlgorithm(key.algorithm, "RSA-PSS")) throw unusable("RSA-PSS");
      const expected = parseInt(alg.slice(2), 10);
      const actual = getHashLength(key.algorithm.hash);
      if (actual !== expected) throw unusable(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    case "EdDSA": {
      if (key.algorithm.name !== "Ed25519" && key.algorithm.name !== "Ed448") {
        throw unusable("Ed25519 or Ed448");
      }
      break;
    }
    case "ES256":
    case "ES384":
    case "ES512": {
      if (!isAlgorithm(key.algorithm, "ECDSA")) throw unusable("ECDSA");
      const expected = getNamedCurve(alg);
      const actual = key.algorithm.namedCurve;
      if (actual !== expected) throw unusable(expected, "algorithm.namedCurve");
      break;
    }
    default:
      throw new TypeError("CryptoKey does not support this operation");
  }
  checkUsage(key, usages);
}
function checkEncCryptoKey(key, alg, ...usages) {
  switch (alg) {
    case "A128GCM":
    case "A192GCM":
    case "A256GCM": {
      if (!isAlgorithm(key.algorithm, "AES-GCM")) throw unusable("AES-GCM");
      const expected = parseInt(alg.slice(1, 4), 10);
      const actual = key.algorithm.length;
      if (actual !== expected) throw unusable(expected, "algorithm.length");
      break;
    }
    case "A128KW":
    case "A192KW":
    case "A256KW": {
      if (!isAlgorithm(key.algorithm, "AES-KW")) throw unusable("AES-KW");
      const expected = parseInt(alg.slice(1, 4), 10);
      const actual = key.algorithm.length;
      if (actual !== expected) throw unusable(expected, "algorithm.length");
      break;
    }
    case "ECDH": {
      switch (key.algorithm.name) {
        case "ECDH":
        case "X25519":
        case "X448":
          break;
        default:
          throw unusable("ECDH, X25519, or X448");
      }
      break;
    }
    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW":
      if (!isAlgorithm(key.algorithm, "PBKDF2")) throw unusable("PBKDF2");
      break;
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      if (!isAlgorithm(key.algorithm, "RSA-OAEP")) throw unusable("RSA-OAEP");
      const expected = parseInt(alg.slice(9), 10) || 1;
      const actual = getHashLength(key.algorithm.hash);
      if (actual !== expected) throw unusable(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    default:
      throw new TypeError("CryptoKey does not support this operation");
  }
  checkUsage(key, usages);
}

// node_modules/jose/dist/node/esm/lib/invalid_key_input.js
function message(msg, actual, ...types4) {
  if (types4.length > 2) {
    const last = types4.pop();
    msg += `one of type ${types4.join(", ")}, or ${last}.`;
  } else if (types4.length === 2) {
    msg += `one of type ${types4[0]} or ${types4[1]}.`;
  } else {
    msg += `of type ${types4[0]}.`;
  }
  if (actual == null) {
    msg += ` Received ${actual}`;
  } else if (typeof actual === "function" && actual.name) {
    msg += ` Received function ${actual.name}`;
  } else if (typeof actual === "object" && actual != null) {
    if (actual.constructor?.name) {
      msg += ` Received an instance of ${actual.constructor.name}`;
    }
  }
  return msg;
}
var invalid_key_input_default = (actual, ...types4) => {
  return message("Key must be ", actual, ...types4);
};
function withAlg(alg, actual, ...types4) {
  return message(`Key for the ${alg} algorithm must be `, actual, ...types4);
}

// node_modules/jose/dist/node/esm/runtime/ciphers.js
import { getCiphers } from "crypto";
var ciphers;
var ciphers_default = (algorithm) => {
  ciphers ||= new Set(getCiphers());
  return ciphers.has(algorithm);
};

// node_modules/jose/dist/node/esm/runtime/is_key_like.js
var is_key_like_default = (key) => is_key_object_default(key) || isCryptoKey(key);
var types3 = ["KeyObject"];
if (globalThis.CryptoKey || webcrypto_default?.CryptoKey) {
  types3.push("CryptoKey");
}

// node_modules/jose/dist/node/esm/runtime/decrypt.js
function cbcDecrypt(enc, cek, ciphertext, iv, tag2, aad) {
  const keySize = parseInt(enc.slice(1, 4), 10);
  if (is_key_object_default(cek)) {
    cek = cek.export();
  }
  const encKey = cek.subarray(keySize >> 3);
  const macKey = cek.subarray(0, keySize >> 3);
  const macSize = parseInt(enc.slice(-3), 10);
  const algorithm = `aes-${keySize}-cbc`;
  if (!ciphers_default(algorithm)) {
    throw new JOSENotSupported(`alg ${enc} is not supported by your javascript runtime`);
  }
  const expectedTag = cbcTag(aad, iv, ciphertext, macSize, macKey, keySize);
  let macCheckPassed;
  try {
    macCheckPassed = timing_safe_equal_default(tag2, expectedTag);
  } catch {
  }
  if (!macCheckPassed) {
    throw new JWEDecryptionFailed();
  }
  let plaintext;
  try {
    const decipher = createDecipheriv(algorithm, encKey, iv);
    plaintext = concat(decipher.update(ciphertext), decipher.final());
  } catch {
  }
  if (!plaintext) {
    throw new JWEDecryptionFailed();
  }
  return plaintext;
}
function gcmDecrypt(enc, cek, ciphertext, iv, tag2, aad) {
  const keySize = parseInt(enc.slice(1, 4), 10);
  const algorithm = `aes-${keySize}-gcm`;
  if (!ciphers_default(algorithm)) {
    throw new JOSENotSupported(`alg ${enc} is not supported by your javascript runtime`);
  }
  try {
    const decipher = createDecipheriv(algorithm, cek, iv, {
      authTagLength: 16
    });
    decipher.setAuthTag(tag2);
    if (aad.byteLength) {
      decipher.setAAD(aad, {
        plaintextLength: ciphertext.length
      });
    }
    const plaintext = decipher.update(ciphertext);
    decipher.final();
    return plaintext;
  } catch {
    throw new JWEDecryptionFailed();
  }
}
var decrypt = (enc, cek, ciphertext, iv, tag2, aad) => {
  let key;
  if (isCryptoKey(cek)) {
    checkEncCryptoKey(cek, enc, "decrypt");
    key = KeyObject.from(cek);
  } else if (cek instanceof Uint8Array || is_key_object_default(cek)) {
    key = cek;
  } else {
    throw new TypeError(invalid_key_input_default(cek, ...types3, "Uint8Array"));
  }
  if (!iv) {
    throw new JWEInvalid("JWE Initialization Vector missing");
  }
  if (!tag2) {
    throw new JWEInvalid("JWE Authentication Tag missing");
  }
  check_cek_length_default(enc, key);
  check_iv_length_default(enc, iv);
  switch (enc) {
    case "A128CBC-HS256":
    case "A192CBC-HS384":
    case "A256CBC-HS512":
      return cbcDecrypt(enc, key, ciphertext, iv, tag2, aad);
    case "A128GCM":
    case "A192GCM":
    case "A256GCM":
      return gcmDecrypt(enc, key, ciphertext, iv, tag2, aad);
    default:
      throw new JOSENotSupported("Unsupported JWE Content Encryption Algorithm");
  }
};
var decrypt_default = decrypt;

// node_modules/jose/dist/node/esm/lib/is_disjoint.js
var isDisjoint = (...headers) => {
  const sources = headers.filter(Boolean);
  if (sources.length === 0 || sources.length === 1) {
    return true;
  }
  let acc;
  for (const header of sources) {
    const parameters = Object.keys(header);
    if (!acc || acc.size === 0) {
      acc = new Set(parameters);
      continue;
    }
    for (const parameter of parameters) {
      if (acc.has(parameter)) {
        return false;
      }
      acc.add(parameter);
    }
  }
  return true;
};
var is_disjoint_default = isDisjoint;

// node_modules/jose/dist/node/esm/lib/is_object.js
function isObjectLike(value) {
  return typeof value === "object" && value !== null;
}
function isObject(input) {
  if (!isObjectLike(input) || Object.prototype.toString.call(input) !== "[object Object]") {
    return false;
  }
  if (Object.getPrototypeOf(input) === null) {
    return true;
  }
  let proto = input;
  while (Object.getPrototypeOf(proto) !== null) {
    proto = Object.getPrototypeOf(proto);
  }
  return Object.getPrototypeOf(input) === proto;
}

// node_modules/jose/dist/node/esm/runtime/aeskw.js
import { Buffer as Buffer2 } from "buffer";
import { KeyObject as KeyObject2, createDecipheriv as createDecipheriv2, createCipheriv, createSecretKey } from "crypto";
function checkKeySize(key, alg) {
  if (key.symmetricKeySize << 3 !== parseInt(alg.slice(1, 4), 10)) {
    throw new TypeError(`Invalid key size for alg: ${alg}`);
  }
}
function ensureKeyObject(key, alg, usage) {
  if (is_key_object_default(key)) {
    return key;
  }
  if (key instanceof Uint8Array) {
    return createSecretKey(key);
  }
  if (isCryptoKey(key)) {
    checkEncCryptoKey(key, alg, usage);
    return KeyObject2.from(key);
  }
  throw new TypeError(invalid_key_input_default(key, ...types3, "Uint8Array"));
}
var wrap = (alg, key, cek) => {
  const size = parseInt(alg.slice(1, 4), 10);
  const algorithm = `aes${size}-wrap`;
  if (!ciphers_default(algorithm)) {
    throw new JOSENotSupported(`alg ${alg} is not supported either by JOSE or your javascript runtime`);
  }
  const keyObject = ensureKeyObject(key, alg, "wrapKey");
  checkKeySize(keyObject, alg);
  const cipher = createCipheriv(algorithm, keyObject, Buffer2.alloc(8, 166));
  return concat(cipher.update(cek), cipher.final());
};
var unwrap = (alg, key, encryptedKey) => {
  const size = parseInt(alg.slice(1, 4), 10);
  const algorithm = `aes${size}-wrap`;
  if (!ciphers_default(algorithm)) {
    throw new JOSENotSupported(`alg ${alg} is not supported either by JOSE or your javascript runtime`);
  }
  const keyObject = ensureKeyObject(key, alg, "unwrapKey");
  checkKeySize(keyObject, alg);
  const cipher = createDecipheriv2(algorithm, keyObject, Buffer2.alloc(8, 166));
  return concat(cipher.update(encryptedKey), cipher.final());
};

// node_modules/jose/dist/node/esm/runtime/ecdhes.js
import { diffieHellman, generateKeyPair as generateKeyPairCb, KeyObject as KeyObject4 } from "crypto";
import { promisify } from "util";

// node_modules/jose/dist/node/esm/runtime/get_named_curve.js
import { KeyObject as KeyObject3 } from "crypto";
var namedCurveToJOSE = (namedCurve) => {
  switch (namedCurve) {
    case "prime256v1":
      return "P-256";
    case "secp384r1":
      return "P-384";
    case "secp521r1":
      return "P-521";
    case "secp256k1":
      return "secp256k1";
    default:
      throw new JOSENotSupported("Unsupported key curve for this operation");
  }
};
var getNamedCurve2 = (kee, raw) => {
  let key;
  if (isCryptoKey(kee)) {
    key = KeyObject3.from(kee);
  } else if (is_key_object_default(kee)) {
    key = kee;
  } else {
    throw new TypeError(invalid_key_input_default(kee, ...types3));
  }
  if (key.type === "secret") {
    throw new TypeError('only "private" or "public" type keys can be used for this operation');
  }
  switch (key.asymmetricKeyType) {
    case "ed25519":
    case "ed448":
      return `Ed${key.asymmetricKeyType.slice(2)}`;
    case "x25519":
    case "x448":
      return `X${key.asymmetricKeyType.slice(1)}`;
    case "ec": {
      const namedCurve = key.asymmetricKeyDetails.namedCurve;
      if (raw) {
        return namedCurve;
      }
      return namedCurveToJOSE(namedCurve);
    }
    default:
      throw new TypeError("Invalid asymmetric key type for this operation");
  }
};
var get_named_curve_default = getNamedCurve2;

// node_modules/jose/dist/node/esm/runtime/ecdhes.js
var generateKeyPair = promisify(generateKeyPairCb);
function deriveKey(_0, _1, _2, _3) {
  return __async(this, arguments, function* (publicKee, privateKee, algorithm, keyLength, apu = new Uint8Array(0), apv = new Uint8Array(0)) {
    let publicKey;
    if (isCryptoKey(publicKee)) {
      checkEncCryptoKey(publicKee, "ECDH");
      publicKey = KeyObject4.from(publicKee);
    } else if (is_key_object_default(publicKee)) {
      publicKey = publicKee;
    } else {
      throw new TypeError(invalid_key_input_default(publicKee, ...types3));
    }
    let privateKey;
    if (isCryptoKey(privateKee)) {
      checkEncCryptoKey(privateKee, "ECDH", "deriveBits");
      privateKey = KeyObject4.from(privateKee);
    } else if (is_key_object_default(privateKee)) {
      privateKey = privateKee;
    } else {
      throw new TypeError(invalid_key_input_default(privateKee, ...types3));
    }
    const value = concat(lengthAndInput(encoder.encode(algorithm)), lengthAndInput(apu), lengthAndInput(apv), uint32be(keyLength));
    const sharedSecret = diffieHellman({
      privateKey,
      publicKey
    });
    return concatKdf(sharedSecret, keyLength, value);
  });
}
function generateEpk(kee) {
  return __async(this, null, function* () {
    let key;
    if (isCryptoKey(kee)) {
      key = KeyObject4.from(kee);
    } else if (is_key_object_default(kee)) {
      key = kee;
    } else {
      throw new TypeError(invalid_key_input_default(kee, ...types3));
    }
    switch (key.asymmetricKeyType) {
      case "x25519":
        return generateKeyPair("x25519");
      case "x448": {
        return generateKeyPair("x448");
      }
      case "ec": {
        const namedCurve = get_named_curve_default(key);
        return generateKeyPair("ec", {
          namedCurve
        });
      }
      default:
        throw new JOSENotSupported("Invalid or unsupported EPK");
    }
  });
}
var ecdhAllowed = (key) => ["P-256", "P-384", "P-521", "X25519", "X448"].includes(get_named_curve_default(key));

// node_modules/jose/dist/node/esm/runtime/pbes2kw.js
import { promisify as promisify2 } from "util";
import { KeyObject as KeyObject5, pbkdf2 as pbkdf2cb } from "crypto";

// node_modules/jose/dist/node/esm/lib/check_p2s.js
function checkP2s(p2s2) {
  if (!(p2s2 instanceof Uint8Array) || p2s2.length < 8) {
    throw new JWEInvalid("PBES2 Salt Input must be 8 or more octets");
  }
}

// node_modules/jose/dist/node/esm/runtime/pbes2kw.js
var pbkdf2 = promisify2(pbkdf2cb);
function getPassword(key, alg) {
  if (is_key_object_default(key)) {
    return key.export();
  }
  if (key instanceof Uint8Array) {
    return key;
  }
  if (isCryptoKey(key)) {
    checkEncCryptoKey(key, alg, "deriveBits", "deriveKey");
    return KeyObject5.from(key).export();
  }
  throw new TypeError(invalid_key_input_default(key, ...types3, "Uint8Array"));
}
var encrypt = (_0, _1, _2, ..._3) => __async(void 0, [_0, _1, _2, ..._3], function* (alg, key, cek, p2c = 2048, p2s2 = randomFillSync(new Uint8Array(16))) {
  checkP2s(p2s2);
  const salt = p2s(alg, p2s2);
  const keylen = parseInt(alg.slice(13, 16), 10) >> 3;
  const password = getPassword(key, alg);
  const derivedKey = yield pbkdf2(password, salt, p2c, keylen, `sha${alg.slice(8, 11)}`);
  const encryptedKey = yield wrap(alg.slice(-6), derivedKey, cek);
  return {
    encryptedKey,
    p2c,
    p2s: encode(p2s2)
  };
});
var decrypt2 = (alg, key, encryptedKey, p2c, p2s2) => __async(void 0, null, function* () {
  checkP2s(p2s2);
  const salt = p2s(alg, p2s2);
  const keylen = parseInt(alg.slice(13, 16), 10) >> 3;
  const password = getPassword(key, alg);
  const derivedKey = yield pbkdf2(password, salt, p2c, keylen, `sha${alg.slice(8, 11)}`);
  return unwrap(alg.slice(-6), derivedKey, encryptedKey);
});

// node_modules/jose/dist/node/esm/runtime/rsaes.js
import { KeyObject as KeyObject6, publicEncrypt, constants, privateDecrypt } from "crypto";
import { deprecate } from "util";

// node_modules/jose/dist/node/esm/runtime/check_key_length.js
var check_key_length_default = (key, alg) => {
  const {
    modulusLength
  } = key.asymmetricKeyDetails;
  if (typeof modulusLength !== "number" || modulusLength < 2048) {
    throw new TypeError(`${alg} requires key modulusLength to be 2048 bits or larger`);
  }
};

// node_modules/jose/dist/node/esm/runtime/rsaes.js
var checkKey = (key, alg) => {
  if (key.asymmetricKeyType !== "rsa") {
    throw new TypeError("Invalid key for this operation, its asymmetricKeyType must be rsa");
  }
  check_key_length_default(key, alg);
};
var RSA1_5 = deprecate(() => constants.RSA_PKCS1_PADDING, 'The RSA1_5 "alg" (JWE Algorithm) is deprecated and will be removed in the next major revision.');
var resolvePadding = (alg) => {
  switch (alg) {
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512":
      return constants.RSA_PKCS1_OAEP_PADDING;
    case "RSA1_5":
      return RSA1_5();
    default:
      return void 0;
  }
};
var resolveOaepHash = (alg) => {
  switch (alg) {
    case "RSA-OAEP":
      return "sha1";
    case "RSA-OAEP-256":
      return "sha256";
    case "RSA-OAEP-384":
      return "sha384";
    case "RSA-OAEP-512":
      return "sha512";
    default:
      return void 0;
  }
};
function ensureKeyObject2(key, alg, ...usages) {
  if (is_key_object_default(key)) {
    return key;
  }
  if (isCryptoKey(key)) {
    checkEncCryptoKey(key, alg, ...usages);
    return KeyObject6.from(key);
  }
  throw new TypeError(invalid_key_input_default(key, ...types3));
}
var encrypt2 = (alg, key, cek) => {
  const padding = resolvePadding(alg);
  const oaepHash = resolveOaepHash(alg);
  const keyObject = ensureKeyObject2(key, alg, "wrapKey", "encrypt");
  checkKey(keyObject, alg);
  return publicEncrypt({
    key: keyObject,
    oaepHash,
    padding
  }, cek);
};
var decrypt3 = (alg, key, encryptedKey) => {
  const padding = resolvePadding(alg);
  const oaepHash = resolveOaepHash(alg);
  const keyObject = ensureKeyObject2(key, alg, "unwrapKey", "decrypt");
  checkKey(keyObject, alg);
  return privateDecrypt({
    key: keyObject,
    oaepHash,
    padding
  }, encryptedKey);
};

// node_modules/jose/dist/node/esm/runtime/normalize_key.js
var normalize_key_default = {};

// node_modules/jose/dist/node/esm/lib/cek.js
function bitLength2(alg) {
  switch (alg) {
    case "A128GCM":
      return 128;
    case "A192GCM":
      return 192;
    case "A256GCM":
    case "A128CBC-HS256":
      return 256;
    case "A192CBC-HS384":
      return 384;
    case "A256CBC-HS512":
      return 512;
    default:
      throw new JOSENotSupported(`Unsupported JWE Algorithm: ${alg}`);
  }
}
var cek_default = (alg) => randomFillSync(new Uint8Array(bitLength2(alg) >> 3));

// node_modules/jose/dist/node/esm/runtime/asn1.js
import { createPrivateKey, createPublicKey, KeyObject as KeyObject7 } from "crypto";
import { Buffer as Buffer3 } from "buffer";
var genericExport = (keyType, keyFormat, key) => {
  let keyObject;
  if (isCryptoKey(key)) {
    if (!key.extractable) {
      throw new TypeError("CryptoKey is not extractable");
    }
    keyObject = KeyObject7.from(key);
  } else if (is_key_object_default(key)) {
    keyObject = key;
  } else {
    throw new TypeError(invalid_key_input_default(key, ...types3));
  }
  if (keyObject.type !== keyType) {
    throw new TypeError(`key is not a ${keyType} key`);
  }
  return keyObject.export({
    format: "pem",
    type: keyFormat
  });
};
var toSPKI = (key) => {
  return genericExport("public", "spki", key);
};
var toPKCS8 = (key) => {
  return genericExport("private", "pkcs8", key);
};
var fromPKCS8 = (pem) => createPrivateKey({
  key: Buffer3.from(pem.replace(/(?:-----(?:BEGIN|END) PRIVATE KEY-----|\s)/g, ""), "base64"),
  type: "pkcs8",
  format: "der"
});
var fromSPKI = (pem) => createPublicKey({
  key: Buffer3.from(pem.replace(/(?:-----(?:BEGIN|END) PUBLIC KEY-----|\s)/g, ""), "base64"),
  type: "spki",
  format: "der"
});
var fromX509 = (pem) => createPublicKey({
  key: pem,
  type: "spki",
  format: "pem"
});

// node_modules/jose/dist/node/esm/runtime/jwk_to_key.js
import { createPrivateKey as createPrivateKey2, createPublicKey as createPublicKey2 } from "crypto";
var parse = (jwk) => {
  return (jwk.d ? createPrivateKey2 : createPublicKey2)({
    format: "jwk",
    key: jwk
  });
};
var jwk_to_key_default = parse;

// node_modules/jose/dist/node/esm/key/import.js
function importSPKI(spki, alg, options) {
  return __async(this, null, function* () {
    if (typeof spki !== "string" || spki.indexOf("-----BEGIN PUBLIC KEY-----") !== 0) {
      throw new TypeError('"spki" must be SPKI formatted string');
    }
    return fromSPKI(spki, alg, options);
  });
}
function importX509(x509, alg, options) {
  return __async(this, null, function* () {
    if (typeof x509 !== "string" || x509.indexOf("-----BEGIN CERTIFICATE-----") !== 0) {
      throw new TypeError('"x509" must be X.509 formatted string');
    }
    return fromX509(x509, alg, options);
  });
}
function importPKCS8(pkcs8, alg, options) {
  return __async(this, null, function* () {
    if (typeof pkcs8 !== "string" || pkcs8.indexOf("-----BEGIN PRIVATE KEY-----") !== 0) {
      throw new TypeError('"pkcs8" must be PKCS#8 formatted string');
    }
    return fromPKCS8(pkcs8, alg, options);
  });
}
function importJWK(jwk, alg) {
  return __async(this, null, function* () {
    if (!isObject(jwk)) {
      throw new TypeError("JWK must be an object");
    }
    alg ||= jwk.alg;
    switch (jwk.kty) {
      case "oct":
        if (typeof jwk.k !== "string" || !jwk.k) {
          throw new TypeError('missing "k" (Key Value) Parameter value');
        }
        return decode(jwk.k);
      case "RSA":
        if (jwk.oth !== void 0) {
          throw new JOSENotSupported('RSA JWK "oth" (Other Primes Info) Parameter value is not supported');
        }
      case "EC":
      case "OKP":
        return jwk_to_key_default(__spreadProps(__spreadValues({}, jwk), {
          alg
        }));
      default:
        throw new JOSENotSupported('Unsupported "kty" (Key Type) Parameter value');
    }
  });
}

// node_modules/jose/dist/node/esm/lib/check_key_type.js
var tag = (key) => key?.[Symbol.toStringTag];
var symmetricTypeCheck = (alg, key) => {
  if (key instanceof Uint8Array) return;
  if (!is_key_like_default(key)) {
    throw new TypeError(withAlg(alg, key, ...types3, "Uint8Array"));
  }
  if (key.type !== "secret") {
    throw new TypeError(`${tag(key)} instances for symmetric algorithms must be of type "secret"`);
  }
};
var asymmetricTypeCheck = (alg, key, usage) => {
  if (!is_key_like_default(key)) {
    throw new TypeError(withAlg(alg, key, ...types3));
  }
  if (key.type === "secret") {
    throw new TypeError(`${tag(key)} instances for asymmetric algorithms must not be of type "secret"`);
  }
  if (usage === "sign" && key.type === "public") {
    throw new TypeError(`${tag(key)} instances for asymmetric algorithm signing must be of type "private"`);
  }
  if (usage === "decrypt" && key.type === "public") {
    throw new TypeError(`${tag(key)} instances for asymmetric algorithm decryption must be of type "private"`);
  }
  if (key.algorithm && usage === "verify" && key.type === "private") {
    throw new TypeError(`${tag(key)} instances for asymmetric algorithm verifying must be of type "public"`);
  }
  if (key.algorithm && usage === "encrypt" && key.type === "private") {
    throw new TypeError(`${tag(key)} instances for asymmetric algorithm encryption must be of type "public"`);
  }
};
var checkKeyType = (alg, key, usage) => {
  const symmetric = alg.startsWith("HS") || alg === "dir" || alg.startsWith("PBES2") || /^A\d{3}(?:GCM)?KW$/.test(alg);
  if (symmetric) {
    symmetricTypeCheck(alg, key);
  } else {
    asymmetricTypeCheck(alg, key, usage);
  }
};
var check_key_type_default = checkKeyType;

// node_modules/jose/dist/node/esm/runtime/encrypt.js
import { createCipheriv as createCipheriv2, KeyObject as KeyObject8 } from "crypto";
function cbcEncrypt(enc, plaintext, cek, iv, aad) {
  const keySize = parseInt(enc.slice(1, 4), 10);
  if (is_key_object_default(cek)) {
    cek = cek.export();
  }
  const encKey = cek.subarray(keySize >> 3);
  const macKey = cek.subarray(0, keySize >> 3);
  const algorithm = `aes-${keySize}-cbc`;
  if (!ciphers_default(algorithm)) {
    throw new JOSENotSupported(`alg ${enc} is not supported by your javascript runtime`);
  }
  const cipher = createCipheriv2(algorithm, encKey, iv);
  const ciphertext = concat(cipher.update(plaintext), cipher.final());
  const macSize = parseInt(enc.slice(-3), 10);
  const tag2 = cbcTag(aad, iv, ciphertext, macSize, macKey, keySize);
  return {
    ciphertext,
    tag: tag2,
    iv
  };
}
function gcmEncrypt(enc, plaintext, cek, iv, aad) {
  const keySize = parseInt(enc.slice(1, 4), 10);
  const algorithm = `aes-${keySize}-gcm`;
  if (!ciphers_default(algorithm)) {
    throw new JOSENotSupported(`alg ${enc} is not supported by your javascript runtime`);
  }
  const cipher = createCipheriv2(algorithm, cek, iv, {
    authTagLength: 16
  });
  if (aad.byteLength) {
    cipher.setAAD(aad, {
      plaintextLength: plaintext.length
    });
  }
  const ciphertext = cipher.update(plaintext);
  cipher.final();
  const tag2 = cipher.getAuthTag();
  return {
    ciphertext,
    tag: tag2,
    iv
  };
}
var encrypt3 = (enc, plaintext, cek, iv, aad) => {
  let key;
  if (isCryptoKey(cek)) {
    checkEncCryptoKey(cek, enc, "encrypt");
    key = KeyObject8.from(cek);
  } else if (cek instanceof Uint8Array || is_key_object_default(cek)) {
    key = cek;
  } else {
    throw new TypeError(invalid_key_input_default(cek, ...types3, "Uint8Array"));
  }
  check_cek_length_default(enc, key);
  if (iv) {
    check_iv_length_default(enc, iv);
  } else {
    iv = iv_default(enc);
  }
  switch (enc) {
    case "A128CBC-HS256":
    case "A192CBC-HS384":
    case "A256CBC-HS512":
      return cbcEncrypt(enc, plaintext, key, iv, aad);
    case "A128GCM":
    case "A192GCM":
    case "A256GCM":
      return gcmEncrypt(enc, plaintext, key, iv, aad);
    default:
      throw new JOSENotSupported("Unsupported JWE Content Encryption Algorithm");
  }
};
var encrypt_default = encrypt3;

// node_modules/jose/dist/node/esm/lib/aesgcmkw.js
function wrap2(alg, key, cek, iv) {
  return __async(this, null, function* () {
    const jweAlgorithm = alg.slice(0, 7);
    const wrapped = yield encrypt_default(jweAlgorithm, cek, key, iv, new Uint8Array(0));
    return {
      encryptedKey: wrapped.ciphertext,
      iv: encode(wrapped.iv),
      tag: encode(wrapped.tag)
    };
  });
}
function unwrap2(alg, key, encryptedKey, iv, tag2) {
  return __async(this, null, function* () {
    const jweAlgorithm = alg.slice(0, 7);
    return decrypt_default(jweAlgorithm, key, encryptedKey, iv, tag2, new Uint8Array(0));
  });
}

// node_modules/jose/dist/node/esm/lib/decrypt_key_management.js
function decryptKeyManagement(alg, key, encryptedKey, joseHeader, options) {
  return __async(this, null, function* () {
    check_key_type_default(alg, key, "decrypt");
    key = (yield normalize_key_default.normalizePrivateKey?.(key, alg)) || key;
    switch (alg) {
      case "dir": {
        if (encryptedKey !== void 0) throw new JWEInvalid("Encountered unexpected JWE Encrypted Key");
        return key;
      }
      case "ECDH-ES":
        if (encryptedKey !== void 0) throw new JWEInvalid("Encountered unexpected JWE Encrypted Key");
      case "ECDH-ES+A128KW":
      case "ECDH-ES+A192KW":
      case "ECDH-ES+A256KW": {
        if (!isObject(joseHeader.epk)) throw new JWEInvalid(`JOSE Header "epk" (Ephemeral Public Key) missing or invalid`);
        if (!ecdhAllowed(key)) throw new JOSENotSupported("ECDH with the provided key is not allowed or not supported by your javascript runtime");
        const epk = yield importJWK(joseHeader.epk, alg);
        let partyUInfo;
        let partyVInfo;
        if (joseHeader.apu !== void 0) {
          if (typeof joseHeader.apu !== "string") throw new JWEInvalid(`JOSE Header "apu" (Agreement PartyUInfo) invalid`);
          try {
            partyUInfo = decode(joseHeader.apu);
          } catch {
            throw new JWEInvalid("Failed to base64url decode the apu");
          }
        }
        if (joseHeader.apv !== void 0) {
          if (typeof joseHeader.apv !== "string") throw new JWEInvalid(`JOSE Header "apv" (Agreement PartyVInfo) invalid`);
          try {
            partyVInfo = decode(joseHeader.apv);
          } catch {
            throw new JWEInvalid("Failed to base64url decode the apv");
          }
        }
        const sharedSecret = yield deriveKey(epk, key, alg === "ECDH-ES" ? joseHeader.enc : alg, alg === "ECDH-ES" ? bitLength2(joseHeader.enc) : parseInt(alg.slice(-5, -2), 10), partyUInfo, partyVInfo);
        if (alg === "ECDH-ES") return sharedSecret;
        if (encryptedKey === void 0) throw new JWEInvalid("JWE Encrypted Key missing");
        return unwrap(alg.slice(-6), sharedSecret, encryptedKey);
      }
      case "RSA1_5":
      case "RSA-OAEP":
      case "RSA-OAEP-256":
      case "RSA-OAEP-384":
      case "RSA-OAEP-512": {
        if (encryptedKey === void 0) throw new JWEInvalid("JWE Encrypted Key missing");
        return decrypt3(alg, key, encryptedKey);
      }
      case "PBES2-HS256+A128KW":
      case "PBES2-HS384+A192KW":
      case "PBES2-HS512+A256KW": {
        if (encryptedKey === void 0) throw new JWEInvalid("JWE Encrypted Key missing");
        if (typeof joseHeader.p2c !== "number") throw new JWEInvalid(`JOSE Header "p2c" (PBES2 Count) missing or invalid`);
        const p2cLimit = options?.maxPBES2Count || 1e4;
        if (joseHeader.p2c > p2cLimit) throw new JWEInvalid(`JOSE Header "p2c" (PBES2 Count) out is of acceptable bounds`);
        if (typeof joseHeader.p2s !== "string") throw new JWEInvalid(`JOSE Header "p2s" (PBES2 Salt) missing or invalid`);
        let p2s2;
        try {
          p2s2 = decode(joseHeader.p2s);
        } catch {
          throw new JWEInvalid("Failed to base64url decode the p2s");
        }
        return decrypt2(alg, key, encryptedKey, joseHeader.p2c, p2s2);
      }
      case "A128KW":
      case "A192KW":
      case "A256KW": {
        if (encryptedKey === void 0) throw new JWEInvalid("JWE Encrypted Key missing");
        return unwrap(alg, key, encryptedKey);
      }
      case "A128GCMKW":
      case "A192GCMKW":
      case "A256GCMKW": {
        if (encryptedKey === void 0) throw new JWEInvalid("JWE Encrypted Key missing");
        if (typeof joseHeader.iv !== "string") throw new JWEInvalid(`JOSE Header "iv" (Initialization Vector) missing or invalid`);
        if (typeof joseHeader.tag !== "string") throw new JWEInvalid(`JOSE Header "tag" (Authentication Tag) missing or invalid`);
        let iv;
        try {
          iv = decode(joseHeader.iv);
        } catch {
          throw new JWEInvalid("Failed to base64url decode the iv");
        }
        let tag2;
        try {
          tag2 = decode(joseHeader.tag);
        } catch {
          throw new JWEInvalid("Failed to base64url decode the tag");
        }
        return unwrap2(alg, key, encryptedKey, iv, tag2);
      }
      default: {
        throw new JOSENotSupported('Invalid or unsupported "alg" (JWE Algorithm) header value');
      }
    }
  });
}
var decrypt_key_management_default = decryptKeyManagement;

// node_modules/jose/dist/node/esm/lib/validate_crit.js
function validateCrit(Err, recognizedDefault, recognizedOption, protectedHeader, joseHeader) {
  if (joseHeader.crit !== void 0 && protectedHeader?.crit === void 0) {
    throw new Err('"crit" (Critical) Header Parameter MUST be integrity protected');
  }
  if (!protectedHeader || protectedHeader.crit === void 0) {
    return /* @__PURE__ */ new Set();
  }
  if (!Array.isArray(protectedHeader.crit) || protectedHeader.crit.length === 0 || protectedHeader.crit.some((input) => typeof input !== "string" || input.length === 0)) {
    throw new Err('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present');
  }
  let recognized;
  if (recognizedOption !== void 0) {
    recognized = new Map([...Object.entries(recognizedOption), ...recognizedDefault.entries()]);
  } else {
    recognized = recognizedDefault;
  }
  for (const parameter of protectedHeader.crit) {
    if (!recognized.has(parameter)) {
      throw new JOSENotSupported(`Extension Header Parameter "${parameter}" is not recognized`);
    }
    if (joseHeader[parameter] === void 0) {
      throw new Err(`Extension Header Parameter "${parameter}" is missing`);
    }
    if (recognized.get(parameter) && protectedHeader[parameter] === void 0) {
      throw new Err(`Extension Header Parameter "${parameter}" MUST be integrity protected`);
    }
  }
  return new Set(protectedHeader.crit);
}
var validate_crit_default = validateCrit;

// node_modules/jose/dist/node/esm/lib/validate_algorithms.js
var validateAlgorithms = (option, algorithms) => {
  if (algorithms !== void 0 && (!Array.isArray(algorithms) || algorithms.some((s) => typeof s !== "string"))) {
    throw new TypeError(`"${option}" option must be an array of strings`);
  }
  if (!algorithms) {
    return void 0;
  }
  return new Set(algorithms);
};
var validate_algorithms_default = validateAlgorithms;

// node_modules/jose/dist/node/esm/jwe/flattened/decrypt.js
function flattenedDecrypt(jwe, key, options) {
  return __async(this, null, function* () {
    if (!isObject(jwe)) {
      throw new JWEInvalid("Flattened JWE must be an object");
    }
    if (jwe.protected === void 0 && jwe.header === void 0 && jwe.unprotected === void 0) {
      throw new JWEInvalid("JOSE Header missing");
    }
    if (jwe.iv !== void 0 && typeof jwe.iv !== "string") {
      throw new JWEInvalid("JWE Initialization Vector incorrect type");
    }
    if (typeof jwe.ciphertext !== "string") {
      throw new JWEInvalid("JWE Ciphertext missing or incorrect type");
    }
    if (jwe.tag !== void 0 && typeof jwe.tag !== "string") {
      throw new JWEInvalid("JWE Authentication Tag incorrect type");
    }
    if (jwe.protected !== void 0 && typeof jwe.protected !== "string") {
      throw new JWEInvalid("JWE Protected Header incorrect type");
    }
    if (jwe.encrypted_key !== void 0 && typeof jwe.encrypted_key !== "string") {
      throw new JWEInvalid("JWE Encrypted Key incorrect type");
    }
    if (jwe.aad !== void 0 && typeof jwe.aad !== "string") {
      throw new JWEInvalid("JWE AAD incorrect type");
    }
    if (jwe.header !== void 0 && !isObject(jwe.header)) {
      throw new JWEInvalid("JWE Shared Unprotected Header incorrect type");
    }
    if (jwe.unprotected !== void 0 && !isObject(jwe.unprotected)) {
      throw new JWEInvalid("JWE Per-Recipient Unprotected Header incorrect type");
    }
    let parsedProt;
    if (jwe.protected) {
      try {
        const protectedHeader2 = decode(jwe.protected);
        parsedProt = JSON.parse(decoder.decode(protectedHeader2));
      } catch {
        throw new JWEInvalid("JWE Protected Header is invalid");
      }
    }
    if (!is_disjoint_default(parsedProt, jwe.header, jwe.unprotected)) {
      throw new JWEInvalid("JWE Protected, JWE Unprotected Header, and JWE Per-Recipient Unprotected Header Parameter names must be disjoint");
    }
    const joseHeader = __spreadValues(__spreadValues(__spreadValues({}, parsedProt), jwe.header), jwe.unprotected);
    validate_crit_default(JWEInvalid, /* @__PURE__ */ new Map(), options?.crit, parsedProt, joseHeader);
    if (joseHeader.zip !== void 0) {
      throw new JOSENotSupported('JWE "zip" (Compression Algorithm) Header Parameter is not supported.');
    }
    const {
      alg,
      enc
    } = joseHeader;
    if (typeof alg !== "string" || !alg) {
      throw new JWEInvalid("missing JWE Algorithm (alg) in JWE Header");
    }
    if (typeof enc !== "string" || !enc) {
      throw new JWEInvalid("missing JWE Encryption Algorithm (enc) in JWE Header");
    }
    const keyManagementAlgorithms = options && validate_algorithms_default("keyManagementAlgorithms", options.keyManagementAlgorithms);
    const contentEncryptionAlgorithms = options && validate_algorithms_default("contentEncryptionAlgorithms", options.contentEncryptionAlgorithms);
    if (keyManagementAlgorithms && !keyManagementAlgorithms.has(alg) || !keyManagementAlgorithms && alg.startsWith("PBES2")) {
      throw new JOSEAlgNotAllowed('"alg" (Algorithm) Header Parameter value not allowed');
    }
    if (contentEncryptionAlgorithms && !contentEncryptionAlgorithms.has(enc)) {
      throw new JOSEAlgNotAllowed('"enc" (Encryption Algorithm) Header Parameter value not allowed');
    }
    let encryptedKey;
    if (jwe.encrypted_key !== void 0) {
      try {
        encryptedKey = decode(jwe.encrypted_key);
      } catch {
        throw new JWEInvalid("Failed to base64url decode the encrypted_key");
      }
    }
    let resolvedKey = false;
    if (typeof key === "function") {
      key = yield key(parsedProt, jwe);
      resolvedKey = true;
    }
    let cek;
    try {
      cek = yield decrypt_key_management_default(alg, key, encryptedKey, joseHeader, options);
    } catch (err) {
      if (err instanceof TypeError || err instanceof JWEInvalid || err instanceof JOSENotSupported) {
        throw err;
      }
      cek = cek_default(enc);
    }
    let iv;
    let tag2;
    if (jwe.iv !== void 0) {
      try {
        iv = decode(jwe.iv);
      } catch {
        throw new JWEInvalid("Failed to base64url decode the iv");
      }
    }
    if (jwe.tag !== void 0) {
      try {
        tag2 = decode(jwe.tag);
      } catch {
        throw new JWEInvalid("Failed to base64url decode the tag");
      }
    }
    const protectedHeader = encoder.encode(jwe.protected ?? "");
    let additionalData;
    if (jwe.aad !== void 0) {
      additionalData = concat(protectedHeader, encoder.encode("."), encoder.encode(jwe.aad));
    } else {
      additionalData = protectedHeader;
    }
    let ciphertext;
    try {
      ciphertext = decode(jwe.ciphertext);
    } catch {
      throw new JWEInvalid("Failed to base64url decode the ciphertext");
    }
    const plaintext = yield decrypt_default(enc, cek, ciphertext, iv, tag2, additionalData);
    const result = {
      plaintext
    };
    if (jwe.protected !== void 0) {
      result.protectedHeader = parsedProt;
    }
    if (jwe.aad !== void 0) {
      try {
        result.additionalAuthenticatedData = decode(jwe.aad);
      } catch {
        throw new JWEInvalid("Failed to base64url decode the aad");
      }
    }
    if (jwe.unprotected !== void 0) {
      result.sharedUnprotectedHeader = jwe.unprotected;
    }
    if (jwe.header !== void 0) {
      result.unprotectedHeader = jwe.header;
    }
    if (resolvedKey) {
      return __spreadProps(__spreadValues({}, result), {
        key
      });
    }
    return result;
  });
}

// node_modules/jose/dist/node/esm/jwe/compact/decrypt.js
function compactDecrypt(jwe, key, options) {
  return __async(this, null, function* () {
    if (jwe instanceof Uint8Array) {
      jwe = decoder.decode(jwe);
    }
    if (typeof jwe !== "string") {
      throw new JWEInvalid("Compact JWE must be a string or Uint8Array");
    }
    const {
      0: protectedHeader,
      1: encryptedKey,
      2: iv,
      3: ciphertext,
      4: tag2,
      length
    } = jwe.split(".");
    if (length !== 5) {
      throw new JWEInvalid("Invalid Compact JWE");
    }
    const decrypted = yield flattenedDecrypt({
      ciphertext,
      iv: iv || void 0,
      protected: protectedHeader,
      tag: tag2 || void 0,
      encrypted_key: encryptedKey || void 0
    }, key, options);
    const result = {
      plaintext: decrypted.plaintext,
      protectedHeader: decrypted.protectedHeader
    };
    if (typeof key === "function") {
      return __spreadProps(__spreadValues({}, result), {
        key: decrypted.key
      });
    }
    return result;
  });
}

// node_modules/jose/dist/node/esm/jwe/general/decrypt.js
function generalDecrypt(jwe, key, options) {
  return __async(this, null, function* () {
    if (!isObject(jwe)) {
      throw new JWEInvalid("General JWE must be an object");
    }
    if (!Array.isArray(jwe.recipients) || !jwe.recipients.every(isObject)) {
      throw new JWEInvalid("JWE Recipients missing or incorrect type");
    }
    if (!jwe.recipients.length) {
      throw new JWEInvalid("JWE Recipients has no members");
    }
    for (const recipient of jwe.recipients) {
      try {
        return yield flattenedDecrypt({
          aad: jwe.aad,
          ciphertext: jwe.ciphertext,
          encrypted_key: recipient.encrypted_key,
          header: recipient.header,
          iv: jwe.iv,
          protected: jwe.protected,
          tag: jwe.tag,
          unprotected: jwe.unprotected
        }, key, options);
      } catch {
      }
    }
    throw new JWEDecryptionFailed();
  });
}

// node_modules/jose/dist/node/esm/runtime/key_to_jwk.js
import { KeyObject as KeyObject9 } from "crypto";
var keyToJWK = (key) => {
  let keyObject;
  if (isCryptoKey(key)) {
    if (!key.extractable) {
      throw new TypeError("CryptoKey is not extractable");
    }
    keyObject = KeyObject9.from(key);
  } else if (is_key_object_default(key)) {
    keyObject = key;
  } else if (key instanceof Uint8Array) {
    return {
      kty: "oct",
      k: encode(key)
    };
  } else {
    throw new TypeError(invalid_key_input_default(key, ...types3, "Uint8Array"));
  }
  if (keyObject.type !== "secret" && !["rsa", "ec", "ed25519", "x25519", "ed448", "x448"].includes(keyObject.asymmetricKeyType)) {
    throw new JOSENotSupported("Unsupported key asymmetricKeyType");
  }
  return keyObject.export({
    format: "jwk"
  });
};
var key_to_jwk_default = keyToJWK;

// node_modules/jose/dist/node/esm/key/export.js
function exportSPKI(key) {
  return __async(this, null, function* () {
    return toSPKI(key);
  });
}
function exportPKCS8(key) {
  return __async(this, null, function* () {
    return toPKCS8(key);
  });
}
function exportJWK(key) {
  return __async(this, null, function* () {
    return key_to_jwk_default(key);
  });
}

// node_modules/jose/dist/node/esm/lib/encrypt_key_management.js
function encryptKeyManagement(_0, _1, _2, _3) {
  return __async(this, arguments, function* (alg, enc, key, providedCek, providedParameters = {}) {
    var _a, _b;
    let encryptedKey;
    let parameters;
    let cek;
    check_key_type_default(alg, key, "encrypt");
    key = (yield normalize_key_default.normalizePublicKey?.(key, alg)) || key;
    switch (alg) {
      case "dir": {
        cek = key;
        break;
      }
      case "ECDH-ES":
      case "ECDH-ES+A128KW":
      case "ECDH-ES+A192KW":
      case "ECDH-ES+A256KW": {
        if (!ecdhAllowed(key)) {
          throw new JOSENotSupported("ECDH with the provided key is not allowed or not supported by your javascript runtime");
        }
        const {
          apu,
          apv
        } = providedParameters;
        let {
          epk: ephemeralKey
        } = providedParameters;
        ephemeralKey ||= (yield generateEpk(key)).privateKey;
        const {
          x,
          y,
          crv,
          kty
        } = yield exportJWK(ephemeralKey);
        const sharedSecret = yield deriveKey(key, ephemeralKey, alg === "ECDH-ES" ? enc : alg, alg === "ECDH-ES" ? bitLength2(enc) : parseInt(alg.slice(-5, -2), 10), apu, apv);
        parameters = {
          epk: {
            x,
            crv,
            kty
          }
        };
        if (kty === "EC") parameters.epk.y = y;
        if (apu) parameters.apu = encode(apu);
        if (apv) parameters.apv = encode(apv);
        if (alg === "ECDH-ES") {
          cek = sharedSecret;
          break;
        }
        cek = providedCek || cek_default(enc);
        const kwAlg = alg.slice(-6);
        encryptedKey = yield wrap(kwAlg, sharedSecret, cek);
        break;
      }
      case "RSA1_5":
      case "RSA-OAEP":
      case "RSA-OAEP-256":
      case "RSA-OAEP-384":
      case "RSA-OAEP-512": {
        cek = providedCek || cek_default(enc);
        encryptedKey = yield encrypt2(alg, key, cek);
        break;
      }
      case "PBES2-HS256+A128KW":
      case "PBES2-HS384+A192KW":
      case "PBES2-HS512+A256KW": {
        cek = providedCek || cek_default(enc);
        const {
          p2c,
          p2s: p2s2
        } = providedParameters;
        _a = yield encrypt(alg, key, cek, p2c, p2s2), {
          encryptedKey
        } = _a, parameters = __objRest(_a, [
          "encryptedKey"
        ]);
        break;
      }
      case "A128KW":
      case "A192KW":
      case "A256KW": {
        cek = providedCek || cek_default(enc);
        encryptedKey = yield wrap(alg, key, cek);
        break;
      }
      case "A128GCMKW":
      case "A192GCMKW":
      case "A256GCMKW": {
        cek = providedCek || cek_default(enc);
        const {
          iv
        } = providedParameters;
        _b = yield wrap2(alg, key, cek, iv), {
          encryptedKey
        } = _b, parameters = __objRest(_b, [
          "encryptedKey"
        ]);
        break;
      }
      default: {
        throw new JOSENotSupported('Invalid or unsupported "alg" (JWE Algorithm) header value');
      }
    }
    return {
      cek,
      encryptedKey,
      parameters
    };
  });
}
var encrypt_key_management_default = encryptKeyManagement;

// node_modules/jose/dist/node/esm/jwe/flattened/encrypt.js
var unprotected = Symbol();
var FlattenedEncrypt = class {
  _plaintext;
  _protectedHeader;
  _sharedUnprotectedHeader;
  _unprotectedHeader;
  _aad;
  _cek;
  _iv;
  _keyManagementParameters;
  constructor(plaintext) {
    if (!(plaintext instanceof Uint8Array)) {
      throw new TypeError("plaintext must be an instance of Uint8Array");
    }
    this._plaintext = plaintext;
  }
  setKeyManagementParameters(parameters) {
    if (this._keyManagementParameters) {
      throw new TypeError("setKeyManagementParameters can only be called once");
    }
    this._keyManagementParameters = parameters;
    return this;
  }
  setProtectedHeader(protectedHeader) {
    if (this._protectedHeader) {
      throw new TypeError("setProtectedHeader can only be called once");
    }
    this._protectedHeader = protectedHeader;
    return this;
  }
  setSharedUnprotectedHeader(sharedUnprotectedHeader) {
    if (this._sharedUnprotectedHeader) {
      throw new TypeError("setSharedUnprotectedHeader can only be called once");
    }
    this._sharedUnprotectedHeader = sharedUnprotectedHeader;
    return this;
  }
  setUnprotectedHeader(unprotectedHeader) {
    if (this._unprotectedHeader) {
      throw new TypeError("setUnprotectedHeader can only be called once");
    }
    this._unprotectedHeader = unprotectedHeader;
    return this;
  }
  setAdditionalAuthenticatedData(aad) {
    this._aad = aad;
    return this;
  }
  setContentEncryptionKey(cek) {
    if (this._cek) {
      throw new TypeError("setContentEncryptionKey can only be called once");
    }
    this._cek = cek;
    return this;
  }
  setInitializationVector(iv) {
    if (this._iv) {
      throw new TypeError("setInitializationVector can only be called once");
    }
    this._iv = iv;
    return this;
  }
  encrypt(key, options) {
    return __async(this, null, function* () {
      if (!this._protectedHeader && !this._unprotectedHeader && !this._sharedUnprotectedHeader) {
        throw new JWEInvalid("either setProtectedHeader, setUnprotectedHeader, or sharedUnprotectedHeader must be called before #encrypt()");
      }
      if (!is_disjoint_default(this._protectedHeader, this._unprotectedHeader, this._sharedUnprotectedHeader)) {
        throw new JWEInvalid("JWE Protected, JWE Shared Unprotected and JWE Per-Recipient Header Parameter names must be disjoint");
      }
      const joseHeader = __spreadValues(__spreadValues(__spreadValues({}, this._protectedHeader), this._unprotectedHeader), this._sharedUnprotectedHeader);
      validate_crit_default(JWEInvalid, /* @__PURE__ */ new Map(), options?.crit, this._protectedHeader, joseHeader);
      if (joseHeader.zip !== void 0) {
        throw new JOSENotSupported('JWE "zip" (Compression Algorithm) Header Parameter is not supported.');
      }
      const {
        alg,
        enc
      } = joseHeader;
      if (typeof alg !== "string" || !alg) {
        throw new JWEInvalid('JWE "alg" (Algorithm) Header Parameter missing or invalid');
      }
      if (typeof enc !== "string" || !enc) {
        throw new JWEInvalid('JWE "enc" (Encryption Algorithm) Header Parameter missing or invalid');
      }
      let encryptedKey;
      if (this._cek && (alg === "dir" || alg === "ECDH-ES")) {
        throw new TypeError(`setContentEncryptionKey cannot be called with JWE "alg" (Algorithm) Header ${alg}`);
      }
      let cek;
      {
        let parameters;
        ({
          cek,
          encryptedKey,
          parameters
        } = yield encrypt_key_management_default(alg, enc, key, this._cek, this._keyManagementParameters));
        if (parameters) {
          if (options && unprotected in options) {
            if (!this._unprotectedHeader) {
              this.setUnprotectedHeader(parameters);
            } else {
              this._unprotectedHeader = __spreadValues(__spreadValues({}, this._unprotectedHeader), parameters);
            }
          } else if (!this._protectedHeader) {
            this.setProtectedHeader(parameters);
          } else {
            this._protectedHeader = __spreadValues(__spreadValues({}, this._protectedHeader), parameters);
          }
        }
      }
      let additionalData;
      let protectedHeader;
      let aadMember;
      if (this._protectedHeader) {
        protectedHeader = encoder.encode(encode(JSON.stringify(this._protectedHeader)));
      } else {
        protectedHeader = encoder.encode("");
      }
      if (this._aad) {
        aadMember = encode(this._aad);
        additionalData = concat(protectedHeader, encoder.encode("."), encoder.encode(aadMember));
      } else {
        additionalData = protectedHeader;
      }
      const {
        ciphertext,
        tag: tag2,
        iv
      } = yield encrypt_default(enc, this._plaintext, cek, this._iv, additionalData);
      const jwe = {
        ciphertext: encode(ciphertext)
      };
      if (iv) {
        jwe.iv = encode(iv);
      }
      if (tag2) {
        jwe.tag = encode(tag2);
      }
      if (encryptedKey) {
        jwe.encrypted_key = encode(encryptedKey);
      }
      if (aadMember) {
        jwe.aad = aadMember;
      }
      if (this._protectedHeader) {
        jwe.protected = decoder.decode(protectedHeader);
      }
      if (this._sharedUnprotectedHeader) {
        jwe.unprotected = this._sharedUnprotectedHeader;
      }
      if (this._unprotectedHeader) {
        jwe.header = this._unprotectedHeader;
      }
      return jwe;
    });
  }
};

// node_modules/jose/dist/node/esm/jwe/general/encrypt.js
var IndividualRecipient = class {
  parent;
  unprotectedHeader;
  key;
  options;
  constructor(enc, key, options) {
    this.parent = enc;
    this.key = key;
    this.options = options;
  }
  setUnprotectedHeader(unprotectedHeader) {
    if (this.unprotectedHeader) {
      throw new TypeError("setUnprotectedHeader can only be called once");
    }
    this.unprotectedHeader = unprotectedHeader;
    return this;
  }
  addRecipient(...args) {
    return this.parent.addRecipient(...args);
  }
  encrypt(...args) {
    return this.parent.encrypt(...args);
  }
  done() {
    return this.parent;
  }
};
var GeneralEncrypt = class {
  _plaintext;
  _recipients = [];
  _protectedHeader;
  _unprotectedHeader;
  _aad;
  constructor(plaintext) {
    this._plaintext = plaintext;
  }
  addRecipient(key, options) {
    const recipient = new IndividualRecipient(this, key, {
      crit: options?.crit
    });
    this._recipients.push(recipient);
    return recipient;
  }
  setProtectedHeader(protectedHeader) {
    if (this._protectedHeader) {
      throw new TypeError("setProtectedHeader can only be called once");
    }
    this._protectedHeader = protectedHeader;
    return this;
  }
  setSharedUnprotectedHeader(sharedUnprotectedHeader) {
    if (this._unprotectedHeader) {
      throw new TypeError("setSharedUnprotectedHeader can only be called once");
    }
    this._unprotectedHeader = sharedUnprotectedHeader;
    return this;
  }
  setAdditionalAuthenticatedData(aad) {
    this._aad = aad;
    return this;
  }
  encrypt() {
    return __async(this, null, function* () {
      if (!this._recipients.length) {
        throw new JWEInvalid("at least one recipient must be added");
      }
      if (this._recipients.length === 1) {
        const [recipient] = this._recipients;
        const flattened = yield new FlattenedEncrypt(this._plaintext).setAdditionalAuthenticatedData(this._aad).setProtectedHeader(this._protectedHeader).setSharedUnprotectedHeader(this._unprotectedHeader).setUnprotectedHeader(recipient.unprotectedHeader).encrypt(recipient.key, __spreadValues({}, recipient.options));
        const jwe2 = {
          ciphertext: flattened.ciphertext,
          iv: flattened.iv,
          recipients: [{}],
          tag: flattened.tag
        };
        if (flattened.aad) jwe2.aad = flattened.aad;
        if (flattened.protected) jwe2.protected = flattened.protected;
        if (flattened.unprotected) jwe2.unprotected = flattened.unprotected;
        if (flattened.encrypted_key) jwe2.recipients[0].encrypted_key = flattened.encrypted_key;
        if (flattened.header) jwe2.recipients[0].header = flattened.header;
        return jwe2;
      }
      let enc;
      for (let i = 0; i < this._recipients.length; i++) {
        const recipient = this._recipients[i];
        if (!is_disjoint_default(this._protectedHeader, this._unprotectedHeader, recipient.unprotectedHeader)) {
          throw new JWEInvalid("JWE Protected, JWE Shared Unprotected and JWE Per-Recipient Header Parameter names must be disjoint");
        }
        const joseHeader = __spreadValues(__spreadValues(__spreadValues({}, this._protectedHeader), this._unprotectedHeader), recipient.unprotectedHeader);
        const {
          alg
        } = joseHeader;
        if (typeof alg !== "string" || !alg) {
          throw new JWEInvalid('JWE "alg" (Algorithm) Header Parameter missing or invalid');
        }
        if (alg === "dir" || alg === "ECDH-ES") {
          throw new JWEInvalid('"dir" and "ECDH-ES" alg may only be used with a single recipient');
        }
        if (typeof joseHeader.enc !== "string" || !joseHeader.enc) {
          throw new JWEInvalid('JWE "enc" (Encryption Algorithm) Header Parameter missing or invalid');
        }
        if (!enc) {
          enc = joseHeader.enc;
        } else if (enc !== joseHeader.enc) {
          throw new JWEInvalid('JWE "enc" (Encryption Algorithm) Header Parameter must be the same for all recipients');
        }
        validate_crit_default(JWEInvalid, /* @__PURE__ */ new Map(), recipient.options.crit, this._protectedHeader, joseHeader);
        if (joseHeader.zip !== void 0) {
          throw new JOSENotSupported('JWE "zip" (Compression Algorithm) Header Parameter is not supported.');
        }
      }
      const cek = cek_default(enc);
      const jwe = {
        ciphertext: "",
        iv: "",
        recipients: [],
        tag: ""
      };
      for (let i = 0; i < this._recipients.length; i++) {
        const recipient = this._recipients[i];
        const target = {};
        jwe.recipients.push(target);
        const joseHeader = __spreadValues(__spreadValues(__spreadValues({}, this._protectedHeader), this._unprotectedHeader), recipient.unprotectedHeader);
        const p2c = joseHeader.alg.startsWith("PBES2") ? 2048 + i : void 0;
        if (i === 0) {
          const flattened = yield new FlattenedEncrypt(this._plaintext).setAdditionalAuthenticatedData(this._aad).setContentEncryptionKey(cek).setProtectedHeader(this._protectedHeader).setSharedUnprotectedHeader(this._unprotectedHeader).setUnprotectedHeader(recipient.unprotectedHeader).setKeyManagementParameters({
            p2c
          }).encrypt(recipient.key, __spreadProps(__spreadValues({}, recipient.options), {
            [unprotected]: true
          }));
          jwe.ciphertext = flattened.ciphertext;
          jwe.iv = flattened.iv;
          jwe.tag = flattened.tag;
          if (flattened.aad) jwe.aad = flattened.aad;
          if (flattened.protected) jwe.protected = flattened.protected;
          if (flattened.unprotected) jwe.unprotected = flattened.unprotected;
          target.encrypted_key = flattened.encrypted_key;
          if (flattened.header) target.header = flattened.header;
          continue;
        }
        const {
          encryptedKey,
          parameters
        } = yield encrypt_key_management_default(recipient.unprotectedHeader?.alg || this._protectedHeader?.alg || this._unprotectedHeader?.alg, enc, recipient.key, cek, {
          p2c
        });
        target.encrypted_key = encode(encryptedKey);
        if (recipient.unprotectedHeader || parameters) target.header = __spreadValues(__spreadValues({}, recipient.unprotectedHeader), parameters);
      }
      return jwe;
    });
  }
};

// node_modules/jose/dist/node/esm/runtime/verify.js
import * as crypto3 from "crypto";
import { promisify as promisify4 } from "util";

// node_modules/jose/dist/node/esm/runtime/dsa_digest.js
function dsaDigest(alg) {
  switch (alg) {
    case "PS256":
    case "RS256":
    case "ES256":
    case "ES256K":
      return "sha256";
    case "PS384":
    case "RS384":
    case "ES384":
      return "sha384";
    case "PS512":
    case "RS512":
    case "ES512":
      return "sha512";
    case "EdDSA":
      return void 0;
    default:
      throw new JOSENotSupported(`alg ${alg} is not supported either by JOSE or your javascript runtime`);
  }
}

// node_modules/jose/dist/node/esm/runtime/node_key.js
import { constants as constants2 } from "crypto";
var PSS = {
  padding: constants2.RSA_PKCS1_PSS_PADDING,
  saltLength: constants2.RSA_PSS_SALTLEN_DIGEST
};
var ecCurveAlgMap = /* @__PURE__ */ new Map([["ES256", "P-256"], ["ES256K", "secp256k1"], ["ES384", "P-384"], ["ES512", "P-521"]]);
function keyForCrypto(alg, key) {
  switch (alg) {
    case "EdDSA":
      if (!["ed25519", "ed448"].includes(key.asymmetricKeyType)) {
        throw new TypeError("Invalid key for this operation, its asymmetricKeyType must be ed25519 or ed448");
      }
      return key;
    case "RS256":
    case "RS384":
    case "RS512":
      if (key.asymmetricKeyType !== "rsa") {
        throw new TypeError("Invalid key for this operation, its asymmetricKeyType must be rsa");
      }
      check_key_length_default(key, alg);
      return key;
    case "PS256":
    case "PS384":
    case "PS512":
      if (key.asymmetricKeyType === "rsa-pss") {
        const {
          hashAlgorithm,
          mgf1HashAlgorithm,
          saltLength
        } = key.asymmetricKeyDetails;
        const length = parseInt(alg.slice(-3), 10);
        if (hashAlgorithm !== void 0 && (hashAlgorithm !== `sha${length}` || mgf1HashAlgorithm !== hashAlgorithm)) {
          throw new TypeError(`Invalid key for this operation, its RSA-PSS parameters do not meet the requirements of "alg" ${alg}`);
        }
        if (saltLength !== void 0 && saltLength > length >> 3) {
          throw new TypeError(`Invalid key for this operation, its RSA-PSS parameter saltLength does not meet the requirements of "alg" ${alg}`);
        }
      } else if (key.asymmetricKeyType !== "rsa") {
        throw new TypeError("Invalid key for this operation, its asymmetricKeyType must be rsa or rsa-pss");
      }
      check_key_length_default(key, alg);
      return __spreadValues({
        key
      }, PSS);
    case "ES256":
    case "ES256K":
    case "ES384":
    case "ES512": {
      if (key.asymmetricKeyType !== "ec") {
        throw new TypeError("Invalid key for this operation, its asymmetricKeyType must be ec");
      }
      const actual = get_named_curve_default(key);
      const expected = ecCurveAlgMap.get(alg);
      if (actual !== expected) {
        throw new TypeError(`Invalid key curve for the algorithm, its curve must be ${expected}, got ${actual}`);
      }
      return {
        dsaEncoding: "ieee-p1363",
        key
      };
    }
    default:
      throw new JOSENotSupported(`alg ${alg} is not supported either by JOSE or your javascript runtime`);
  }
}

// node_modules/jose/dist/node/esm/runtime/sign.js
import * as crypto2 from "crypto";
import { promisify as promisify3 } from "util";

// node_modules/jose/dist/node/esm/runtime/hmac_digest.js
function hmacDigest(alg) {
  switch (alg) {
    case "HS256":
      return "sha256";
    case "HS384":
      return "sha384";
    case "HS512":
      return "sha512";
    default:
      throw new JOSENotSupported(`alg ${alg} is not supported either by JOSE or your javascript runtime`);
  }
}

// node_modules/jose/dist/node/esm/runtime/get_sign_verify_key.js
import { KeyObject as KeyObject10, createSecretKey as createSecretKey2 } from "crypto";
function getSignVerifyKey(alg, key, usage) {
  if (key instanceof Uint8Array) {
    if (!alg.startsWith("HS")) {
      throw new TypeError(invalid_key_input_default(key, ...types3));
    }
    return createSecretKey2(key);
  }
  if (key instanceof KeyObject10) {
    return key;
  }
  if (isCryptoKey(key)) {
    checkSigCryptoKey(key, alg, usage);
    return KeyObject10.from(key);
  }
  throw new TypeError(invalid_key_input_default(key, ...types3, "Uint8Array"));
}

// node_modules/jose/dist/node/esm/runtime/sign.js
var oneShotSign = promisify3(crypto2.sign);
var sign2 = (alg, key, data) => __async(void 0, null, function* () {
  const keyObject = getSignVerifyKey(alg, key, "sign");
  if (alg.startsWith("HS")) {
    const hmac = crypto2.createHmac(hmacDigest(alg), keyObject);
    hmac.update(data);
    return hmac.digest();
  }
  return oneShotSign(dsaDigest(alg), data, keyForCrypto(alg, keyObject));
});
var sign_default = sign2;

// node_modules/jose/dist/node/esm/runtime/verify.js
var oneShotVerify = promisify4(crypto3.verify);
var verify2 = (alg, key, signature, data) => __async(void 0, null, function* () {
  const keyObject = getSignVerifyKey(alg, key, "verify");
  if (alg.startsWith("HS")) {
    const expected = yield sign_default(alg, keyObject, data);
    const actual = signature;
    try {
      return crypto3.timingSafeEqual(actual, expected);
    } catch {
      return false;
    }
  }
  const algorithm = dsaDigest(alg);
  const keyInput = keyForCrypto(alg, keyObject);
  try {
    return yield oneShotVerify(algorithm, data, keyInput, signature);
  } catch {
    return false;
  }
});
var verify_default = verify2;

// node_modules/jose/dist/node/esm/jws/flattened/verify.js
function flattenedVerify(jws, key, options) {
  return __async(this, null, function* () {
    if (!isObject(jws)) {
      throw new JWSInvalid("Flattened JWS must be an object");
    }
    if (jws.protected === void 0 && jws.header === void 0) {
      throw new JWSInvalid('Flattened JWS must have either of the "protected" or "header" members');
    }
    if (jws.protected !== void 0 && typeof jws.protected !== "string") {
      throw new JWSInvalid("JWS Protected Header incorrect type");
    }
    if (jws.payload === void 0) {
      throw new JWSInvalid("JWS Payload missing");
    }
    if (typeof jws.signature !== "string") {
      throw new JWSInvalid("JWS Signature missing or incorrect type");
    }
    if (jws.header !== void 0 && !isObject(jws.header)) {
      throw new JWSInvalid("JWS Unprotected Header incorrect type");
    }
    let parsedProt = {};
    if (jws.protected) {
      try {
        const protectedHeader = decode(jws.protected);
        parsedProt = JSON.parse(decoder.decode(protectedHeader));
      } catch {
        throw new JWSInvalid("JWS Protected Header is invalid");
      }
    }
    if (!is_disjoint_default(parsedProt, jws.header)) {
      throw new JWSInvalid("JWS Protected and JWS Unprotected Header Parameter names must be disjoint");
    }
    const joseHeader = __spreadValues(__spreadValues({}, parsedProt), jws.header);
    const extensions = validate_crit_default(JWSInvalid, /* @__PURE__ */ new Map([["b64", true]]), options?.crit, parsedProt, joseHeader);
    let b64 = true;
    if (extensions.has("b64")) {
      b64 = parsedProt.b64;
      if (typeof b64 !== "boolean") {
        throw new JWSInvalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
      }
    }
    const {
      alg
    } = joseHeader;
    if (typeof alg !== "string" || !alg) {
      throw new JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
    }
    const algorithms = options && validate_algorithms_default("algorithms", options.algorithms);
    if (algorithms && !algorithms.has(alg)) {
      throw new JOSEAlgNotAllowed('"alg" (Algorithm) Header Parameter value not allowed');
    }
    if (b64) {
      if (typeof jws.payload !== "string") {
        throw new JWSInvalid("JWS Payload must be a string");
      }
    } else if (typeof jws.payload !== "string" && !(jws.payload instanceof Uint8Array)) {
      throw new JWSInvalid("JWS Payload must be a string or an Uint8Array instance");
    }
    let resolvedKey = false;
    if (typeof key === "function") {
      key = yield key(parsedProt, jws);
      resolvedKey = true;
    }
    check_key_type_default(alg, key, "verify");
    const data = concat(encoder.encode(jws.protected ?? ""), encoder.encode("."), typeof jws.payload === "string" ? encoder.encode(jws.payload) : jws.payload);
    let signature;
    try {
      signature = decode(jws.signature);
    } catch {
      throw new JWSInvalid("Failed to base64url decode the signature");
    }
    const verified = yield verify_default(alg, key, signature, data);
    if (!verified) {
      throw new JWSSignatureVerificationFailed();
    }
    let payload;
    if (b64) {
      try {
        payload = decode(jws.payload);
      } catch {
        throw new JWSInvalid("Failed to base64url decode the payload");
      }
    } else if (typeof jws.payload === "string") {
      payload = encoder.encode(jws.payload);
    } else {
      payload = jws.payload;
    }
    const result = {
      payload
    };
    if (jws.protected !== void 0) {
      result.protectedHeader = parsedProt;
    }
    if (jws.header !== void 0) {
      result.unprotectedHeader = jws.header;
    }
    if (resolvedKey) {
      return __spreadProps(__spreadValues({}, result), {
        key
      });
    }
    return result;
  });
}

// node_modules/jose/dist/node/esm/jws/compact/verify.js
function compactVerify(jws, key, options) {
  return __async(this, null, function* () {
    if (jws instanceof Uint8Array) {
      jws = decoder.decode(jws);
    }
    if (typeof jws !== "string") {
      throw new JWSInvalid("Compact JWS must be a string or Uint8Array");
    }
    const {
      0: protectedHeader,
      1: payload,
      2: signature,
      length
    } = jws.split(".");
    if (length !== 3) {
      throw new JWSInvalid("Invalid Compact JWS");
    }
    const verified = yield flattenedVerify({
      payload,
      protected: protectedHeader,
      signature
    }, key, options);
    const result = {
      payload: verified.payload,
      protectedHeader: verified.protectedHeader
    };
    if (typeof key === "function") {
      return __spreadProps(__spreadValues({}, result), {
        key: verified.key
      });
    }
    return result;
  });
}

// node_modules/jose/dist/node/esm/jws/general/verify.js
function generalVerify(jws, key, options) {
  return __async(this, null, function* () {
    if (!isObject(jws)) {
      throw new JWSInvalid("General JWS must be an object");
    }
    if (!Array.isArray(jws.signatures) || !jws.signatures.every(isObject)) {
      throw new JWSInvalid("JWS Signatures missing or incorrect type");
    }
    for (const signature of jws.signatures) {
      try {
        return yield flattenedVerify({
          header: signature.header,
          payload: jws.payload,
          protected: signature.protected,
          signature: signature.signature
        }, key, options);
      } catch {
      }
    }
    throw new JWSSignatureVerificationFailed();
  });
}

// node_modules/jose/dist/node/esm/lib/epoch.js
var epoch_default = (date) => Math.floor(date.getTime() / 1e3);

// node_modules/jose/dist/node/esm/lib/secs.js
var minute = 60;
var hour = minute * 60;
var day = hour * 24;
var week = day * 7;
var year = day * 365.25;
var REGEX = /^(\+|\-)? ?(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?$/i;
var secs_default = (str) => {
  const matched = REGEX.exec(str);
  if (!matched || matched[4] && matched[1]) {
    throw new TypeError("Invalid time period format");
  }
  const value = parseFloat(matched[2]);
  const unit = matched[3].toLowerCase();
  let numericDate;
  switch (unit) {
    case "sec":
    case "secs":
    case "second":
    case "seconds":
    case "s":
      numericDate = Math.round(value);
      break;
    case "minute":
    case "minutes":
    case "min":
    case "mins":
    case "m":
      numericDate = Math.round(value * minute);
      break;
    case "hour":
    case "hours":
    case "hr":
    case "hrs":
    case "h":
      numericDate = Math.round(value * hour);
      break;
    case "day":
    case "days":
    case "d":
      numericDate = Math.round(value * day);
      break;
    case "week":
    case "weeks":
    case "w":
      numericDate = Math.round(value * week);
      break;
    default:
      numericDate = Math.round(value * year);
      break;
  }
  if (matched[1] === "-" || matched[4] === "ago") {
    return -numericDate;
  }
  return numericDate;
};

// node_modules/jose/dist/node/esm/lib/jwt_claims_set.js
var normalizeTyp = (value) => value.toLowerCase().replace(/^application\//, "");
var checkAudiencePresence = (audPayload, audOption) => {
  if (typeof audPayload === "string") {
    return audOption.includes(audPayload);
  }
  if (Array.isArray(audPayload)) {
    return audOption.some(Set.prototype.has.bind(new Set(audPayload)));
  }
  return false;
};
var jwt_claims_set_default = (protectedHeader, encodedPayload, options = {}) => {
  let payload;
  try {
    payload = JSON.parse(decoder.decode(encodedPayload));
  } catch {
  }
  if (!isObject(payload)) {
    throw new JWTInvalid("JWT Claims Set must be a top-level JSON object");
  }
  const {
    typ
  } = options;
  if (typ && (typeof protectedHeader.typ !== "string" || normalizeTyp(protectedHeader.typ) !== normalizeTyp(typ))) {
    throw new JWTClaimValidationFailed('unexpected "typ" JWT header value', payload, "typ", "check_failed");
  }
  const {
    requiredClaims = [],
    issuer,
    subject,
    audience,
    maxTokenAge
  } = options;
  const presenceCheck = [...requiredClaims];
  if (maxTokenAge !== void 0) presenceCheck.push("iat");
  if (audience !== void 0) presenceCheck.push("aud");
  if (subject !== void 0) presenceCheck.push("sub");
  if (issuer !== void 0) presenceCheck.push("iss");
  for (const claim of new Set(presenceCheck.reverse())) {
    if (!(claim in payload)) {
      throw new JWTClaimValidationFailed(`missing required "${claim}" claim`, payload, claim, "missing");
    }
  }
  if (issuer && !(Array.isArray(issuer) ? issuer : [issuer]).includes(payload.iss)) {
    throw new JWTClaimValidationFailed('unexpected "iss" claim value', payload, "iss", "check_failed");
  }
  if (subject && payload.sub !== subject) {
    throw new JWTClaimValidationFailed('unexpected "sub" claim value', payload, "sub", "check_failed");
  }
  if (audience && !checkAudiencePresence(payload.aud, typeof audience === "string" ? [audience] : audience)) {
    throw new JWTClaimValidationFailed('unexpected "aud" claim value', payload, "aud", "check_failed");
  }
  let tolerance;
  switch (typeof options.clockTolerance) {
    case "string":
      tolerance = secs_default(options.clockTolerance);
      break;
    case "number":
      tolerance = options.clockTolerance;
      break;
    case "undefined":
      tolerance = 0;
      break;
    default:
      throw new TypeError("Invalid clockTolerance option type");
  }
  const {
    currentDate
  } = options;
  const now = epoch_default(currentDate || /* @__PURE__ */ new Date());
  if ((payload.iat !== void 0 || maxTokenAge) && typeof payload.iat !== "number") {
    throw new JWTClaimValidationFailed('"iat" claim must be a number', payload, "iat", "invalid");
  }
  if (payload.nbf !== void 0) {
    if (typeof payload.nbf !== "number") {
      throw new JWTClaimValidationFailed('"nbf" claim must be a number', payload, "nbf", "invalid");
    }
    if (payload.nbf > now + tolerance) {
      throw new JWTClaimValidationFailed('"nbf" claim timestamp check failed', payload, "nbf", "check_failed");
    }
  }
  if (payload.exp !== void 0) {
    if (typeof payload.exp !== "number") {
      throw new JWTClaimValidationFailed('"exp" claim must be a number', payload, "exp", "invalid");
    }
    if (payload.exp <= now - tolerance) {
      throw new JWTExpired('"exp" claim timestamp check failed', payload, "exp", "check_failed");
    }
  }
  if (maxTokenAge) {
    const age = now - payload.iat;
    const max = typeof maxTokenAge === "number" ? maxTokenAge : secs_default(maxTokenAge);
    if (age - tolerance > max) {
      throw new JWTExpired('"iat" claim timestamp check failed (too far in the past)', payload, "iat", "check_failed");
    }
    if (age < 0 - tolerance) {
      throw new JWTClaimValidationFailed('"iat" claim timestamp check failed (it should be in the past)', payload, "iat", "check_failed");
    }
  }
  return payload;
};

// node_modules/jose/dist/node/esm/jwt/verify.js
function jwtVerify(jwt, key, options) {
  return __async(this, null, function* () {
    const verified = yield compactVerify(jwt, key, options);
    if (verified.protectedHeader.crit?.includes("b64") && verified.protectedHeader.b64 === false) {
      throw new JWTInvalid("JWTs MUST NOT use unencoded payload");
    }
    const payload = jwt_claims_set_default(verified.protectedHeader, verified.payload, options);
    const result = {
      payload,
      protectedHeader: verified.protectedHeader
    };
    if (typeof key === "function") {
      return __spreadProps(__spreadValues({}, result), {
        key: verified.key
      });
    }
    return result;
  });
}

// node_modules/jose/dist/node/esm/jwt/decrypt.js
function jwtDecrypt(jwt, key, options) {
  return __async(this, null, function* () {
    const decrypted = yield compactDecrypt(jwt, key, options);
    const payload = jwt_claims_set_default(decrypted.protectedHeader, decrypted.plaintext, options);
    const {
      protectedHeader
    } = decrypted;
    if (protectedHeader.iss !== void 0 && protectedHeader.iss !== payload.iss) {
      throw new JWTClaimValidationFailed('replicated "iss" claim header parameter mismatch', payload, "iss", "mismatch");
    }
    if (protectedHeader.sub !== void 0 && protectedHeader.sub !== payload.sub) {
      throw new JWTClaimValidationFailed('replicated "sub" claim header parameter mismatch', payload, "sub", "mismatch");
    }
    if (protectedHeader.aud !== void 0 && JSON.stringify(protectedHeader.aud) !== JSON.stringify(payload.aud)) {
      throw new JWTClaimValidationFailed('replicated "aud" claim header parameter mismatch', payload, "aud", "mismatch");
    }
    const result = {
      payload,
      protectedHeader
    };
    if (typeof key === "function") {
      return __spreadProps(__spreadValues({}, result), {
        key: decrypted.key
      });
    }
    return result;
  });
}

// node_modules/jose/dist/node/esm/jwe/compact/encrypt.js
var CompactEncrypt = class {
  _flattened;
  constructor(plaintext) {
    this._flattened = new FlattenedEncrypt(plaintext);
  }
  setContentEncryptionKey(cek) {
    this._flattened.setContentEncryptionKey(cek);
    return this;
  }
  setInitializationVector(iv) {
    this._flattened.setInitializationVector(iv);
    return this;
  }
  setProtectedHeader(protectedHeader) {
    this._flattened.setProtectedHeader(protectedHeader);
    return this;
  }
  setKeyManagementParameters(parameters) {
    this._flattened.setKeyManagementParameters(parameters);
    return this;
  }
  encrypt(key, options) {
    return __async(this, null, function* () {
      const jwe = yield this._flattened.encrypt(key, options);
      return [jwe.protected, jwe.encrypted_key, jwe.iv, jwe.ciphertext, jwe.tag].join(".");
    });
  }
};

// node_modules/jose/dist/node/esm/jws/flattened/sign.js
var FlattenedSign = class {
  _payload;
  _protectedHeader;
  _unprotectedHeader;
  constructor(payload) {
    if (!(payload instanceof Uint8Array)) {
      throw new TypeError("payload must be an instance of Uint8Array");
    }
    this._payload = payload;
  }
  setProtectedHeader(protectedHeader) {
    if (this._protectedHeader) {
      throw new TypeError("setProtectedHeader can only be called once");
    }
    this._protectedHeader = protectedHeader;
    return this;
  }
  setUnprotectedHeader(unprotectedHeader) {
    if (this._unprotectedHeader) {
      throw new TypeError("setUnprotectedHeader can only be called once");
    }
    this._unprotectedHeader = unprotectedHeader;
    return this;
  }
  sign(key, options) {
    return __async(this, null, function* () {
      if (!this._protectedHeader && !this._unprotectedHeader) {
        throw new JWSInvalid("either setProtectedHeader or setUnprotectedHeader must be called before #sign()");
      }
      if (!is_disjoint_default(this._protectedHeader, this._unprotectedHeader)) {
        throw new JWSInvalid("JWS Protected and JWS Unprotected Header Parameter names must be disjoint");
      }
      const joseHeader = __spreadValues(__spreadValues({}, this._protectedHeader), this._unprotectedHeader);
      const extensions = validate_crit_default(JWSInvalid, /* @__PURE__ */ new Map([["b64", true]]), options?.crit, this._protectedHeader, joseHeader);
      let b64 = true;
      if (extensions.has("b64")) {
        b64 = this._protectedHeader.b64;
        if (typeof b64 !== "boolean") {
          throw new JWSInvalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
        }
      }
      const {
        alg
      } = joseHeader;
      if (typeof alg !== "string" || !alg) {
        throw new JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
      }
      check_key_type_default(alg, key, "sign");
      let payload = this._payload;
      if (b64) {
        payload = encoder.encode(encode(payload));
      }
      let protectedHeader;
      if (this._protectedHeader) {
        protectedHeader = encoder.encode(encode(JSON.stringify(this._protectedHeader)));
      } else {
        protectedHeader = encoder.encode("");
      }
      const data = concat(protectedHeader, encoder.encode("."), payload);
      const signature = yield sign_default(alg, key, data);
      const jws = {
        signature: encode(signature),
        payload: ""
      };
      if (b64) {
        jws.payload = decoder.decode(payload);
      }
      if (this._unprotectedHeader) {
        jws.header = this._unprotectedHeader;
      }
      if (this._protectedHeader) {
        jws.protected = decoder.decode(protectedHeader);
      }
      return jws;
    });
  }
};

// node_modules/jose/dist/node/esm/jws/compact/sign.js
var CompactSign = class {
  _flattened;
  constructor(payload) {
    this._flattened = new FlattenedSign(payload);
  }
  setProtectedHeader(protectedHeader) {
    this._flattened.setProtectedHeader(protectedHeader);
    return this;
  }
  sign(key, options) {
    return __async(this, null, function* () {
      const jws = yield this._flattened.sign(key, options);
      if (jws.payload === void 0) {
        throw new TypeError("use the flattened module for creating JWS with b64: false");
      }
      return `${jws.protected}.${jws.payload}.${jws.signature}`;
    });
  }
};

// node_modules/jose/dist/node/esm/jws/general/sign.js
var IndividualSignature = class {
  parent;
  protectedHeader;
  unprotectedHeader;
  options;
  key;
  constructor(sig, key, options) {
    this.parent = sig;
    this.key = key;
    this.options = options;
  }
  setProtectedHeader(protectedHeader) {
    if (this.protectedHeader) {
      throw new TypeError("setProtectedHeader can only be called once");
    }
    this.protectedHeader = protectedHeader;
    return this;
  }
  setUnprotectedHeader(unprotectedHeader) {
    if (this.unprotectedHeader) {
      throw new TypeError("setUnprotectedHeader can only be called once");
    }
    this.unprotectedHeader = unprotectedHeader;
    return this;
  }
  addSignature(...args) {
    return this.parent.addSignature(...args);
  }
  sign(...args) {
    return this.parent.sign(...args);
  }
  done() {
    return this.parent;
  }
};
var GeneralSign = class {
  _payload;
  _signatures = [];
  constructor(payload) {
    this._payload = payload;
  }
  addSignature(key, options) {
    const signature = new IndividualSignature(this, key, options);
    this._signatures.push(signature);
    return signature;
  }
  sign() {
    return __async(this, null, function* () {
      if (!this._signatures.length) {
        throw new JWSInvalid("at least one signature must be added");
      }
      const jws = {
        signatures: [],
        payload: ""
      };
      for (let i = 0; i < this._signatures.length; i++) {
        const signature = this._signatures[i];
        const flattened = new FlattenedSign(this._payload);
        flattened.setProtectedHeader(signature.protectedHeader);
        flattened.setUnprotectedHeader(signature.unprotectedHeader);
        const _a = yield flattened.sign(signature.key, signature.options), {
          payload
        } = _a, rest = __objRest(_a, [
          "payload"
        ]);
        if (i === 0) {
          jws.payload = payload;
        } else if (jws.payload !== payload) {
          throw new JWSInvalid("inconsistent use of JWS Unencoded Payload (RFC7797)");
        }
        jws.signatures.push(rest);
      }
      return jws;
    });
  }
};

// node_modules/jose/dist/node/esm/jwt/produce.js
function validateInput(label, input) {
  if (!Number.isFinite(input)) {
    throw new TypeError(`Invalid ${label} input`);
  }
  return input;
}
var ProduceJWT = class {
  _payload;
  constructor(payload = {}) {
    if (!isObject(payload)) {
      throw new TypeError("JWT Claims Set MUST be an object");
    }
    this._payload = payload;
  }
  setIssuer(issuer) {
    this._payload = __spreadProps(__spreadValues({}, this._payload), {
      iss: issuer
    });
    return this;
  }
  setSubject(subject) {
    this._payload = __spreadProps(__spreadValues({}, this._payload), {
      sub: subject
    });
    return this;
  }
  setAudience(audience) {
    this._payload = __spreadProps(__spreadValues({}, this._payload), {
      aud: audience
    });
    return this;
  }
  setJti(jwtId) {
    this._payload = __spreadProps(__spreadValues({}, this._payload), {
      jti: jwtId
    });
    return this;
  }
  setNotBefore(input) {
    if (typeof input === "number") {
      this._payload = __spreadProps(__spreadValues({}, this._payload), {
        nbf: validateInput("setNotBefore", input)
      });
    } else if (input instanceof Date) {
      this._payload = __spreadProps(__spreadValues({}, this._payload), {
        nbf: validateInput("setNotBefore", epoch_default(input))
      });
    } else {
      this._payload = __spreadProps(__spreadValues({}, this._payload), {
        nbf: epoch_default(/* @__PURE__ */ new Date()) + secs_default(input)
      });
    }
    return this;
  }
  setExpirationTime(input) {
    if (typeof input === "number") {
      this._payload = __spreadProps(__spreadValues({}, this._payload), {
        exp: validateInput("setExpirationTime", input)
      });
    } else if (input instanceof Date) {
      this._payload = __spreadProps(__spreadValues({}, this._payload), {
        exp: validateInput("setExpirationTime", epoch_default(input))
      });
    } else {
      this._payload = __spreadProps(__spreadValues({}, this._payload), {
        exp: epoch_default(/* @__PURE__ */ new Date()) + secs_default(input)
      });
    }
    return this;
  }
  setIssuedAt(input) {
    if (typeof input === "undefined") {
      this._payload = __spreadProps(__spreadValues({}, this._payload), {
        iat: epoch_default(/* @__PURE__ */ new Date())
      });
    } else if (input instanceof Date) {
      this._payload = __spreadProps(__spreadValues({}, this._payload), {
        iat: validateInput("setIssuedAt", epoch_default(input))
      });
    } else if (typeof input === "string") {
      this._payload = __spreadProps(__spreadValues({}, this._payload), {
        iat: validateInput("setIssuedAt", epoch_default(/* @__PURE__ */ new Date()) + secs_default(input))
      });
    } else {
      this._payload = __spreadProps(__spreadValues({}, this._payload), {
        iat: validateInput("setIssuedAt", input)
      });
    }
    return this;
  }
};

// node_modules/jose/dist/node/esm/jwt/sign.js
var SignJWT = class extends ProduceJWT {
  _protectedHeader;
  setProtectedHeader(protectedHeader) {
    this._protectedHeader = protectedHeader;
    return this;
  }
  sign(key, options) {
    return __async(this, null, function* () {
      const sig = new CompactSign(encoder.encode(JSON.stringify(this._payload)));
      sig.setProtectedHeader(this._protectedHeader);
      if (Array.isArray(this._protectedHeader?.crit) && this._protectedHeader.crit.includes("b64") && this._protectedHeader.b64 === false) {
        throw new JWTInvalid("JWTs MUST NOT use unencoded payload");
      }
      return sig.sign(key, options);
    });
  }
};

// node_modules/jose/dist/node/esm/jwt/encrypt.js
var EncryptJWT = class extends ProduceJWT {
  _cek;
  _iv;
  _keyManagementParameters;
  _protectedHeader;
  _replicateIssuerAsHeader;
  _replicateSubjectAsHeader;
  _replicateAudienceAsHeader;
  setProtectedHeader(protectedHeader) {
    if (this._protectedHeader) {
      throw new TypeError("setProtectedHeader can only be called once");
    }
    this._protectedHeader = protectedHeader;
    return this;
  }
  setKeyManagementParameters(parameters) {
    if (this._keyManagementParameters) {
      throw new TypeError("setKeyManagementParameters can only be called once");
    }
    this._keyManagementParameters = parameters;
    return this;
  }
  setContentEncryptionKey(cek) {
    if (this._cek) {
      throw new TypeError("setContentEncryptionKey can only be called once");
    }
    this._cek = cek;
    return this;
  }
  setInitializationVector(iv) {
    if (this._iv) {
      throw new TypeError("setInitializationVector can only be called once");
    }
    this._iv = iv;
    return this;
  }
  replicateIssuerAsHeader() {
    this._replicateIssuerAsHeader = true;
    return this;
  }
  replicateSubjectAsHeader() {
    this._replicateSubjectAsHeader = true;
    return this;
  }
  replicateAudienceAsHeader() {
    this._replicateAudienceAsHeader = true;
    return this;
  }
  encrypt(key, options) {
    return __async(this, null, function* () {
      const enc = new CompactEncrypt(encoder.encode(JSON.stringify(this._payload)));
      if (this._replicateIssuerAsHeader) {
        this._protectedHeader = __spreadProps(__spreadValues({}, this._protectedHeader), {
          iss: this._payload.iss
        });
      }
      if (this._replicateSubjectAsHeader) {
        this._protectedHeader = __spreadProps(__spreadValues({}, this._protectedHeader), {
          sub: this._payload.sub
        });
      }
      if (this._replicateAudienceAsHeader) {
        this._protectedHeader = __spreadProps(__spreadValues({}, this._protectedHeader), {
          aud: this._payload.aud
        });
      }
      enc.setProtectedHeader(this._protectedHeader);
      if (this._iv) {
        enc.setInitializationVector(this._iv);
      }
      if (this._cek) {
        enc.setContentEncryptionKey(this._cek);
      }
      if (this._keyManagementParameters) {
        enc.setKeyManagementParameters(this._keyManagementParameters);
      }
      return enc.encrypt(key, options);
    });
  }
};

// node_modules/jose/dist/node/esm/jwk/thumbprint.js
var check = (value, description) => {
  if (typeof value !== "string" || !value) {
    throw new JWKInvalid(`${description} missing or invalid`);
  }
};
function calculateJwkThumbprint(jwk, digestAlgorithm) {
  return __async(this, null, function* () {
    if (!isObject(jwk)) {
      throw new TypeError("JWK must be an object");
    }
    digestAlgorithm ??= "sha256";
    if (digestAlgorithm !== "sha256" && digestAlgorithm !== "sha384" && digestAlgorithm !== "sha512") {
      throw new TypeError('digestAlgorithm must one of "sha256", "sha384", or "sha512"');
    }
    let components;
    switch (jwk.kty) {
      case "EC":
        check(jwk.crv, '"crv" (Curve) Parameter');
        check(jwk.x, '"x" (X Coordinate) Parameter');
        check(jwk.y, '"y" (Y Coordinate) Parameter');
        components = {
          crv: jwk.crv,
          kty: jwk.kty,
          x: jwk.x,
          y: jwk.y
        };
        break;
      case "OKP":
        check(jwk.crv, '"crv" (Subtype of Key Pair) Parameter');
        check(jwk.x, '"x" (Public Key) Parameter');
        components = {
          crv: jwk.crv,
          kty: jwk.kty,
          x: jwk.x
        };
        break;
      case "RSA":
        check(jwk.e, '"e" (Exponent) Parameter');
        check(jwk.n, '"n" (Modulus) Parameter');
        components = {
          e: jwk.e,
          kty: jwk.kty,
          n: jwk.n
        };
        break;
      case "oct":
        check(jwk.k, '"k" (Key Value) Parameter');
        components = {
          k: jwk.k,
          kty: jwk.kty
        };
        break;
      default:
        throw new JOSENotSupported('"kty" (Key Type) Parameter missing or unsupported');
    }
    const data = encoder.encode(JSON.stringify(components));
    return encode(yield digest_default(digestAlgorithm, data));
  });
}
function calculateJwkThumbprintUri(jwk, digestAlgorithm) {
  return __async(this, null, function* () {
    digestAlgorithm ??= "sha256";
    const thumbprint = yield calculateJwkThumbprint(jwk, digestAlgorithm);
    return `urn:ietf:params:oauth:jwk-thumbprint:sha-${digestAlgorithm.slice(-3)}:${thumbprint}`;
  });
}

// node_modules/jose/dist/node/esm/jwk/embedded.js
function EmbeddedJWK(protectedHeader, token) {
  return __async(this, null, function* () {
    const joseHeader = __spreadValues(__spreadValues({}, protectedHeader), token?.header);
    if (!isObject(joseHeader.jwk)) {
      throw new JWSInvalid('"jwk" (JSON Web Key) Header Parameter must be a JSON object');
    }
    const key = yield importJWK(__spreadProps(__spreadValues({}, joseHeader.jwk), {
      ext: true
    }), joseHeader.alg);
    if (key instanceof Uint8Array || key.type !== "public") {
      throw new JWSInvalid('"jwk" (JSON Web Key) Header Parameter must be a public key');
    }
    return key;
  });
}

// node_modules/jose/dist/node/esm/jwks/local.js
function getKtyFromAlg(alg) {
  switch (typeof alg === "string" && alg.slice(0, 2)) {
    case "RS":
    case "PS":
      return "RSA";
    case "ES":
      return "EC";
    case "Ed":
      return "OKP";
    default:
      throw new JOSENotSupported('Unsupported "alg" value for a JSON Web Key Set');
  }
}
function isJWKSLike(jwks) {
  return jwks && typeof jwks === "object" && Array.isArray(jwks.keys) && jwks.keys.every(isJWKLike);
}
function isJWKLike(key) {
  return isObject(key);
}
function clone(obj) {
  if (typeof structuredClone === "function") {
    return structuredClone(obj);
  }
  return JSON.parse(JSON.stringify(obj));
}
var LocalJWKSet = class {
  _jwks;
  _cached = /* @__PURE__ */ new WeakMap();
  constructor(jwks) {
    if (!isJWKSLike(jwks)) {
      throw new JWKSInvalid("JSON Web Key Set malformed");
    }
    this._jwks = clone(jwks);
  }
  getKey(protectedHeader, token) {
    return __async(this, null, function* () {
      const {
        alg,
        kid
      } = __spreadValues(__spreadValues({}, protectedHeader), token?.header);
      const kty = getKtyFromAlg(alg);
      const candidates = this._jwks.keys.filter((jwk2) => {
        let candidate = kty === jwk2.kty;
        if (candidate && typeof kid === "string") {
          candidate = kid === jwk2.kid;
        }
        if (candidate && typeof jwk2.alg === "string") {
          candidate = alg === jwk2.alg;
        }
        if (candidate && typeof jwk2.use === "string") {
          candidate = jwk2.use === "sig";
        }
        if (candidate && Array.isArray(jwk2.key_ops)) {
          candidate = jwk2.key_ops.includes("verify");
        }
        if (candidate && alg === "EdDSA") {
          candidate = jwk2.crv === "Ed25519" || jwk2.crv === "Ed448";
        }
        if (candidate) {
          switch (alg) {
            case "ES256":
              candidate = jwk2.crv === "P-256";
              break;
            case "ES256K":
              candidate = jwk2.crv === "secp256k1";
              break;
            case "ES384":
              candidate = jwk2.crv === "P-384";
              break;
            case "ES512":
              candidate = jwk2.crv === "P-521";
              break;
          }
        }
        return candidate;
      });
      const {
        0: jwk,
        length
      } = candidates;
      if (length === 0) {
        throw new JWKSNoMatchingKey();
      }
      if (length !== 1) {
        const error = new JWKSMultipleMatchingKeys();
        const {
          _cached
        } = this;
        error[Symbol.asyncIterator] = function() {
          return __asyncGenerator(this, null, function* () {
            for (const jwk2 of candidates) {
              try {
                yield yield new __await(importWithAlgCache(_cached, jwk2, alg));
              } catch {
              }
            }
          });
        };
        throw error;
      }
      return importWithAlgCache(this._cached, jwk, alg);
    });
  }
};
function importWithAlgCache(cache, jwk, alg) {
  return __async(this, null, function* () {
    const cached = cache.get(jwk) || cache.set(jwk, {}).get(jwk);
    if (cached[alg] === void 0) {
      const key = yield importJWK(__spreadProps(__spreadValues({}, jwk), {
        ext: true
      }), alg);
      if (key instanceof Uint8Array || key.type !== "public") {
        throw new JWKSInvalid("JSON Web Key Set members must be public keys");
      }
      cached[alg] = key;
    }
    return cached[alg];
  });
}
function createLocalJWKSet(jwks) {
  const set = new LocalJWKSet(jwks);
  const localJWKSet = (protectedHeader, token) => __async(this, null, function* () {
    return set.getKey(protectedHeader, token);
  });
  Object.defineProperties(localJWKSet, {
    jwks: {
      value: () => clone(set._jwks),
      enumerable: true,
      configurable: false,
      writable: false
    }
  });
  return localJWKSet;
}

// node_modules/jose/dist/node/esm/runtime/fetch_jwks.js
import * as http from "http";
import * as https from "https";
import { once } from "events";
var fetchJwks = (url, timeout, options) => __async(void 0, null, function* () {
  let get3;
  switch (url.protocol) {
    case "https:":
      get3 = https.get;
      break;
    case "http:":
      get3 = http.get;
      break;
    default:
      throw new TypeError("Unsupported URL protocol.");
  }
  const {
    agent,
    headers
  } = options;
  const req = get3(url.href, {
    agent,
    timeout,
    headers
  });
  const [response] = yield Promise.race([once(req, "response"), once(req, "timeout")]);
  if (!response) {
    req.destroy();
    throw new JWKSTimeout();
  }
  if (response.statusCode !== 200) {
    throw new JOSEError("Expected 200 OK from the JSON Web Key Set HTTP response");
  }
  const parts = [];
  try {
    for (var iter = __forAwait(response), more, temp, error; more = !(temp = yield iter.next()).done; more = false) {
      const part = temp.value;
      parts.push(part);
    }
  } catch (temp) {
    error = [temp];
  } finally {
    try {
      more && (temp = iter.return) && (yield temp.call(iter));
    } finally {
      if (error)
        throw error[0];
    }
  }
  try {
    return JSON.parse(decoder.decode(concat(...parts)));
  } catch {
    throw new JOSEError("Failed to parse the JSON Web Key Set HTTP response as JSON");
  }
});
var fetch_jwks_default = fetchJwks;

// node_modules/jose/dist/node/esm/jwks/remote.js
function isCloudflareWorkers() {
  return typeof WebSocketPair !== "undefined" || typeof navigator !== "undefined" && navigator.userAgent === "Cloudflare-Workers" || typeof EdgeRuntime !== "undefined" && EdgeRuntime === "vercel";
}
var USER_AGENT;
if (typeof navigator === "undefined" || !navigator.userAgent?.startsWith?.("Mozilla/5.0 ")) {
  const NAME = "jose";
  const VERSION = "v5.6.3";
  USER_AGENT = `${NAME}/${VERSION}`;
}
var experimental_jwksCache = Symbol();
function isFreshJwksCache(input, cacheMaxAge) {
  if (typeof input !== "object" || input === null) {
    return false;
  }
  if (!("uat" in input) || typeof input.uat !== "number" || Date.now() - input.uat >= cacheMaxAge) {
    return false;
  }
  if (!("jwks" in input) || !isObject(input.jwks) || !Array.isArray(input.jwks.keys) || !Array.prototype.every.call(input.jwks.keys, isObject)) {
    return false;
  }
  return true;
}
var RemoteJWKSet = class {
  _url;
  _timeoutDuration;
  _cooldownDuration;
  _cacheMaxAge;
  _jwksTimestamp;
  _pendingFetch;
  _options;
  _local;
  _cache;
  constructor(url, options) {
    if (!(url instanceof URL)) {
      throw new TypeError("url must be an instance of URL");
    }
    this._url = new URL(url.href);
    this._options = {
      agent: options?.agent,
      headers: options?.headers
    };
    this._timeoutDuration = typeof options?.timeoutDuration === "number" ? options?.timeoutDuration : 5e3;
    this._cooldownDuration = typeof options?.cooldownDuration === "number" ? options?.cooldownDuration : 3e4;
    this._cacheMaxAge = typeof options?.cacheMaxAge === "number" ? options?.cacheMaxAge : 6e5;
    if (options?.[experimental_jwksCache] !== void 0) {
      this._cache = options?.[experimental_jwksCache];
      if (isFreshJwksCache(options?.[experimental_jwksCache], this._cacheMaxAge)) {
        this._jwksTimestamp = this._cache.uat;
        this._local = createLocalJWKSet(this._cache.jwks);
      }
    }
  }
  coolingDown() {
    return typeof this._jwksTimestamp === "number" ? Date.now() < this._jwksTimestamp + this._cooldownDuration : false;
  }
  fresh() {
    return typeof this._jwksTimestamp === "number" ? Date.now() < this._jwksTimestamp + this._cacheMaxAge : false;
  }
  getKey(protectedHeader, token) {
    return __async(this, null, function* () {
      if (!this._local || !this.fresh()) {
        yield this.reload();
      }
      try {
        return yield this._local(protectedHeader, token);
      } catch (err) {
        if (err instanceof JWKSNoMatchingKey) {
          if (this.coolingDown() === false) {
            yield this.reload();
            return this._local(protectedHeader, token);
          }
        }
        throw err;
      }
    });
  }
  reload() {
    return __async(this, null, function* () {
      if (this._pendingFetch && isCloudflareWorkers()) {
        this._pendingFetch = void 0;
      }
      const headers = new Headers(this._options.headers);
      if (USER_AGENT && !headers.has("User-Agent")) {
        headers.set("User-Agent", USER_AGENT);
        this._options.headers = Object.fromEntries(headers.entries());
      }
      this._pendingFetch ||= fetch_jwks_default(this._url, this._timeoutDuration, this._options).then((json) => {
        this._local = createLocalJWKSet(json);
        if (this._cache) {
          this._cache.uat = Date.now();
          this._cache.jwks = json;
        }
        this._jwksTimestamp = Date.now();
        this._pendingFetch = void 0;
      }).catch((err) => {
        this._pendingFetch = void 0;
        throw err;
      });
      yield this._pendingFetch;
    });
  }
};
function createRemoteJWKSet(url, options) {
  const set = new RemoteJWKSet(url, options);
  const remoteJWKSet = (protectedHeader, token) => __async(this, null, function* () {
    return set.getKey(protectedHeader, token);
  });
  Object.defineProperties(remoteJWKSet, {
    coolingDown: {
      get: () => set.coolingDown(),
      enumerable: true,
      configurable: false
    },
    fresh: {
      get: () => set.fresh(),
      enumerable: true,
      configurable: false
    },
    reload: {
      value: () => set.reload(),
      enumerable: true,
      configurable: false,
      writable: false
    },
    reloading: {
      get: () => !!set._pendingFetch,
      enumerable: true,
      configurable: false
    },
    jwks: {
      value: () => set._local?.jwks(),
      enumerable: true,
      configurable: false,
      writable: false
    }
  });
  return remoteJWKSet;
}

// node_modules/jose/dist/node/esm/jwt/unsecured.js
var UnsecuredJWT = class extends ProduceJWT {
  encode() {
    const header = encode(JSON.stringify({
      alg: "none"
    }));
    const payload = encode(JSON.stringify(this._payload));
    return `${header}.${payload}.`;
  }
  static decode(jwt, options) {
    if (typeof jwt !== "string") {
      throw new JWTInvalid("Unsecured JWT must be a string");
    }
    const {
      0: encodedHeader,
      1: encodedPayload,
      2: signature,
      length
    } = jwt.split(".");
    if (length !== 3 || signature !== "") {
      throw new JWTInvalid("Invalid Unsecured JWT");
    }
    let header;
    try {
      header = JSON.parse(decoder.decode(decode(encodedHeader)));
      if (header.alg !== "none") throw new Error();
    } catch {
      throw new JWTInvalid("Invalid Unsecured JWT");
    }
    const payload = jwt_claims_set_default(header, decode(encodedPayload), options);
    return {
      payload,
      header
    };
  }
};

// node_modules/jose/dist/node/esm/util/base64url.js
var base64url_exports2 = {};
__export(base64url_exports2, {
  decode: () => decode2,
  encode: () => encode2
});
var encode2 = encode;
var decode2 = decode;

// node_modules/jose/dist/node/esm/util/decode_protected_header.js
function decodeProtectedHeader(token) {
  let protectedB64u;
  if (typeof token === "string") {
    const parts = token.split(".");
    if (parts.length === 3 || parts.length === 5) {
      ;
      [protectedB64u] = parts;
    }
  } else if (typeof token === "object" && token) {
    if ("protected" in token) {
      protectedB64u = token.protected;
    } else {
      throw new TypeError("Token does not contain a Protected Header");
    }
  }
  try {
    if (typeof protectedB64u !== "string" || !protectedB64u) {
      throw new Error();
    }
    const result = JSON.parse(decoder.decode(decode2(protectedB64u)));
    if (!isObject(result)) {
      throw new Error();
    }
    return result;
  } catch {
    throw new TypeError("Invalid Token or Protected Header formatting");
  }
}

// node_modules/jose/dist/node/esm/util/decode_jwt.js
function decodeJwt(jwt) {
  if (typeof jwt !== "string") throw new JWTInvalid("JWTs must use Compact JWS serialization, JWT must be a string");
  const {
    1: payload,
    length
  } = jwt.split(".");
  if (length === 5) throw new JWTInvalid("Only JWTs using Compact JWS serialization can be decoded");
  if (length !== 3) throw new JWTInvalid("Invalid JWT");
  if (!payload) throw new JWTInvalid("JWTs must contain a payload");
  let decoded;
  try {
    decoded = decode2(payload);
  } catch {
    throw new JWTInvalid("Failed to base64url decode the payload");
  }
  let result;
  try {
    result = JSON.parse(decoder.decode(decoded));
  } catch {
    throw new JWTInvalid("Failed to parse the decoded payload as JSON");
  }
  if (!isObject(result)) throw new JWTInvalid("Invalid JWT Claims Set");
  return result;
}

// node_modules/jose/dist/node/esm/runtime/generate.js
import { createSecretKey as createSecretKey3, generateKeyPair as generateKeyPairCb2 } from "crypto";
import { promisify as promisify5 } from "util";
var generate = promisify5(generateKeyPairCb2);
function generateSecret(alg, options) {
  return __async(this, null, function* () {
    let length;
    switch (alg) {
      case "HS256":
      case "HS384":
      case "HS512":
      case "A128CBC-HS256":
      case "A192CBC-HS384":
      case "A256CBC-HS512":
        length = parseInt(alg.slice(-3), 10);
        break;
      case "A128KW":
      case "A192KW":
      case "A256KW":
      case "A128GCMKW":
      case "A192GCMKW":
      case "A256GCMKW":
      case "A128GCM":
      case "A192GCM":
      case "A256GCM":
        length = parseInt(alg.slice(1, 4), 10);
        break;
      default:
        throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
    }
    return createSecretKey3(randomFillSync(new Uint8Array(length >> 3)));
  });
}
function generateKeyPair2(alg, options) {
  return __async(this, null, function* () {
    switch (alg) {
      case "RS256":
      case "RS384":
      case "RS512":
      case "PS256":
      case "PS384":
      case "PS512":
      case "RSA-OAEP":
      case "RSA-OAEP-256":
      case "RSA-OAEP-384":
      case "RSA-OAEP-512":
      case "RSA1_5": {
        const modulusLength = options?.modulusLength ?? 2048;
        if (typeof modulusLength !== "number" || modulusLength < 2048) {
          throw new JOSENotSupported("Invalid or unsupported modulusLength option provided, 2048 bits or larger keys must be used");
        }
        const keypair = yield generate("rsa", {
          modulusLength,
          publicExponent: 65537
        });
        return keypair;
      }
      case "ES256":
        return generate("ec", {
          namedCurve: "P-256"
        });
      case "ES256K":
        return generate("ec", {
          namedCurve: "secp256k1"
        });
      case "ES384":
        return generate("ec", {
          namedCurve: "P-384"
        });
      case "ES512":
        return generate("ec", {
          namedCurve: "P-521"
        });
      case "EdDSA": {
        switch (options?.crv) {
          case void 0:
          case "Ed25519":
            return generate("ed25519");
          case "Ed448":
            return generate("ed448");
          default:
            throw new JOSENotSupported("Invalid or unsupported crv option provided, supported values are Ed25519 and Ed448");
        }
      }
      case "ECDH-ES":
      case "ECDH-ES+A128KW":
      case "ECDH-ES+A192KW":
      case "ECDH-ES+A256KW": {
        const crv = options?.crv ?? "P-256";
        switch (crv) {
          case void 0:
          case "P-256":
          case "P-384":
          case "P-521":
            return generate("ec", {
              namedCurve: crv
            });
          case "X25519":
            return generate("x25519");
          case "X448":
            return generate("x448");
          default:
            throw new JOSENotSupported("Invalid or unsupported crv option provided, supported values are P-256, P-384, P-521, X25519, and X448");
        }
      }
      default:
        throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
    }
  });
}

// node_modules/jose/dist/node/esm/key/generate_key_pair.js
function generateKeyPair3(alg, options) {
  return __async(this, null, function* () {
    return generateKeyPair2(alg, options);
  });
}

// node_modules/jose/dist/node/esm/key/generate_secret.js
function generateSecret2(alg, options) {
  return __async(this, null, function* () {
    return generateSecret(alg, options);
  });
}

// node_modules/jose/dist/node/esm/runtime/runtime.js
var runtime_default = "node:crypto";

// node_modules/jose/dist/node/esm/util/runtime.js
var runtime_default2 = runtime_default;
export {
  CompactEncrypt,
  CompactSign,
  EmbeddedJWK,
  EncryptJWT,
  FlattenedEncrypt,
  FlattenedSign,
  GeneralEncrypt,
  GeneralSign,
  SignJWT,
  UnsecuredJWT,
  base64url_exports2 as base64url,
  calculateJwkThumbprint,
  calculateJwkThumbprintUri,
  compactDecrypt,
  compactVerify,
  createLocalJWKSet,
  createRemoteJWKSet,
  runtime_default2 as cryptoRuntime,
  decodeJwt,
  decodeProtectedHeader,
  errors_exports as errors,
  experimental_jwksCache,
  exportJWK,
  exportPKCS8,
  exportSPKI,
  flattenedDecrypt,
  flattenedVerify,
  generalDecrypt,
  generalVerify,
  generateKeyPair3 as generateKeyPair,
  generateSecret2 as generateSecret,
  importJWK,
  importPKCS8,
  importSPKI,
  importX509,
  jwtDecrypt,
  jwtVerify
};
//# sourceMappingURL=jose.js.map
