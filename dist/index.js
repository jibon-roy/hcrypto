"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  aesDecrypt: () => aesDecrypt,
  aesEncrypt: () => aesEncrypt,
  generateKeyPair: () => generateRSAKeys,
  generateRSAKeys: () => generateRSAKeys,
  hybridDecrypt: () => hybridDecrypt,
  hybridEncrypt: () => hybridEncrypt,
  randomIV: () => randomIV,
  randomKey: () => randomKey,
  rsaDecrypt: () => rsaDecrypt,
  rsaEncrypt: () => rsaEncrypt
});
module.exports = __toCommonJS(index_exports);

// src/hybrid/aes.ts
function nodeCrypto() {
  return require("crypto");
}
function getKeyLength(algorithm) {
  switch (algorithm) {
    case "aes-128-cbc":
      return 16;
    case "aes-192-cbc":
      return 24;
    case "aes-256-cbc":
    default:
      return 32;
  }
}
function latin1ToUint8Array(latin1) {
  const arr = new Uint8Array(latin1.length);
  for (let i = 0; i < latin1.length; i++) arr[i] = latin1.charCodeAt(i) & 255;
  return arr;
}
function uint8ArrayToBase64(bytes) {
  if (typeof window !== "undefined") {
    let binary = "";
    for (let i = 0; i < bytes.length; i++)
      binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }
  const Buffer2 = require("buffer").Buffer;
  return Buffer2.from(bytes).toString("base64");
}
function base64ToUint8Array(b64) {
  if (typeof window !== "undefined") {
    const binary = atob(b64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }
  const Buffer2 = require("buffer").Buffer;
  return new Uint8Array(Buffer2.from(b64, "base64"));
}
var aesEncrypt = async (data, config) => {
  const {
    secretKey,
    iv,
    salt,
    algorithm,
    expiresIn,
    encoding = "base64"
  } = config;
  const payload = {
    data,
    exp: expiresIn ? Date.now() + expiresIn * 1e3 : null
  };
  const json = JSON.stringify(payload);
  if (typeof window === "undefined") {
    const crypto2 = nodeCrypto();
    const key = crypto2.scryptSync(secretKey, salt, getKeyLength(algorithm));
    const ivBuf = Buffer.from(iv, "latin1");
    const cipher = crypto2.createCipheriv(algorithm, key, ivBuf);
    const out = cipher.update(json, "utf8", encoding) + cipher.final(encoding);
    return out;
  }
  const scryptModule = await import("scrypt-js");
  const scrypt = scryptModule.scrypt;
  const enc = new TextEncoder();
  const keyLen = getKeyLength(algorithm);
  const hexRegex = /^[0-9a-fA-F]+$/;
  let derived;
  if (hexRegex.test(secretKey) && secretKey.length === keyLen * 2) {
    const bytes = new Uint8Array(keyLen);
    for (let i = 0; i < keyLen; i++) {
      bytes[i] = parseInt(secretKey.substr(i * 2, 2), 16);
    }
    derived = bytes;
  } else {
    const pw = enc.encode(secretKey);
    const saltBuf = enc.encode(salt);
    derived = await new Promise((resolve, reject) => {
      try {
        scrypt(
          Array.from(pw),
          Array.from(saltBuf),
          16384,
          8,
          1,
          keyLen,
          (...cbArgs) => {
            const candidate = cbArgs[cbArgs.length - 1];
            if (candidate && (candidate instanceof Uint8Array || Array.isArray(candidate))) {
              return resolve(new Uint8Array(candidate));
            }
            const maybeErr = cbArgs[0];
            if (maybeErr && maybeErr instanceof Error) return reject(maybeErr);
          }
        );
      } catch (e) {
        reject(e);
      }
    });
  }
  const subtle = window.crypto && window.crypto.subtle;
  const cryptoKey = await subtle.importKey(
    "raw",
    derived,
    { name: "AES-CBC" },
    false,
    ["encrypt", "decrypt"]
  );
  const ivArr = latin1ToUint8Array(iv);
  const dataBuf = enc.encode(json);
  const encrypted = await subtle.encrypt(
    { name: "AES-CBC", iv: ivArr },
    cryptoKey,
    dataBuf
  );
  const outBytes = new Uint8Array(encrypted);
  const b64 = uint8ArrayToBase64(outBytes);
  return b64;
};
var aesDecrypt = async (encrypted, config) => {
  try {
    const { secretKey, iv, salt, algorithm, encoding = "base64" } = config;
    if (typeof window === "undefined") {
      const crypto2 = nodeCrypto();
      const key = crypto2.scryptSync(secretKey, salt, getKeyLength(algorithm));
      const ivBuf = Buffer.from(iv, "latin1");
      const decipher = crypto2.createDecipheriv(algorithm, key, ivBuf);
      const decrypted = decipher.update(encrypted, encoding, "utf8") + decipher.final("utf8");
      const parsed2 = JSON.parse(decrypted);
      if (parsed2.exp && Date.now() > parsed2.exp)
        throw new Error("Token expired");
      return parsed2.data;
    }
    const scryptModule = await import("scrypt-js");
    const scrypt = scryptModule.scrypt;
    const keyLen = getKeyLength(algorithm);
    const enc = new TextEncoder();
    const hexRegex = /^[0-9a-fA-F]+$/;
    let derived;
    if (hexRegex.test(secretKey) && secretKey.length === keyLen * 2) {
      const bytes = new Uint8Array(keyLen);
      for (let i = 0; i < keyLen; i++) {
        bytes[i] = parseInt(secretKey.substr(i * 2, 2), 16);
      }
      derived = bytes;
    } else {
      const pw = enc.encode(secretKey);
      const saltBuf = enc.encode(salt);
      derived = await new Promise((resolve, reject) => {
        try {
          scrypt(
            Array.from(pw),
            Array.from(saltBuf),
            16384,
            8,
            1,
            keyLen,
            (...cbArgs) => {
              const candidate = cbArgs[cbArgs.length - 1];
              if (candidate && (candidate instanceof Uint8Array || Array.isArray(candidate))) {
                return resolve(new Uint8Array(candidate));
              }
              const maybeErr = cbArgs[0];
              if (maybeErr && maybeErr instanceof Error)
                return reject(maybeErr);
            }
          );
        } catch (e) {
          reject(e);
        }
      });
    }
    const subtle = window.crypto && window.crypto.subtle;
    const cryptoKey = await subtle.importKey(
      "raw",
      derived,
      { name: "AES-CBC" },
      false,
      ["encrypt", "decrypt"]
    );
    const ivArr = latin1ToUint8Array(iv);
    const encryptedBytes = base64ToUint8Array(encrypted);
    const decryptedBuf = await subtle.decrypt(
      { name: "AES-CBC", iv: ivArr },
      cryptoKey,
      encryptedBytes
    );
    const dec = new TextDecoder();
    const json = dec.decode(decryptedBuf);
    const parsed = JSON.parse(json);
    if (parsed.exp && Date.now() > parsed.exp) throw new Error("Token expired");
    return parsed.data;
  } catch {
    return null;
  }
};

// src/hybrid/rsa.ts
var import_crypto = __toESM(require("crypto"));
var generateRSAKeys = (bits = 2048) => {
  const { publicKey, privateKey } = import_crypto.default.generateKeyPairSync("rsa", {
    modulusLength: bits,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });
  return { publicKey, privateKey, algorithm: "RSA-SHA256" };
};
var rsaEncrypt = (data, publicKey) => {
  return import_crypto.default.publicEncrypt(publicKey, Buffer.from(data)).toString("base64");
};
var rsaDecrypt = (encrypted, privateKey) => {
  return import_crypto.default.privateDecrypt(privateKey, Buffer.from(encrypted, "base64")).toString("utf8");
};

// src/hybrid/sodium.ts
var import_libsodium_wrappers = __toESM(require("libsodium-wrappers"));
async function ready() {
  await import_libsodium_wrappers.default.ready;
  return import_libsodium_wrappers.default;
}
function toBase64(buf) {
  if (typeof window !== "undefined") {
    let binary = "";
    for (let i = 0; i < buf.length; i++) binary += String.fromCharCode(buf[i]);
    return btoa(binary);
  }
  const Buffer2 = require("buffer").Buffer;
  return Buffer2.from(buf).toString("base64");
}
function fromBase64(b64) {
  if (typeof window !== "undefined") {
    const binary = atob(b64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }
  const Buffer2 = require("buffer").Buffer;
  return new Uint8Array(Buffer2.from(b64, "base64"));
}
var sodiumSeal = async (plaintext, recipientPublicKeyB64) => {
  const s = await ready();
  const pub = fromBase64(recipientPublicKeyB64);
  const pt = new TextEncoder().encode(plaintext);
  const cipher = s.crypto_box_seal(pt, pub);
  return toBase64(cipher);
};
var sodiumUnseal = async (cipherB64, recipientPublicKeyB64, recipientPrivateKeyB64) => {
  const s = await ready();
  const pub = fromBase64(recipientPublicKeyB64);
  const priv = fromBase64(recipientPrivateKeyB64);
  const cipher = fromBase64(cipherB64);
  const opened = s.crypto_box_seal_open(cipher, pub, priv);
  return new TextDecoder().decode(opened);
};

// src/hybrid/hybridEncryptor.ts
var hybridEncrypt = async (data, config) => {
  const aesEncrypted = await aesEncrypt(data, config.aes);
  const keyData = JSON.stringify({
    secretKey: config.aes.secretKey,
    iv: config.aes.iv,
    salt: config.aes.salt
  });
  const encryptedKey = await sodiumSeal(keyData, config.rsa.publicKey);
  return JSON.stringify({
    encryptedData: aesEncrypted,
    encryptedKey
  });
};
var hybridDecrypt = async (token, config) => {
  try {
    const { encryptedData, encryptedKey } = JSON.parse(token);
    const keyInfo = JSON.parse(
      await sodiumUnseal(
        encryptedKey,
        config.rsa.publicKey,
        config.rsa.privateKey
      )
    );
    const aesConfig = { ...config.aes, ...keyInfo };
    return await aesDecrypt(encryptedData, aesConfig);
  } catch {
    return null;
  }
};

// src/utils/keyGenerator.ts
function nodeCrypto2() {
  return require("crypto");
}
var randomKey = (length = 32) => {
  if (typeof window !== "undefined" && window.crypto && window.crypto.getRandomValues) {
    const arr = new Uint8Array(length);
    window.crypto.getRandomValues(arr);
    return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, length);
  }
  const crypto2 = nodeCrypto2();
  return crypto2.randomBytes(length).toString("hex").slice(0, length);
};
var randomIV = () => {
  if (typeof window !== "undefined" && window.crypto && window.crypto.getRandomValues) {
    const arr = new Uint8Array(16);
    window.crypto.getRandomValues(arr);
    return String.fromCharCode(...Array.from(arr));
  }
  const crypto2 = nodeCrypto2();
  return crypto2.randomBytes(16).toString("latin1").slice(0, 16);
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  aesDecrypt,
  aesEncrypt,
  generateKeyPair,
  generateRSAKeys,
  hybridDecrypt,
  hybridEncrypt,
  randomIV,
  randomKey,
  rsaDecrypt,
  rsaEncrypt
});
