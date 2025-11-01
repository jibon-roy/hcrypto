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
var import_crypto = __toESM(require("crypto"));
var aesEncrypt = (data, config) => {
  const {
    secretKey,
    iv,
    salt,
    algorithm,
    expiresIn,
    encoding = "base64"
  } = config;
  const key = import_crypto.default.scryptSync(secretKey, salt, getKeyLength(algorithm));
  const ivBuf = Buffer.from(iv, "latin1");
  const cipher = import_crypto.default.createCipheriv(algorithm, key, ivBuf);
  const payload = {
    data,
    exp: expiresIn ? Date.now() + expiresIn * 1e3 : null
  };
  const json = JSON.stringify(payload);
  return cipher.update(json, "utf8", encoding) + cipher.final(encoding);
};
var aesDecrypt = (encrypted, config) => {
  try {
    const { secretKey, iv, salt, algorithm, encoding = "base64" } = config;
    const key = import_crypto.default.scryptSync(secretKey, salt, getKeyLength(algorithm));
    const ivBuf = Buffer.from(iv, "latin1");
    const decipher = import_crypto.default.createDecipheriv(algorithm, key, ivBuf);
    const decrypted = decipher.update(encrypted, encoding, "utf8") + decipher.final("utf8");
    const parsed = JSON.parse(decrypted);
    if (parsed.exp && Date.now() > parsed.exp) throw new Error("Token expired");
    return parsed.data;
  } catch {
    return null;
  }
};
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

// src/hybrid/rsa.ts
var import_crypto2 = __toESM(require("crypto"));
var generateRSAKeys = (bits = 2048) => {
  const { publicKey, privateKey } = import_crypto2.default.generateKeyPairSync("rsa", {
    modulusLength: bits,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });
  return { publicKey, privateKey, algorithm: "RSA-SHA256" };
};
var rsaEncrypt = (data, publicKey) => {
  return import_crypto2.default.publicEncrypt(publicKey, Buffer.from(data)).toString("base64");
};
var rsaDecrypt = (encrypted, privateKey) => {
  return import_crypto2.default.privateDecrypt(privateKey, Buffer.from(encrypted, "base64")).toString("utf8");
};

// src/hybrid/hybridEncryptor.ts
var hybridEncrypt = (data, config) => {
  const aesEncrypted = aesEncrypt(data, config.aes);
  const keyData = JSON.stringify({
    secretKey: config.aes.secretKey,
    iv: config.aes.iv,
    salt: config.aes.salt
  });
  const encryptedKey = rsaEncrypt(keyData, config.rsa.publicKey);
  return JSON.stringify({
    encryptedData: aesEncrypted,
    encryptedKey
  });
};
var hybridDecrypt = (token, config) => {
  try {
    const { encryptedData, encryptedKey } = JSON.parse(token);
    const keyInfo = JSON.parse(rsaDecrypt(encryptedKey, config.rsa.privateKey));
    const aesConfig = { ...config.aes, ...keyInfo };
    return aesDecrypt(encryptedData, aesConfig);
  } catch {
    return null;
  }
};

// src/utils/keyGenerator.ts
var import_crypto3 = __toESM(require("crypto"));
var randomKey = (length = 32) => import_crypto3.default.randomBytes(length).toString("hex").slice(0, length);
var randomIV = () => (
  // use 'latin1' so each byte maps to a single character and length === bytes
  import_crypto3.default.randomBytes(16).toString("latin1").slice(0, 16)
);
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  aesDecrypt,
  aesEncrypt,
  generateRSAKeys,
  hybridDecrypt,
  hybridEncrypt,
  randomIV,
  randomKey,
  rsaDecrypt,
  rsaEncrypt
});
