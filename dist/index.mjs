// src/hybrid/aes.ts
import crypto from "crypto";
var aesEncrypt = (data, config) => {
  const {
    secretKey,
    iv,
    salt,
    algorithm,
    expiresIn,
    encoding = "base64"
  } = config;
  const key = crypto.scryptSync(secretKey, salt, getKeyLength(algorithm));
  const ivBuf = Buffer.from(iv, "latin1");
  const cipher = crypto.createCipheriv(algorithm, key, ivBuf);
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
    const key = crypto.scryptSync(secretKey, salt, getKeyLength(algorithm));
    const ivBuf = Buffer.from(iv, "latin1");
    const decipher = crypto.createDecipheriv(algorithm, key, ivBuf);
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
import crypto2 from "crypto";
var generateRSAKeys = (bits = 2048) => {
  const { publicKey, privateKey } = crypto2.generateKeyPairSync("rsa", {
    modulusLength: bits,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });
  return { publicKey, privateKey, algorithm: "RSA-SHA256" };
};
var rsaEncrypt = (data, publicKey) => {
  return crypto2.publicEncrypt(publicKey, Buffer.from(data)).toString("base64");
};
var rsaDecrypt = (encrypted, privateKey) => {
  return crypto2.privateDecrypt(privateKey, Buffer.from(encrypted, "base64")).toString("utf8");
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
import crypto3 from "crypto";
var randomKey = (length = 32) => crypto3.randomBytes(length).toString("hex").slice(0, length);
var randomIV = () => (
  // use 'latin1' so each byte maps to a single character and length === bytes
  crypto3.randomBytes(16).toString("latin1").slice(0, 16)
);
export {
  aesDecrypt,
  aesEncrypt,
  generateRSAKeys,
  hybridDecrypt,
  hybridEncrypt,
  randomIV,
  randomKey,
  rsaDecrypt,
  rsaEncrypt
};
