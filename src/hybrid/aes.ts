import { AESConfig } from "../types";

// Isomorphic AES encrypt/decrypt using Node crypto on server and Web Crypto + scrypt-js in browser.
function nodeCrypto() {
  // dynamic require to avoid bundler issues

  return require("crypto");
}

function getKeyLength(algorithm: string) {
  switch (algorithm) {
    case "aes-128-cbc":
      return 16;
    case "aes-128-gcm":
      return 16;
    case "aes-256-cbc":
    default:
      return 32;
  }
}

function isGcm(algorithm: string) {
  return /-gcm$/.test(algorithm);
}

function hexToUint8Array(hex: string) {
  const len = hex.length / 2;
  const arr = new Uint8Array(len);
  for (let i = 0; i < len; i++)
    arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16) & 0xff;
  return arr;
}

function latin1ToUint8Array(latin1: string) {
  const arr = new Uint8Array(latin1.length);
  for (let i = 0; i < latin1.length; i++) arr[i] = latin1.charCodeAt(i) & 0xff;
  return arr;
}

function uint8ArrayToBase64(bytes: Uint8Array) {
  if (typeof window !== "undefined") {
    let binary = "";
    for (let i = 0; i < bytes.length; i++)
      binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }
  // Node

  const Buffer = require("buffer").Buffer;
  return Buffer.from(bytes).toString("base64");
}

function base64ToUint8Array(b64: string) {
  if (typeof window !== "undefined") {
    const binary = atob(b64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }
  // Node

  const Buffer = require("buffer").Buffer;
  return new Uint8Array(Buffer.from(b64, "base64"));
}

export const aesEncrypt = async (
  data: Record<string, any>,
  config: AESConfig
): Promise<string> => {
  const {
    secretKey,
    iv,
    salt,
    algorithm,
    expiresIn,
    encoding = "base64",
  } = config;

  const payload = {
    data,
    exp: expiresIn ? Date.now() + expiresIn * 1000 : null,
  };
  const json = JSON.stringify(payload);

  // Node (server) path - use Node crypto synchronously but return Promise
  if (typeof window === "undefined") {
    // Basic validation: salt must be present
    if (!salt) throw new Error("Missing salt for key derivation");
    const crypto = nodeCrypto();
    const key = crypto.scryptSync(secretKey, salt, getKeyLength(algorithm));

    // IV length validation: CBC requires 16 bytes, GCM commonly uses 12 bytes
    const isHexIv = /^[0-9a-fA-F]+$/.test(iv);
    if (isGcm(algorithm)) {
      if (isHexIv) {
        if (iv.length !== 24)
          throw new Error(
            "Invalid IV length for GCM: expected 12 bytes (24 hex chars)"
          );
      } else {
        if (iv.length !== 12)
          throw new Error(
            "Invalid IV length for GCM: expected 12 bytes (latin1 string length 12)"
          );
      }
    } else {
      if (isHexIv) {
        if (iv.length !== 32)
          throw new Error(
            "Invalid IV length: expected 16 bytes (32 hex chars)"
          );
      } else {
        if (iv.length !== 16)
          throw new Error(
            "Invalid IV length: expected 16 bytes (latin1 string length 16)"
          );
      }
    }

    const isHex = /^[0-9a-fA-F]+$/.test(iv);
    const ivBuf = Buffer.from(iv, isHex ? "hex" : "latin1");
    const cipher = crypto.createCipheriv(algorithm, key, ivBuf);
    const outBuf = Buffer.concat([cipher.update(json, "utf8"), cipher.final()]);

    if (isGcm(algorithm)) {
      // append auth tag for GCM
      const tag = cipher.getAuthTag();
      const combined = Buffer.concat([outBuf, tag]);
      return combined.toString(encoding);
    }

    return outBuf.toString(encoding);
  }

  // Browser path - derive key using scrypt-js and use Web Crypto AES-CBC
  const scryptModule = await import("scrypt-js");
  const scrypt = (scryptModule as any).scrypt;

  const enc = new TextEncoder();
  const keyLen = getKeyLength(algorithm);

  // Basic validation: salt must be present
  if (!salt) throw new Error("Missing salt for key derivation");

  // IV length validation: different for GCM vs CBC
  const isHexIv = /^[0-9a-fA-F]+$/.test(iv);
  if (isGcm(algorithm)) {
    if (isHexIv) {
      if (iv.length !== 24)
        throw new Error(
          "Invalid IV length for GCM: expected 12 bytes (24 hex chars)"
        );
    } else {
      if (iv.length !== 12)
        throw new Error(
          "Invalid IV length for GCM: expected 12 bytes (latin1 string length 12)"
        );
    }
  } else {
    if (isHexIv) {
      if (iv.length !== 32)
        throw new Error("Invalid IV length: expected 16 bytes (32 hex chars)");
    } else {
      if (iv.length !== 16)
        throw new Error(
          "Invalid IV length: expected 16 bytes (latin1 string length 16)"
        );
    }
  }

  // If secretKey looks like a hex string of the correct length, use it directly as the
  // derived key (hex -> bytes). This allows callers to pass a hex secret directly.
  const hexRegex = /^[0-9a-fA-F]+$/;
  let derived: Uint8Array;
  if (hexRegex.test(secretKey) && secretKey.length === keyLen * 2) {
    // hex -> bytes
    const bytes = new Uint8Array(keyLen);
    for (let i = 0; i < keyLen; i++) {
      bytes[i] = parseInt(secretKey.slice(i * 2, i * 2 + 2), 16);
    }
    derived = bytes;
  } else {
    const pw = enc.encode(secretKey);
    const saltBuf = enc.encode(salt);

    // scrypt-js may call the callback multiple times with progress values before
    // finally providing the derived key. Different versions use different callback
    // signatures (progress, key) or (error, progress, key). Treat the last
    // argument as the candidate key when it's present.
    derived = await new Promise<Uint8Array>((resolve, reject) => {
      try {
        scrypt(
          Array.from(pw),
          Array.from(saltBuf),
          16384,
          8,
          1,
          keyLen,
          (...cbArgs: any[]) => {
            // Candidate key may be the last argument
            const candidate = cbArgs[cbArgs.length - 1];
            if (
              candidate &&
              (candidate instanceof Uint8Array || Array.isArray(candidate))
            ) {
              return resolve(new Uint8Array(candidate));
            }
            // Some implementations pass (err, progress, key) where err can be null
            const maybeErr = cbArgs[0];
            if (maybeErr && maybeErr instanceof Error) return reject(maybeErr);
            // Otherwise it's a progress callback; ignore
          }
        );
      } catch (e) {
        reject(e);
      }
    });
  }

  // @ts-ignore - derived is a Uint8Array
  const subtle = (window.crypto &&
    (window.crypto as any).subtle) as SubtleCrypto;
  const algName = isGcm(algorithm) ? "AES-GCM" : "AES-CBC";
  const cryptoKey = await subtle.importKey(
    "raw",
    derived as any,
    { name: algName },
    false,
    ["encrypt", "decrypt"]
  );

  // IV may be provided as a hex string (preferred) or a latin1 byte string for
  // backwards compatibility. Convert appropriately to a Uint8Array.
  const ivArr = /^[0-9a-fA-F]+$/.test(iv)
    ? hexToUint8Array(iv)
    : latin1ToUint8Array(iv);
  const dataBuf = enc.encode(json);
  const encryptParams: any = { name: algName, iv: ivArr };
  if (isGcm(algorithm)) encryptParams.tagLength = 128;
  const encrypted = await subtle.encrypt(
    encryptParams,
    cryptoKey,
    dataBuf as any
  );
  const outBytes = new Uint8Array(encrypted as ArrayBuffer);
  const b64 = uint8ArrayToBase64(outBytes);
  return b64;
};

export const aesDecrypt = async (
  encrypted: string,
  config: AESConfig
): Promise<Record<string, any> | null> => {
  try {
    const { secretKey, iv, salt, algorithm, encoding = "base64" } = config;

    // Node path
    if (typeof window === "undefined") {
      // Basic validation: salt must be present
      if (!salt) throw new Error("Missing salt for key derivation");
      // IV length validation: GCM uses 12 bytes, CBC uses 16
      const isHexIv = /^[0-9a-fA-F]+$/.test(iv);
      if (isGcm(algorithm)) {
        if (isHexIv) {
          if (iv.length !== 24)
            throw new Error(
              "Invalid IV length for GCM: expected 12 bytes (24 hex chars)"
            );
        } else {
          if (iv.length !== 12)
            throw new Error(
              "Invalid IV length for GCM: expected 12 bytes (latin1 string length 12)"
            );
        }
      } else {
        if (isHexIv) {
          if (iv.length !== 32)
            throw new Error(
              "Invalid IV length: expected 16 bytes (32 hex chars)"
            );
        } else {
          if (iv.length !== 16)
            throw new Error(
              "Invalid IV length: expected 16 bytes (latin1 string length 16)"
            );
        }
      }
      const crypto = nodeCrypto();
      const key = crypto.scryptSync(secretKey, salt, getKeyLength(algorithm));
      const isHex = /^[0-9a-fA-F]+$/.test(iv);
      const ivBuf = Buffer.from(iv, isHex ? "hex" : "latin1");
      const decipher = crypto.createDecipheriv(algorithm, key, ivBuf);
      let decryptedBuf: Buffer;
      if (isGcm(algorithm)) {
        // split auth tag (last 16 bytes) from ciphertext
        const encBuf = Buffer.from(encrypted, encoding);
        if (encBuf.length < 16) throw new Error("Invalid encrypted data");
        const tag = encBuf.slice(encBuf.length - 16);
        const ciphertext = encBuf.slice(0, encBuf.length - 16);
        decipher.setAuthTag(tag);
        decryptedBuf = Buffer.concat([
          decipher.update(ciphertext),
          decipher.final(),
        ]);
      } else {
        decryptedBuf = Buffer.concat([
          decipher.update(Buffer.from(encrypted, encoding)),
          decipher.final(),
        ]);
      }
      const parsed = JSON.parse(decryptedBuf.toString("utf8"));
      if (parsed.exp && Date.now() > parsed.exp)
        throw new Error("Token expired");
      return parsed.data;
    }

    // Browser path
    const scryptModule = await import("scrypt-js");
    const scrypt = (scryptModule as any).scrypt;

    const keyLen = getKeyLength(algorithm);
    const enc = new TextEncoder();

    // Basic validation: salt must be present
    if (!salt) throw new Error("Missing salt for key derivation");
    // IV length validation for browser side
    const isHexIv2 = /^[0-9a-fA-F]+$/.test(iv);
    if (isGcm(algorithm)) {
      if (isHexIv2) {
        if (iv.length !== 24)
          throw new Error(
            "Invalid IV length for GCM: expected 12 bytes (24 hex chars)"
          );
      } else {
        if (iv.length !== 12)
          throw new Error(
            "Invalid IV length for GCM: expected 12 bytes (latin1 string length 12)"
          );
      }
    } else {
      if (isHexIv2) {
        if (iv.length !== 32)
          throw new Error(
            "Invalid IV length: expected 16 bytes (32 hex chars)"
          );
      } else {
        if (iv.length !== 16)
          throw new Error(
            "Invalid IV length: expected 16 bytes (latin1 string length 16)"
          );
      }
    }

    // Support hex secretKey directly (raw key bytes) if length matches
    const hexRegex = /^[0-9a-fA-F]+$/;
    let derived: Uint8Array;
    if (hexRegex.test(secretKey) && secretKey.length === keyLen * 2) {
      const bytes = new Uint8Array(keyLen);
      for (let i = 0; i < keyLen; i++) {
        bytes[i] = parseInt(secretKey.slice(i * 2, i * 2 + 2), 16);
      }
      derived = bytes;
    } else {
      const pw = enc.encode(secretKey);
      const saltBuf = enc.encode(salt);
      derived = await new Promise<Uint8Array>((resolve, reject) => {
        try {
          scrypt(
            Array.from(pw),
            Array.from(saltBuf),
            16384,
            8,
            1,
            keyLen,
            (...cbArgs: any[]) => {
              const candidate = cbArgs[cbArgs.length - 1];
              if (
                candidate &&
                (candidate instanceof Uint8Array || Array.isArray(candidate))
              ) {
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

    // @ts-ignore
    const subtle = (window.crypto &&
      (window.crypto as any).subtle) as SubtleCrypto;
    const algName = isGcm(algorithm) ? "AES-GCM" : "AES-CBC";
    const cryptoKey = await subtle.importKey(
      "raw",
      derived as any,
      { name: algName },
      false,
      ["encrypt", "decrypt"]
    );

    const ivArr = /^[0-9a-fA-F]+$/.test(iv)
      ? hexToUint8Array(iv)
      : latin1ToUint8Array(iv);
    const encryptedBytes = base64ToUint8Array(encrypted);
    const decryptParams: any = { name: algName, iv: ivArr };
    if (isGcm(algorithm)) decryptParams.tagLength = 128;
    const decryptedBuf = await subtle.decrypt(
      decryptParams,
      cryptoKey,
      encryptedBytes as any
    );
    const dec = new TextDecoder();
    const json = dec.decode(decryptedBuf as ArrayBuffer);
    const parsed = JSON.parse(json);
    if (parsed.exp && Date.now() > parsed.exp) throw new Error("Token expired");
    return parsed.data;
  } catch {
    return null;
  }
};

/**
 * Check whether a token is expired. Returns:
 * - true if token is expired
 * - false if token is valid (not expired)
 * - null if token could not be decrypted / invalid
 */
export const isTokenExpired = async (
  token: string,
  config: AESConfig
): Promise<boolean | null> => {
  try {
    const { secretKey, iv, salt, algorithm, encoding = "base64" } = config;

    // Node path
    if (typeof window === "undefined") {
      // Basic validation: salt must be present
      if (!salt) throw new Error("Missing salt for key derivation");
      // IV length validation
      // IV length validation: GCM uses 12 bytes, CBC uses 16
      const isHexIv = /^[0-9a-fA-F]+$/.test(iv);
      if (isGcm(algorithm)) {
        if (isHexIv) {
          if (iv.length !== 24)
            throw new Error(
              "Invalid IV length for GCM: expected 12 bytes (24 hex chars)"
            );
        } else {
          if (iv.length !== 12)
            throw new Error(
              "Invalid IV length for GCM: expected 12 bytes (latin1 string length 12)"
            );
        }
      } else {
        if (isHexIv) {
          if (iv.length !== 32)
            throw new Error(
              "Invalid IV length: expected 16 bytes (32 hex chars)"
            );
        } else {
          if (iv.length !== 16)
            throw new Error(
              "Invalid IV length: expected 16 bytes (latin1 string length 16)"
            );
        }
      }
      const crypto = nodeCrypto();
      const key = crypto.scryptSync(secretKey, salt, getKeyLength(algorithm));
      const isHex = /^[0-9a-fA-F]+$/.test(iv);
      const ivBuf = Buffer.from(iv, isHex ? "hex" : "latin1");
      const decipher = crypto.createDecipheriv(algorithm, key, ivBuf);
      let decryptedBuf: Buffer;
      if (isGcm(algorithm)) {
        const encBuf = Buffer.from(token, encoding);
        if (encBuf.length < 16) return null;
        const tag = encBuf.slice(encBuf.length - 16);
        const ciphertext = encBuf.slice(0, encBuf.length - 16);
        decipher.setAuthTag(tag);
        decryptedBuf = Buffer.concat([
          decipher.update(ciphertext),
          decipher.final(),
        ]);
      } else {
        decryptedBuf = Buffer.concat([
          decipher.update(Buffer.from(token, encoding)),
          decipher.final(),
        ]);
      }
      const parsed = JSON.parse(decryptedBuf.toString("utf8"));
      if (parsed.exp && Date.now() > parsed.exp) return true;
      return false;
    }

    // Browser path
    const scryptModule = await import("scrypt-js");
    const scrypt = (scryptModule as any).scrypt;

    const keyLen = getKeyLength(algorithm);
    const enc = new TextEncoder();

    // Basic validation: salt must be present
    if (!salt) throw new Error("Missing salt for key derivation");
    // IV length validation
    const isHexIv2 = /^[0-9a-fA-F]+$/.test(iv);
    if (isGcm(algorithm)) {
      if (isHexIv2) {
        if (iv.length !== 24)
          throw new Error(
            "Invalid IV length for GCM: expected 12 bytes (24 hex chars)"
          );
      } else {
        if (iv.length !== 12)
          throw new Error(
            "Invalid IV length for GCM: expected 12 bytes (latin1 string length 12)"
          );
      }
    } else {
      if (isHexIv2) {
        if (iv.length !== 32)
          throw new Error(
            "Invalid IV length: expected 16 bytes (32 hex chars)"
          );
      } else {
        if (iv.length !== 16)
          throw new Error(
            "Invalid IV length: expected 16 bytes (latin1 string length 16)"
          );
      }
    }
    // Support hex secretKey directly (raw key bytes) if length matches
    const hexRegex = /^[0-9a-fA-F]+$/;
    let derived: Uint8Array;
    if (hexRegex.test(secretKey) && secretKey.length === keyLen * 2) {
      const bytes = new Uint8Array(keyLen);
      for (let i = 0; i < keyLen; i++) {
        bytes[i] = parseInt(secretKey.slice(i * 2, i * 2 + 2), 16);
      }
      derived = bytes;
    } else {
      const pw = enc.encode(secretKey);
      const saltBuf = enc.encode(salt);
      derived = await new Promise<Uint8Array>((resolve, reject) => {
        try {
          scrypt(
            Array.from(pw),
            Array.from(saltBuf),
            16384,
            8,
            1,
            keyLen,
            (...cbArgs: any[]) => {
              const candidate = cbArgs[cbArgs.length - 1];
              if (
                candidate &&
                (candidate instanceof Uint8Array || Array.isArray(candidate))
              ) {
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

    // @ts-ignore
    const subtle = (window.crypto &&
      (window.crypto as any).subtle) as SubtleCrypto;
    const algName = isGcm(algorithm) ? "AES-GCM" : "AES-CBC";
    const cryptoKey = await subtle.importKey(
      "raw",
      derived as any,
      { name: algName },
      false,
      ["encrypt", "decrypt"]
    );

    const ivArr = /^[0-9a-fA-F]+$/.test(iv)
      ? hexToUint8Array(iv)
      : latin1ToUint8Array(iv);
    const encryptedBytes = base64ToUint8Array(token);
    const decryptParams: any = { name: algName, iv: ivArr };
    if (isGcm(algorithm)) decryptParams.tagLength = 128;
    const decryptedBuf = await subtle.decrypt(
      decryptParams,
      cryptoKey,
      encryptedBytes as any
    );
    const dec = new TextDecoder();
    const json = dec.decode(decryptedBuf as ArrayBuffer);
    const parsed = JSON.parse(json);
    if (parsed.exp && Date.now() > parsed.exp) return true;
    return false;
  } catch {
    return null;
  }
};
