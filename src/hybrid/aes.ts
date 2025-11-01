import { AESConfig } from "../types";

// Isomorphic AES encrypt/decrypt using Node crypto on server and Web Crypto + scrypt-js in browser.
function nodeCrypto() {
  // dynamic require to avoid bundler issues
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  return require("crypto");
}

function getKeyLength(algorithm: string) {
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
  // eslint-disable-next-line @typescript-eslint/no-var-requires
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
  // eslint-disable-next-line @typescript-eslint/no-var-requires
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
    const crypto = nodeCrypto();
    const key = crypto.scryptSync(secretKey, salt, getKeyLength(algorithm));
    const ivBuf = Buffer.from(iv, "latin1");
    const cipher = crypto.createCipheriv(algorithm, key, ivBuf);
    const out = cipher.update(json, "utf8", encoding) + cipher.final(encoding);
    return out;
  }

  // Browser path - derive key using scrypt-js and use Web Crypto AES-CBC
  const scryptModule = await import("scrypt-js");
  const scrypt = (scryptModule as any).scrypt;

  const enc = new TextEncoder();
  const keyLen = getKeyLength(algorithm);

  // If secretKey looks like a hex string of the correct length, use it directly as the
  // derived key (hex -> bytes). This allows callers to pass a hex secret directly.
  const hexRegex = /^[0-9a-fA-F]+$/;
  let derived: Uint8Array;
  if (hexRegex.test(secretKey) && secretKey.length === keyLen * 2) {
    // hex -> bytes
    const bytes = new Uint8Array(keyLen);
    for (let i = 0; i < keyLen; i++) {
      bytes[i] = parseInt(secretKey.substr(i * 2, 2), 16);
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
  const cryptoKey = await subtle.importKey(
    "raw",
    derived as any,
    { name: "AES-CBC" },
    false,
    ["encrypt", "decrypt"]
  );

  const ivArr = latin1ToUint8Array(iv);
  const dataBuf = enc.encode(json);
  const encrypted = await subtle.encrypt(
    { name: "AES-CBC", iv: ivArr },
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
      const crypto = nodeCrypto();
      const key = crypto.scryptSync(secretKey, salt, getKeyLength(algorithm));
      const ivBuf = Buffer.from(iv, "latin1");
      const decipher = crypto.createDecipheriv(algorithm, key, ivBuf);
      const decrypted =
        decipher.update(encrypted, encoding, "utf8") + decipher.final("utf8");
      const parsed = JSON.parse(decrypted);
      if (parsed.exp && Date.now() > parsed.exp)
        throw new Error("Token expired");
      return parsed.data;
    }

    // Browser path
    const scryptModule = await import("scrypt-js");
    const scrypt = (scryptModule as any).scrypt;

    const keyLen = getKeyLength(algorithm);
    const enc = new TextEncoder();

    // Support hex secretKey directly (raw key bytes) if length matches
    const hexRegex = /^[0-9a-fA-F]+$/;
    let derived: Uint8Array;
    if (hexRegex.test(secretKey) && secretKey.length === keyLen * 2) {
      const bytes = new Uint8Array(keyLen);
      for (let i = 0; i < keyLen; i++) {
        bytes[i] = parseInt(secretKey.substr(i * 2, 2), 16);
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
    const cryptoKey = await subtle.importKey(
      "raw",
      derived as any,
      { name: "AES-CBC" },
      false,
      ["encrypt", "decrypt"]
    );

    const ivArr = latin1ToUint8Array(iv);
    const encryptedBytes = base64ToUint8Array(encrypted);
    const decryptedBuf = await subtle.decrypt(
      { name: "AES-CBC", iv: ivArr },
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
