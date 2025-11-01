import crypto from "crypto";
import { AESConfig } from "../types";

export const aesEncrypt = (
  data: Record<string, any>,
  config: AESConfig
): string => {
  const {
    secretKey,
    iv,
    salt,
    algorithm,
    expiresIn,
    encoding = "base64",
  } = config;

  const key = crypto.scryptSync(secretKey, salt, getKeyLength(algorithm));
  // IV is provided as a latin1 string (one char per byte). Convert to Buffer.
  const ivBuf = Buffer.from(iv, "latin1");
  const cipher = crypto.createCipheriv(algorithm, key, ivBuf);

  const payload = {
    data,
    exp: expiresIn ? Date.now() + expiresIn * 1000 : null,
  };

  const json = JSON.stringify(payload);
  return cipher.update(json, "utf8", encoding) + cipher.final(encoding);
};

export const aesDecrypt = (
  encrypted: string,
  config: AESConfig
): Record<string, any> | null => {
  try {
    const { secretKey, iv, salt, algorithm, encoding = "base64" } = config;
    const key = crypto.scryptSync(secretKey, salt, getKeyLength(algorithm));
    const ivBuf = Buffer.from(iv, "latin1");
    const decipher = crypto.createDecipheriv(algorithm, key, ivBuf);

    const decrypted =
      decipher.update(encrypted, encoding, "utf8") + decipher.final("utf8");
    const parsed = JSON.parse(decrypted);

    if (parsed.exp && Date.now() > parsed.exp) throw new Error("Token expired");
    return parsed.data;
  } catch {
    return null;
  }
};

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
