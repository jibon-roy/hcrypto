import crypto from "crypto";
import { RSAKeyPair } from "../types";

export const generateRSAKeys = (bits = 2048): RSAKeyPair => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: bits,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  return { publicKey, privateKey, algorithm: "RSA-SHA256" };
};

export const rsaEncrypt = (data: string, publicKey: string): string => {
  return crypto.publicEncrypt(publicKey, Buffer.from(data)).toString("base64");
};

export const rsaDecrypt = (encrypted: string, privateKey: string): string => {
  return crypto
    .privateDecrypt(privateKey, Buffer.from(encrypted, "base64"))
    .toString("utf8");
};
