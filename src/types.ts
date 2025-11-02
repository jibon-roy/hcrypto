export type AESAlgorithm =
  | "aes-128-cbc"
  | "aes-256-cbc"
  | "aes-128-gcm"
  | "aes-256-gcm";

export type RSAAlgorithm = "RSA-SHA256" | "RSA-SHA512";

export type EncodingType = "base64" | "hex" | "utf8";

export interface AESConfig {
  secretKey: string; // hex string representing 16/24/32 bytes (32/48/64 hex chars) or passphrase
  iv: string; // hex string representing IV bytes (e.g. 16 bytes -> 32 hex chars)
  salt: string;
  algorithm: AESAlgorithm;
  encoding?: EncodingType;
  expiresIn?: number;
}

export interface RSAKeyPair {
  publicKey: string;
  privateKey: string;
  algorithm?: RSAAlgorithm;
}

export interface HybridEncryptConfig {
  aes: AESConfig;
  rsa: RSAKeyPair;
}
