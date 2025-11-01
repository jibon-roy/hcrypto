export type AESAlgorithm = "aes-128-cbc" | "aes-192-cbc" | "aes-256-cbc";

export type RSAAlgorithm = "RSA-SHA256" | "RSA-SHA512";

export type EncodingType = "base64" | "hex" | "utf8";

export interface AESConfig {
  secretKey: string; // 16/24/32 bytes
  iv: string; // 16 bytes
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
