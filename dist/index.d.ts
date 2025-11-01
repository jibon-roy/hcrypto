type AESAlgorithm = "aes-128-cbc" | "aes-192-cbc" | "aes-256-cbc";
type RSAAlgorithm = "RSA-SHA256" | "RSA-SHA512";
type EncodingType = "base64" | "hex" | "utf8";
interface AESConfig {
    secretKey: string;
    iv: string;
    salt: string;
    algorithm: AESAlgorithm;
    encoding?: EncodingType;
    expiresIn?: number;
}
interface RSAKeyPair {
    publicKey: string;
    privateKey: string;
    algorithm?: RSAAlgorithm;
}
interface HybridEncryptConfig {
    aes: AESConfig;
    rsa: RSAKeyPair;
}

declare const aesEncrypt: (data: Record<string, any>, config: AESConfig) => Promise<string>;
declare const aesDecrypt: (encrypted: string, config: AESConfig) => Promise<Record<string, any> | null>;
/**
 * Check whether a token is expired. Returns:
 * - true if token is expired
 * - false if token is valid (not expired)
 * - null if token could not be decrypted / invalid
 */
declare const isTokenExpired: (token: string, config: AESConfig) => Promise<boolean | null>;

declare const generateRSAKeys: (bits?: number) => RSAKeyPair;
declare const rsaEncrypt: (data: string, publicKey: string) => string;
declare const rsaDecrypt: (encrypted: string, privateKey: string) => string;

declare const hybridEncrypt: (data: Record<string, any>, config: HybridEncryptConfig) => Promise<string>;
declare const hybridDecrypt: (token: string, config: HybridEncryptConfig) => Promise<Record<string, any> | null>;

declare const randomKey: (length?: number) => string;
declare const randomIV: () => string;
declare const randomIVHex: (bytes?: number) => string;

export { type AESAlgorithm, type AESConfig, type EncodingType, type HybridEncryptConfig, type RSAAlgorithm, type RSAKeyPair, aesDecrypt, aesEncrypt, generateRSAKeys as generateKeyPair, generateRSAKeys, hybridDecrypt, hybridEncrypt, isTokenExpired, randomIV, randomIVHex, randomKey, rsaDecrypt, rsaEncrypt };
