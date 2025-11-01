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

declare const aesEncrypt: (data: Record<string, any>, config: AESConfig) => string;
declare const aesDecrypt: (encrypted: string, config: AESConfig) => Record<string, any> | null;

declare const generateRSAKeys: (bits?: number) => RSAKeyPair;
declare const rsaEncrypt: (data: string, publicKey: string) => string;
declare const rsaDecrypt: (encrypted: string, privateKey: string) => string;

declare const hybridEncrypt: (data: Record<string, any>, config: HybridEncryptConfig) => string;
declare const hybridDecrypt: (token: string, config: HybridEncryptConfig) => Record<string, any> | null;

declare const randomKey: (length?: number) => string;
declare const randomIV: () => string;

export { type AESAlgorithm, type AESConfig, type EncodingType, type HybridEncryptConfig, type RSAAlgorithm, type RSAKeyPair, aesDecrypt, aesEncrypt, generateRSAKeys, hybridDecrypt, hybridEncrypt, randomIV, randomKey, rsaDecrypt, rsaEncrypt };
