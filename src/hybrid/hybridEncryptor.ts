import { aesEncrypt, aesDecrypt } from "./aes";
import { rsaEncrypt, rsaDecrypt } from "./rsa";
import { HybridEncryptConfig } from "../types";

export const hybridEncrypt = (
  data: Record<string, any>,
  config: HybridEncryptConfig
): string => {
  const aesEncrypted = aesEncrypt(data, config.aes);

  // Encrypt AES key & IV using RSA public key
  const keyData = JSON.stringify({
    secretKey: config.aes.secretKey,
    iv: config.aes.iv,
    salt: config.aes.salt,
  });

  const encryptedKey = rsaEncrypt(keyData, config.rsa.publicKey);

  return JSON.stringify({
    encryptedData: aesEncrypted,
    encryptedKey,
  });
};

export const hybridDecrypt = (
  token: string,
  config: HybridEncryptConfig
): Record<string, any> | null => {
  try {
    const { encryptedData, encryptedKey } = JSON.parse(token);

    // Decrypt AES key info using private RSA key
    const keyInfo = JSON.parse(rsaDecrypt(encryptedKey, config.rsa.privateKey));

    // Merge decrypted AES config with provided
    const aesConfig = { ...config.aes, ...keyInfo };

    return aesDecrypt(encryptedData, aesConfig);
  } catch {
    return null;
  }
};
