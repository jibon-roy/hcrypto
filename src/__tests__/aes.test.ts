import { aesEncrypt, aesDecrypt } from "../hybrid/aes";
import { randomKey, randomIV } from "../utils/keyGenerator";
import type { AESConfig } from "../types";

describe("AES encrypt/decrypt", () => {
  test("roundtrip encrypt and decrypt returns original data", () => {
    const config: AESConfig = {
      secretKey: randomKey(32),
      iv: randomIV(),
      salt: "testsalt",
      algorithm: "aes-256-cbc",
    };

    const payload = { hello: "world", n: 42 };
    const encrypted = aesEncrypt(payload, config);
    expect(typeof encrypted).toBe("string");

    const decrypted = aesDecrypt(encrypted, config);
    expect(decrypted).toEqual(payload);
  });
});
