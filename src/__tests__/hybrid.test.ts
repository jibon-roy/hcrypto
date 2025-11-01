import { hybridEncrypt, hybridDecrypt } from "../hybrid/hybridEncryptor";
import { generateRSAKeys } from "../hybrid/rsa";
import { randomKey, randomIV } from "../utils/keyGenerator";

describe("Hybrid encrypt/decrypt", () => {
  test("roundtrip encrypt and decrypt returns original object", () => {
    const aes = {
      secretKey: randomKey(32),
      iv: randomIV(),
      salt: "salt",
      algorithm: "aes-256-cbc",
    };
    // use 2048 bits so RSA can encrypt the AES key JSON payload reliably
    const rsa = generateRSAKeys(2048);

    const cfg = { aes, rsa } as any;
    const data = { ok: true, value: 123 };

    const token = hybridEncrypt(data, cfg);
    expect(typeof token).toBe("string");

    const out = hybridDecrypt(token, cfg);
    expect(out).toEqual(data);
  });
});
