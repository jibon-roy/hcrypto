import { generateRSAKeys, rsaEncrypt, rsaDecrypt } from "../hybrid/rsa";

describe("RSA encrypt/decrypt", () => {
  test("roundtrip encrypt and decrypt returns original string", () => {
    const keys = generateRSAKeys(1024);
    const msg = "the quick brown fox";
    const enc = rsaEncrypt(msg, keys.publicKey);
    expect(typeof enc).toBe("string");

    const dec = rsaDecrypt(enc, keys.privateKey);
    expect(dec).toBe(msg);
  });
});
