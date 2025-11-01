import { randomKey, randomIV } from "../utils/keyGenerator";

describe("Key generator", () => {
  test("randomKey returns string of given length", () => {
    const k = randomKey(32);
    expect(typeof k).toBe("string");
    expect(k).toHaveLength(32);
  });

  test("randomIV returns 16 character string", () => {
    const iv = randomIV();
    expect(typeof iv).toBe("string");
    expect(iv).toHaveLength(16);
  });
});
