import crypto from "crypto";

export const randomKey = (length = 32): string =>
  crypto.randomBytes(length).toString("hex").slice(0, length);

export const randomIV = (): string =>
  // use 'latin1' so each byte maps to a single character and length === bytes
  crypto.randomBytes(16).toString("latin1").slice(0, 16);
