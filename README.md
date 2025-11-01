# joycrypto-hybrid

A hybrid encryption helper focused on providing cross-platform (Node + browser-ready APIs) building blocks for hybrid encryption flows. This project provides AES helpers, sealed-box wrappers (libsodium), key generation utilities, and an easy hybrid envelope pattern.

## Install

```powershell
npm install joycrypto-hybrid
# or
pnpm add joycrypto-hybrid
```

## Quick notes about platform compatibility

- As of v1.x the package provides browser-safe code paths for symmetric AES operations (Web Crypto + scrypt-js) and uses libsodium-wrappers sealed boxes for cross-platform asymmetric wrapping. This allows the same high-level API to work in browsers (WASM libsodium) and Node.
- For server-only RSA/PEM flows the old `rsa` helpers remain, but the hybrid encryptor uses the sodium sealed-box helpers by default.

## Front-end (React / Next client) — client-only example

The package includes helpers to generate hex secrets and hex IVs that are easy to copy/paste into front-end code. Below is a minimal client-only React component example (adapted for Next.js client components):

```tsx
import React from "react";
import {
  aesEncrypt,
  aesDecrypt,
  randomKey,
  randomIVHex,
} from "joycrypto-hybrid";

async function demo() {
  // prefer AES-256
  const secretHex = randomKey(64); // 64 hex chars -> 32 bytes
  const ivHex = randomIVHex(16); // 16 bytes -> 32 hex chars

  const cfg = {
    secretKey: secretHex,
    iv: ivHex,
    salt: "client-salt",
    algorithm: "aes-256-cbc",
    encoding: "base64",
    expiresIn: 3600,
  };

  const payload = { hello: "world" };
  const token = await aesEncrypt(payload, cfg);
  const recovered = await aesDecrypt(token, cfg);
  console.log({ token, recovered });
}

demo();
```

Notes for client-only usage:

- Any secret embedded in client code is visible to end users. Client-only secrets are appropriate only when you want client-side encryption for local storage or user-controlled secrets. Do not use client-only secrets to protect server-only data.
- IVs and secrets are hex strings: use `randomKey(length)` where length is number of hex characters, and `randomIVHex(bytes)` where bytes is the number of bytes for the IV.

## Server-side (Node, Next.js API routes, Express)

Server code can keep private keys and secrets hidden. Here's a minimal Next.js API route example that decrypts a token sent from a client. It assumes you already created/stored a sodium keypair (or RSA pair if you prefer):

```js
// pages/api/decrypt-token.js (Next.js API route)
import { hybridDecrypt } from "joycrypto-hybrid";

// Keep keys in a secure store in production. For demo we use process.env or in-memory.
const KEYPAIR = {
  publicKey: process.env.SODIUM_PUBLIC,
  privateKey: process.env.SODIUM_PRIVATE,
};

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).end();
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: "token required" });

  const cfg = {
    aes: { algorithm: "aes-256-cbc", salt: "client-salt" },
    rsa: { publicKey: KEYPAIR.publicKey, privateKey: KEYPAIR.privateKey },
  };

  const data = await hybridDecrypt(token, cfg);
  if (!data) return res.status(400).json({ error: "decrypt failed" });
  return res.status(200).json({ data });
}
```

Server-side Express example (Node):

```js
const express = require("express");
const { hybridDecrypt, generateSodiumKeyPair } = require("joycrypto-hybrid");

const app = express();
app.use(express.json());

(async () => {
  // Generate or load keypair at startup (persist private key in a secure store for production)
  const kp = await generateSodiumKeyPair();
  app.post("/decrypt", async (req, res) => {
    const { token } = req.body;
    const cfg = {
      aes: { algorithm: "aes-256-cbc", salt: "client-salt" },
      rsa: { publicKey: kp.publicKey, privateKey: kp.privateKey },
    };
    const data = await hybridDecrypt(token, cfg);
    res.json({ data });
  });
  app.listen(3000);
})();
```

## API and helpers

Below is a quick reference table for the most-used functions, their main parameters and return values. For all functions that accept an `AESConfig`, see the `Types` section in the source (`src/types.ts`).

| Function                                                  | Main parameters                                 |                              Returns | Notes / expected input                                                                                                                                                   |
| --------------------------------------------------------- | ----------------------------------------------- | -----------------------------------: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| aesEncrypt(data, config)                                  | data: object, config: AESConfig                 |         Promise<string> (ciphertext) | `config.secretKey` can be a hex key (raw) or a passphrase (KDF). `config.iv` accepts hex (preferred) or legacy latin1. `config.expiresIn` sets payload expiry (seconds). |
| aesDecrypt(token, config)                                 | token: string, config: AESConfig                |                       Promise<object | null>                                                                                                                                                                    | Returns decrypted object or null on failure/expired. Provide same config used to encrypt (secretKey, iv, salt, algorithm). |
| isTokenExpired(token, config)                             | token: string, config: AESConfig                |                      Promise<boolean | null>                                                                                                                                                                    | true = expired, false = valid, null = invalid/unreadable.                                                                  |
| randomKey(length)                                         | length: number (hex chars)                      |                         string (hex) | Returns random hex string. For AES-256 provide 64 (hex chars) → 32 bytes.                                                                                                |
| randomIVHex(bytes)                                        | bytes: number                                   |                         string (hex) | Returns hex IV (bytes \* 2 hex chars). Example: randomIVHex(16) → 32 hex chars.                                                                                          |
| randomIV()                                                | —                                               |                      string (latin1) | Legacy helper: returns 16-char latin1 string (each char = one byte). Kept for backwards compatibility.                                                                   |
| generateSodiumKeyPair()                                   | —                                               |   Promise<{ publicKey, privateKey }> | Base64-encoded sodium keypair (ready for `sodiumSeal`/`sodiumUnseal`). Works in browser & Node.                                                                          |
| sodiumSeal(plaintext, publicKey)                          | plaintext: string, publicKey: string (base64)   |             Promise<string> (base64) | Sealed-box encrypts data to recipient public key (no sender key needed).                                                                                                 |
| sodiumUnseal(cipherB64, publicKey, privateKey)            | cipherB64: string, publicKey/privateKey: base64 |          Promise<string> (plaintext) | Opens sealed box with recipient keypair.                                                                                                                                 |
| generateRSAKeys(bits?)                                    | bits?: number                                   | { publicKey, privateKey, algorithm } | Legacy Node-only RSA keypair (PEM). Still exported for compatibility.                                                                                                    |
| rsaEncrypt(data, publicKey) / rsaDecrypt(enc, privateKey) | data/string, PEM keys                           |                      string / string | Legacy RSA helpers (Node-only). Prefer sodium sealed boxes for browser compatibility.                                                                                    |
| hybridEncrypt(data, config)                               | data: object, config: HybridEncryptConfig       |      Promise<string> (envelope JSON) | Creates an envelope: { encryptedData, encryptedKey } where encryptedKey is sealed with sodium by default.                                                                |
| hybridDecrypt(token, config)                              | token: string, config: HybridEncryptConfig      |                       Promise<object | null>                                                                                                                                                                    | Decrypts envelope with private key + AES config, returns original object or null.                                          |

Examples / input expectations

- secretKey (hex): For AES-256 pass a 64-char hex string (32 bytes). For AES-192 pass 48 hex chars. For AES-128 pass 32 hex chars.
- iv (hex): Use `randomIVHex(bytes)` to generate a hex IV. `aesEncrypt`/`aesDecrypt` accept hex IVs or the legacy latin1 string returned by `randomIV()`.

If you want a self-contained token format (ciphertext + iv + meta) I can add helper functions to wrap those fields into one compact envelope for easier transport.

## Security notes & recommendations

- Prefer AES-256 and hex-formatted keys/IVs for clarity.
- Do not store private keys or secrets in client code. Keep private keys in server-side secure storage.
- Consider migrating symmetric layer to an AEAD (XChaCha20-Poly1305 via libsodium) for authenticated encryption and fewer configuration pitfalls — I can implement this migration if you want.

## Development & tests

```powershell
npm install
npm run build
npm test
```

## Contributing

- Create a branch, open a PR, and include tests for new features. The repository already contains unit tests for AES, RSA (legacy), sodium sealed-box, and hybrid flows.

## Questions / next steps

- Want me to migrate symmetric encryption to libsodium AEAD (recommended)?
- Want a small example Next.js repo demonstrating both client and server usage?

Open an issue or PR on the repo and I’ll help.
