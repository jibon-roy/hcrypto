# joycrypto-hybrid

A hybrid AES + RSA encryption library usable from both JavaScript and TypeScript projects. This package ships prebuilt CommonJS and ESM bundles plus TypeScript declarations so it can be consumed by both kinds of projects.

## Install

Run in your project root:

```powershell
npm install joycrypto-hybrid
# or
pnpm add joycrypto-hybrid
```

## Usage (TypeScript)

```ts
import { HybridEncryptConfig, AESConfig, RSAKeyPair } from "joycrypto-hybrid";
import { generateKeyPair } from "joycrypto-hybrid";

const rsa = generateKeyPair();
const aes: AESConfig = {
  secretKey: "0123456789abcdef0123456789abcdef",
  iv: "0123456789abcdef",
  salt: "mysalt",
  algorithm: "aes-256-cbc",
};

const config: HybridEncryptConfig = { aes, rsa };
// use library functions...
```

## Usage (JavaScript - CJS)

```js
const jc = require("joycrypto-hybrid");
// use jc.* exports
```

### Usage in an Express.js server

Below is a minimal example showing how to expose simple encrypt/decrypt endpoints using Express. This runs on the server (Node.js) and uses the library's Node crypto-based APIs.

```js
const express = require("express");
const bodyParser = require("body-parser");
const {
  generateKeyPair,
  randomKey,
  randomIV,
  hybridEncrypt,
  hybridDecrypt,
} = require("joycrypto-hybrid");

const app = express();
app.use(bodyParser.json());

// For demo purposes we generate an RSA pair in memory. In production
// you'd persist keys or use a secure KMS.
const rsa = generateKeyPair();

app.post("/encrypt", (req, res) => {
  const aes = {
    secretKey: randomKey(32),
    iv: randomIV(),
    salt: "mysalt",
    algorithm: "aes-256-cbc",
  };

  const token = hybridEncrypt(req.body, { aes, rsa });
  res.json({ token });
});

app.post("/decrypt", (req, res) => {
  const { token } = req.body;

  // When decrypting, hybridDecrypt will recover AES key/iv from the
  // encryptedKey portion using the private RSA key. Provide a minimal
  // AES config (algorithm/salt) — secretKey and iv will be merged from
  // the decrypted key info.
  const aesPlaceholder = {
    secretKey: "",
    iv: "",
    salt: "mysalt",
    algorithm: "aes-256-cbc",
  };

  const data = hybridDecrypt(token, { aes: aesPlaceholder, rsa });
  res.json({ data });
});

app.listen(3000, () => console.log("Server listening on :3000"));
```

### Usage in Next.js (API routes / server-side)

Use this library inside Next.js API routes or other server-side code (Node). Next.js API routes run on the server and can safely use Node's crypto APIs.

```js
// pages/api/encrypt.js
import {
  generateKeyPair,
  randomKey,
  randomIV,
  hybridEncrypt,
} from "joycrypto-hybrid";

const rsa = generateKeyPair();

export default function handler(req, res) {
  if (req.method !== "POST") return res.status(405).end();

  const aes = {
    secretKey: randomKey(32),
    iv: randomIV(),
    salt: "mysalt",
    algorithm: "aes-256-cbc",
  };

  const token = hybridEncrypt(req.body, { aes, rsa });
  res.status(200).json({ token });
}
```

### Using from a plain JavaScript (CommonJS) project

The package ships CJS and ESM bundles. In a plain Node.js project using CommonJS you can require and call the functions directly (example shown earlier under "Usage (JavaScript - CJS)"). Typical exports you may use:

- `generateKeyPair()` — generate an RSA key pair
- `randomKey(length)` and `randomIV()` — convenience key/IV generators
- `hybridEncrypt(data, config)` — encrypt an object
- `hybridDecrypt(token, config)` — decrypt a token

Example (CJS quick snippet):

```js
const {
  generateKeyPair,
  randomKey,
  randomIV,
  hybridEncrypt,
  hybridDecrypt,
} = require("joycrypto-hybrid");

const rsa = generateKeyPair();
const aes = {
  secretKey: randomKey(32),
  iv: randomIV(),
  salt: "mysalt",
  algorithm: "aes-256-cbc",
};

const token = hybridEncrypt({ hello: "world" }, { aes, rsa });
const data = hybridDecrypt(token, {
  aes: { secretKey: "", iv: "", salt: "mysalt", algorithm: "aes-256-cbc" },
  rsa,
});

console.log({ token, data });
```

### Browser / client-side React note

This library uses Node's built-in `crypto` module (server-side). While earlier docs mentioned client compatibility, the current implementation relies on Node APIs and is intended to run in Node.js environments (Express, Next.js API routes, server-side code). For browser-based React apps, either:

- Call a server API (Express/Next.js) that uses this library to perform encryption/decryption, or
- Use a browser-friendly crypto library (Web Crypto API or a dedicated browser library) if you need client-side cryptography.

If you need help adapting the library for browser usage or adding a browser-friendly build, say so and I can propose changes.

## Building locally (for contributors)

1. Install dev deps:

```powershell
npm install
```

2. Build (produces `dist/` with CJS/ESM bundles and `.d.ts` files):

```powershell
npm run build
```

3. Clean:

```powershell
npm run clean
```

## Notes

- The package exports both ESM and CJS entrypoints and provides `dist/index.d.ts` for TypeScript users.
- CI: Consider adding a GitHub Actions workflow that runs `npm ci && npm run build && npm test` on push.

## Next steps / Suggestions

- Publish a release and verify install in a downstream JS and TS project.
- Optionally add a browser-friendly UMD bundle if you target direct <script> usage.
