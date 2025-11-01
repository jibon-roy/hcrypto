# @joycrypto/hybrid

A hybrid AES + RSA encryption library usable from both JavaScript and TypeScript projects. This package ships prebuilt CommonJS and ESM bundles plus TypeScript declarations so it can be consumed by both kinds of projects.

## Install

Run in your project root:

```powershell
npm install @joycrypto/hybrid
# or
pnpm add @joycrypto/hybrid
```

## Usage (TypeScript)

```ts
import { HybridEncryptConfig, AESConfig, RSAKeyPair } from "@joycrypto/hybrid";
import { generateKeyPair } from "@joycrypto/hybrid";

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
const jc = require("@joycrypto/hybrid");
// use jc.* exports
```

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
