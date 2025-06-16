# 🏆 @bepalo/jwt

[![npm version](https://img.shields.io/npm/v/@bepalo/jwt.svg)](https://www.npmjs.com/package/@bepalo/jwt)
[![CI](https://github.com/nati-esh-zed/bepalo--jwt/actions/workflows/ci.yaml/badge.svg)](https://github.com/nati-esh-zed/bepalo--jwt/actions)
[![Tests](https://img.shields.io/github/actions/workflow/status/nati-esh-zed/bepalo--jwt/ci.yaml?label=tests&style=flat-square)](https://github.com/nati-esh-zed/bepalo--jwt/actions/workflows/ci.yaml.yml)
[![license](https://img.shields.io/npm/l/@bepalo/jwt.svg)](LICENSE)

JsonWebToken utility class and helpers for signing, verifying, and decoding JWT payloads.

## 📥 Install

```bash
pnpm add @bepalo/jwt
```

```bash
npm install @bepalo/jwt
```

## ✨ Features

- 🎯 JWT sign and verify with HMAC, ECDSA, RSA, RSA-PSS algorithms
- 🗝️ Easy key generation support
- ⌚ Time helper functions from [@bepalo/time](https://github.com/nati-esh-zed/bepalo--time)
- 🔃 Synchronous by default
- 📄 Written in modern TypeScript

## ✅ Usage

```ts
import { JWT, JwtError } from "@bepalo/jwt";

const payload = { userId: 123, role: "admin" };
const alg = "HS256";
const key = JWT.genKey(alg);
const jwt = JWT.create<typeof payload>(key, alg);

const token = jwt.sign({
  ...payload,
  exp: JWT.in(1).Minute,
  iat: JWT.now(),
  jti: "jti-1234",
  iss: "auth-server",
  sub: "session",
  aud: ["auth-client-a", "auth-client-b"],
});

// verify signature only. Does not set payload
const { valid: signatureValid, reason: reason_ } = jwt.verifySignature(token);

// verify signature and claims and return payload
const { valid, payload: decoded, reason } = jwt.verify(token);

// handle invalid token
if (!valid) {
  throw new JwtError(reason);
}

// log
typeof key === "string"
  ? console.log(key)
  : console.log(key.publicKey, key.privateKey);

console.log({
  alg,
  token,
  len: token.length,
  signatureValid,
  valid,
  decoded,
});
```

## Quick Docs

```ts
import type { RelativeTime } from "@bepalo/time";

class JWT<Payload> {
  /** Generate a random key for HMAC */
  static genHmacKey(alg): string;
  /** Generate a random key pair for ECDSA, RSA and RSA-PSS */
  static genKeyPair(alg, options?): KeyPair;
  /** Generate a random key for HMAC or a key pair for ECDSA, RSA and RSA-PSS */
  static genKey(alg, options?): KeyPair | string;
  /** Create JWT with symmetric keys and algorithm. */
  static createSymmetric<Payload>(key, alg): JWT<Payload>;
  /** Create JWT with asymmetric keys and algorithm. */
  static createAsymmetric<Payload>(key, alg): JWT<Payload>;
  /** Create JWT with symmetric or asymmetric keys and algorithm. */
  static create<Payload>(key, alg): JWT<Payload>;

  /** Get the current time in seconds. */
  static now(): number;
  /** Get the relative time in seconds. */
  static for(): RelativeTime;
  /** Get the relative time in seconds. */
  static in(): RelativeTime;
  /** Get the relative time in seconds. */
  static after(): RelativeTime;
  /** Get the relative time in seconds. */
  static before(): RelativeTime;

  /** Sign a payload and return a JWT token string. */
  sign(payload): string;
  /** Verify only the signature of the token (no claims checked). */
  verifySignature(token, verifyJwt?): JwtResult<Payload>;
  /** Verify a token  including signature and claims. */
  verify(token, verifyJwt?): JwtResult<Payload>;
}
```

## 🕊️ Thanks and Enjoy

If you like this library and want to support then please give a star on [GitHub](https://github.com/nati-esh-zed/bepalo--jwt).
