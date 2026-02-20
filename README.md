# inslash

> Enterprise-grade, zero-dependency password hashing for Node.js — v2.0.0

Built to exceed the security and flexibility of bcrypt, argon2, and scrypt wrappers.  
Designed for zero-compromise production use at scale.

## Why inslash?

| Feature | bcrypt | argon2 | **inslash** |
|---|---|---|---|
| Zero native dependencies | ❌ | ❌ | ✅ |
| PBKDF2 + HMAC hybrid | ❌ | ❌ | ✅ |
| Automatic security upgrades | ❌ | ❌ | ✅ |
| Audit history in passport | ❌ | ❌ | ✅ |
| API mode (hosted hashing) | ❌ | ❌ | ✅ |
| Security scoring | ❌ | ❌ | ✅ |
| Batch verification | ❌ | ❌ | ✅ |
| TypeScript types | ❌ | ✅ | ✅ |

## Installation

```sh
npm install inslash
```

## Quick Start

```js
const { hash, verify } = require('inslash');

const secret = process.env.HASH_SECRET;

// Hash a password
const result = await hash('myPassword', secret);
// Store result.passport in your database

// Verify a password
const { valid } = await verify('myPassword', result.passport, secret);
console.log(valid); // true
```

## Security Presets

Use presets instead of tuning options manually:

```js
const { hash } = require('inslash');

// 'fast' | 'balanced' | 'strong' | 'paranoid'
const result = await hash('myPassword', secret, { preset: 'strong' });
```

| Preset | Algorithm | Iterations | Salt | Hash |
|---|---|---|---|---|
| `fast` | sha256 | 50,000 | 16 | 32 |
| `balanced` | sha256 | 100,000 | 16 | 32 |
| `strong` | sha384 | 200,000 | 24 | 48 |
| `paranoid` | sha512 | 400,000 | 32 | 64 |

## Automatic Security Upgrades

When security requirements change, `verify()` can automatically rehash on login — no forced password resets needed:

```js
const { valid, needsUpgrade, upgradedPassport } = await verify(
    'myPassword',
    storedPassport,
    secret,
    { preset: 'paranoid' } // new target security level
);

if (valid && needsUpgrade) {
    // Save upgradedPassport to your database
    await db.users.update({ passwordHash: upgradedPassport });
}
```

## API Mode (Hosted Hashing)

Offload hashing to the Inslash hosted API with automatic local fallback:

```js
const inslash = require('inslash');
require('dotenv').config();

inslash.configure({
    apiKey: process.env.INSLASH_API_KEY,
    apiUrl: 'https://inslash-q5s6.vercel.app',
    strictMode: false, // true = throw on API failure instead of falling back
    timeout: 10_000,
});

const { hash, verify } = inslash;

const result = await hash('password123', process.env.HASH_PEPPER);
const { valid } = await verify('password123', result.passport, process.env.HASH_PEPPER);
```

Get your API key at [https://inslash-q5s6.vercel.app](https://inslash-q5s6.vercel.app).

## Full API Reference

### `configure(options)`

Configure API mode globally. Call once at startup.

| Option | Type | Default | Description |
|---|---|---|---|
| `apiKey` | string | — | Your Inslash API key |
| `apiUrl` | string | — | Hosted API base URL |
| `strictMode` | boolean | `false` | Throw on API failure instead of falling back |
| `timeout` | number | `10000` | Request timeout in ms |

---

### `hash(value, secret, options?)`

Hash a value. Returns a `HashResult` with a self-contained `passport` string.

```js
const result = await hash('myPassword', secret, {
    algorithm: 'sha512',   // 'sha256' | 'sha384' | 'sha512'
    iterations: 200_000,
    saltLength: 24,
    hashLength: 48,
    encoding: 'hex',       // 'hex' | 'base64' | 'base64url'
});

console.log(result.passport); // store this in your DB
```

---

### `verify(value, passport, secret, options?)`

Verify a value against a stored passport. Optionally upgrades the hash.

```js
const result = await verify('myPassword', storedPassport, secret);
// result.valid          → boolean
// result.needsUpgrade   → boolean
// result.upgradedPassport → string | null (save to DB if truthy)
// result.upgradeReasons → string[]
// result.metadata       → { algorithm, iterations, encoding, ... }
```

---

### `batchVerify(values, passport, secret, options?)`

Verify multiple values against the same passport (e.g. checking a list of candidates). Runs with concurrency control to avoid CPU starvation.

```js
const results = await batchVerify(
    ['guess1', 'guess2', 'correctPassword'],
    storedPassport,
    secret,
    { concurrency: 4 }
);
// [{ value, valid, needsUpgrade }, ...]
```

---

### `inspectPassport(passport)`

Decode a passport and read its metadata without verifying.

```js
const info = inspectPassport(storedPassport);
// { valid, version, algorithm, iterations, saltLength, hashLength, encoding, history }
```

---

### `comparePassports(passport1, passport2)`

Structurally compare two passports (does **not** verify plaintext).

```js
const cmp = comparePassports(p1, p2);
// { sameAlgorithm, sameIterations, sameEncoding, sameSalt, sameHash, identical }
```

---

### `estimateSecurity(passport)`

Score a passport's security strength and get upgrade recommendations.

```js
const { score, level, recommendations } = estimateSecurity(storedPassport);
// level: 'Excellent' | 'Strong' | 'Good' | 'Fair' | 'Weak' | 'Critical' | 'Invalid'
// recommendations: string[]
```

---

### `generateApiKey(options?)`

Generate a cryptographically secure API key.

```js
const key = generateApiKey({ prefix: 'myapp', byteLength: 32, encoding: 'hex' });
// 'myapp_a3f9...'
```

---

### `deriveKey(password, salt, opts?)`

Derive a deterministic encryption key from a password using PBKDF2. Useful for symmetric encryption, not authentication.

```js
const keyBuffer = await deriveKey(password, saltHex, {
    iterations: 200_000,
    keyLength: 32,
    algorithm: 'sha512'
});
```

---

## Environment Variables

| Variable | Description |
|---|---|
| `HASH_PEPPER` | Optional global pepper appended to all values before hashing |

## Constants

```js
const { DEFAULTS, SECURITY_PRESETS, SUPPORTED_ALGORITHMS, SUPPORTED_ENCODINGS, VERSION } = require('inslash');
```

## License

MIT