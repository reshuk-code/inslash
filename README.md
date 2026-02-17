# inslash

A modern, upgradeable, and secure password hashing utility for Node.js.  
Features passport encoding, hash ancestry, salt, pepper, and automatic upgrade support.

## Features

- Secure password hashing with salt and pepper
- Passport encoding (all hash info in one string)
- Hash ancestry/history for upgrades and audits
- Automatic upgrade detection and rehashing
- Async API

## Installation

```sh
npm install inslash
```

## Usage

```js
const { hash, verify } = require("inslash");

const secret = "your-secret-key";

// Hash a password
const result = await hash("myPassword", secret);

// Store result.passport in your database

// Verify a password
const verifyResult = await verify("myPassword", result.passport, secret);

console.log(verifyResult.valid); // true or false
```

## API Mode (Hosted Hashing)

`inslash` can connect to a hosted API for password hashing, with automatic fallback to local crypto if the API is unavailable.

### Setup

```js
const inslash = require('inslash');
require("dotenv").config();

// 1. Configure (Global)
inslash.configure({
    apiKey: process.env.INSLASH_API_KEY,
    apiUrl: 'https://inslash-q5s6.vercel.app' // Hosted Instance
});

// 2. Destructure after configuration (optional, but cleaner)
const { hash, verify } = inslash;

async function example() {
    // This now automatically uses the API!
    const result = await hash('password123', process.env.HASH_PEPPER);
    console.log(result.passport);

    const isValid = await verify('password123', result.passport, process.env.HASH_PEPPER);
    console.log(isValid.valid); // true
}

example();
```

### How It Works

1. **API First**: When configured, `hash()` and `verify()` call your hosted API
2. **Silent Fallback**: If the API is down or slow, falls back to local crypto automatically
3. **Zero Config Local**: If not configured, uses local crypto only (no secret needed from you)

### Get an API Key

Visit [https://inslash-q5s6.vercel.app](https://inslash-q5s6.vercel.app) to create a project and get your API key.

## API

### `configure(options)`
- `options.apiKey` (string): Your Inslash API key.
- `options.apiUrl` (string): API endpoint URL.
- **Returns:** Current configuration object.
- **Note:** Call this once before using `hash()` or `verify()` to enable API mode.

### `async hash(value, secret, options?)`
- `value` (string): The value to hash.
- `secret` (string): Secret key for HMAC.
- `options` (object): Optional. Override defaults (`iterations`, `algorithm`, etc).
- **Returns:** `{ passport, algorithm, iterations, saltLength, hashLength, salt, hash, history }`

### `async verify(value, passport, secret, options?)`
- `value` (string): Value to verify.
- `passport` (string): Encoded hash passport.
- `secret` (string): Secret key for HMAC.
- `options` (object): Optional. Override defaults.
- **Returns:** `{ valid, needsUpgrade, upgradedPassport }`

### Environment Variables

- `HASH_PEPPER`: Optional. Adds a global pepper to all hashes.

## License

MIT