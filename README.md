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

## API

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