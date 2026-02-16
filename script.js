const crypto = require("crypto");

const DEFAULTS = {
    saltLength: 16,
    hashLength: 32,
    iterations: 100_000,
    algorithm: "sha256"
};

const createSalt = (length) => crypto.randomBytes(length).toString("hex");

const hashWithSalt = async (value, salt, secret, options) => {
    const { iterations, hashLength, algorithm } = options;
    let data = value + salt;
    let digest = Buffer.from(data);

    for (let i = 0; i < iterations; i++) {
        digest = crypto.createHmac(algorithm, secret).update(digest).digest();
    }

    return digest.toString("hex").slice(0, hashLength);
};

const encodePassport = (meta) => {
    const history = Buffer.from(JSON.stringify(meta.history || [])).toString("base64");
    return [
        "$inslash",
        meta.algorithm,
        meta.iterations,
        meta.saltLength,
        meta.hashLength,
        meta.salt,
        meta.hash,
        history
    ].join("$");
};

const decodePassport = (passport) => {
    const parts = passport.split("$");
    if (parts[1] !== "inslash") throw new Error("Invalid passport format");
    const [ , , algorithm, iterations, saltLength, hashLength, salt, hash, history ] = parts;
    return {
        algorithm,
        iterations: Number(iterations),
        saltLength: Number(saltLength),
        hashLength: Number(hashLength),
        salt,
        hash,
        history: JSON.parse(Buffer.from(history, "base64").toString())
    };
};

const hash = async (value, secret, opts = {}) => {
    if (!secret) throw new Error("Secret key is required");
    if (typeof value !== "string" || !value) throw new Error("Value to hash must be a non-empty string");
    const options = { ...DEFAULTS, ...opts };
    const salt = createSalt(options.saltLength);
    const pepper = process.env.HASH_PEPPER || "";
    const valueWithPepper = value + pepper;
    const hashed = await hashWithSalt(valueWithPepper, salt, secret, options);

    const meta = {
        algorithm: options.algorithm,
        iterations: options.iterations,
        saltLength: options.saltLength,
        hashLength: options.hashLength,
        salt,
        hash: hashed,
        history: [
            {
                date: new Date().toISOString(),
                algorithm: options.algorithm,
                iterations: options.iterations
            }
        ]
    };

    return {
        passport: encodePassport(meta),
        ...meta
    };
};

const verify = async (value, passport, secret, opts = {}) => {
    const meta = decodePassport(passport);
    const options = {
        algorithm: meta.algorithm,
        iterations: meta.iterations,
        saltLength: meta.saltLength,
        hashLength: meta.hashLength,
        ...opts
    };
    const pepper = process.env.HASH_PEPPER || "";
    const valueWithPepper = value + pepper;
    const computed = await hashWithSalt(valueWithPepper, meta.salt, secret, options);
    const valid = crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(meta.hash));
    let needsUpgrade = false;
    if (opts.iterations && opts.iterations > meta.iterations) needsUpgrade = true;
    if (opts.algorithm && opts.algorithm !== meta.algorithm) needsUpgrade = true;
    let upgradedPassport = null;
    if (valid && needsUpgrade) {
        const newMeta = { ...meta, ...opts };
        newMeta.history = meta.history.concat([
            {
                date: new Date().toISOString(),
                algorithm: opts.algorithm || meta.algorithm,
                iterations: opts.iterations || meta.iterations
            }
        ]);
        const newSalt = createSalt(newMeta.saltLength);
        const newHash = await hashWithSalt(valueWithPepper, newSalt, secret, newMeta);
        newMeta.salt = newSalt;
        newMeta.hash = newHash;
        upgradedPassport = encodePassport(newMeta);
    }
    return { valid, needsUpgrade, upgradedPassport };
};

module.exports = {
    hash,
    verify,
    encodePassport,
    decodePassport
};
