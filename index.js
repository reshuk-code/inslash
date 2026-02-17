const crypto = require("crypto");
const https = require("https");
const http = require("http");

// Module-level configuration for API mode
let CONFIG = {
    apiKey: null,
    apiUrl: null,
    strictMode: false // If true, throw error instead of falling back to local
};

const DEFAULTS = {
    saltLength: 16,
    hashLength: 32,
    iterations: 100_000,
    algorithm: "sha256",
    encoding: "hex" // New: support for different encodings
};

const SUPPORTED_ALGORITHMS = ["sha256", "sha512", "sha384"];
const SUPPORTED_ENCODINGS = ["hex", "base64", "base64url", "latin1"];

const createSalt = (length) => crypto.randomBytes(length).toString("hex");

// New: Generate a secure API key
const generateApiKey = (options = {}) => {
    const {
        prefix = "inslash",
        length = 32,
        encoding = "hex"
    } = options;

    const random = crypto.randomBytes(length).toString(encoding);
    return prefix ? `${prefix}_${random}` : random;
};

// New: Hash with timing attack protection info
const hashWithSalt = async (value, salt, secret, options) => {
    const { iterations, hashLength, algorithm, encoding = "hex" } = options;
    let data = value + salt;
    let digest = Buffer.from(data);

    console.time(`Hash operation (${iterations} iterations)`);
    for (let i = 0; i < iterations; i++) {
        digest = crypto.createHmac(algorithm, secret).update(digest).digest();
    }
    console.timeEnd(`Hash operation (${iterations} iterations)`);

    const result = digest.toString(encoding).slice(0, hashLength);

    return {
        hash: result,
        timing: iterations, // For informational purposes
        algorithm
    };
};

// Enhanced: Passport encoding with versioning
const encodePassport = (meta) => {
    const history = Buffer.from(JSON.stringify(meta.history || [])).toString("base64");
    const parts = [
        "$inslash",
        meta.version || "1",
        meta.algorithm,
        meta.iterations,
        meta.saltLength,
        meta.hashLength,
        meta.salt,
        meta.hash,
        history
    ];

    // Add optional metadata if present
    if (meta.encoding) parts.push(meta.encoding);

    return parts.join("$");
};

// Enhanced: Decode with backward compatibility
const decodePassport = (passport) => {
    const parts = passport.split("$");
    if (parts[1] !== "inslash") throw new Error("Invalid passport format");

    // Detect format: check if parts[2] is a numeric version or an algorithm name
    // Legacy format: $inslash$algorithm$iterations$...
    // New format: $inslash$version$algorithm$iterations$...
    const isLegacyFormat = SUPPORTED_ALGORITHMS.includes(parts[2]);

    if (isLegacyFormat) {
        // Legacy format without explicit version
        const [, , algorithm, iterations, saltLength, hashLength, salt, hash, history] = parts;
        return {
            version: "1",
            algorithm,
            iterations: Number(iterations),
            saltLength: Number(saltLength),
            hashLength: Number(hashLength),
            salt,
            hash,
            history: history ? JSON.parse(Buffer.from(history, "base64").toString()) : []
        };
    } else {
        // New format with explicit version
        const version = parts[2];
        const [, , , algorithm, iterations, saltLength, hashLength, salt, hash, history, encoding] = parts;
        return {
            version,
            algorithm,
            iterations: Number(iterations),
            saltLength: Number(saltLength),
            hashLength: Number(hashLength),
            salt,
            hash,
            history: history ? JSON.parse(Buffer.from(history, "base64").toString()) : [],
            encoding: encoding || "hex"
        };
    }
};

// Helper: Call API endpoint
const callAPI = (endpoint, body) => {
    return new Promise((resolve, reject) => {
        const url = new URL(endpoint, CONFIG.apiUrl);
        const client = url.protocol === 'https:' ? https : http;

        const postData = JSON.stringify(body);
        const options = {
            hostname: url.hostname,
            port: url.port || (url.protocol === 'https:' ? 443 : 80),
            path: url.pathname,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': CONFIG.apiKey,
                'Content-Length': Buffer.byteLength(postData)
            },
            timeout: 10000
        };

        const req = client.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    try {
                        resolve(JSON.parse(data));
                    } catch (e) {
                        reject(new Error('Invalid JSON response'));
                    }
                } else {
                    reject(new Error(`API error: ${res.statusCode}`));
                }
            });
        });

        req.on('error', reject);
        req.on('timeout', () => {
            req.destroy();
            reject(new Error('API request timeout'));
        });

        req.write(postData);
        req.end();
    });
};

// Configure API mode
const configure = (options = {}) => {
    const { apiKey, apiUrl, strictMode } = options;

    if (apiKey) CONFIG.apiKey = apiKey;
    if (apiUrl) CONFIG.apiUrl = apiUrl;
    if (typeof strictMode !== 'undefined') CONFIG.strictMode = strictMode;

    return CONFIG;
};

// Enhanced: Hash function with more options and API support
const hash = async (value, secret, opts = {}) => {
    if (typeof value !== "string" || !value) throw new Error("Value to hash must be a non-empty string");

    // API Mode: Try API first if configured
    if (CONFIG.apiKey && CONFIG.apiUrl) {
        try {
            const apiResult = await callAPI('/api/hash', {
                value,
                secret,
                options: opts
            });
            return apiResult;
        } catch (error) {
            // In strict mode, throw the error instead of falling back
            if (CONFIG.strictMode) {
                throw new Error(`API hash failed: ${error.message}`);
            }
            // Silent fallback to local crypto
            console.warn('API hash failed, falling back to local:', error.message);
        }
    }

    // Local Mode: Original crypto implementation
    if (!secret) throw new Error("Secret key is required");

    // Validate algorithm
    if (opts.algorithm && !SUPPORTED_ALGORITHMS.includes(opts.algorithm)) {
        throw new Error(`Unsupported algorithm: ${opts.algorithm}. Supported: ${SUPPORTED_ALGORITHMS.join(", ")}`);
    }

    // Validate encoding
    if (opts.encoding && !SUPPORTED_ENCODINGS.includes(opts.encoding)) {
        throw new Error(`Unsupported encoding: ${opts.encoding}. Supported: ${SUPPORTED_ENCODINGS.join(", ")}`);
    }

    const options = { ...DEFAULTS, ...opts };
    const salt = createSalt(options.saltLength);
    const pepper = process.env.HASH_PEPPER || "";
    const valueWithPepper = value + pepper;

    const { hash: hashed } = await hashWithSalt(valueWithPepper, salt, secret, options);

    const meta = {
        version: "2",
        algorithm: options.algorithm,
        iterations: options.iterations,
        saltLength: options.saltLength,
        hashLength: options.hashLength,
        salt,
        hash: hashed,
        encoding: options.encoding,
        history: [
            {
                date: new Date().toISOString(),
                algorithm: options.algorithm,
                iterations: options.iterations,
                encoding: options.encoding
            }
        ]
    };

    return {
        passport: encodePassport(meta),
        ...meta
    };
};

// Enhanced: Verify with more detailed response and API support
const verify = async (value, passport, secret, opts = {}) => {
    // API Mode: Try API first if configured
    if (CONFIG.apiKey && CONFIG.apiUrl) {
        try {
            const apiResult = await callAPI('/api/verify', {
                value,
                passport,
                secret,
                options: opts
            });
            return apiResult;
        } catch (error) {
            // In strict mode, throw the error instead of falling back
            if (CONFIG.strictMode) {
                throw new Error(`API verify failed: ${error.message}`);
            }
            // Silent fallback to local crypto
            console.warn('API verify failed, falling back to local:', error.message);
        }
    }

    // Local Mode: Original crypto implementation
    const meta = decodePassport(passport);
    const options = {
        algorithm: meta.algorithm,
        iterations: meta.iterations,
        saltLength: meta.saltLength,
        hashLength: meta.hashLength,
        encoding: meta.encoding || "hex",
        ...opts
    };

    const pepper = process.env.HASH_PEPPER || "";
    const valueWithPepper = value + pepper;

    const { hash: computed } = await hashWithSalt(valueWithPepper, meta.salt, secret, options);

    // Use timing-safe comparison
    const valid = crypto.timingSafeEqual(
        Buffer.from(computed, options.encoding),
        Buffer.from(meta.hash, meta.encoding || "hex")
    );

    let needsUpgrade = false;
    let upgradeReasons = [];

    if (opts.iterations && opts.iterations > meta.iterations) {
        needsUpgrade = true;
        upgradeReasons.push(`iterations (${meta.iterations} -> ${opts.iterations})`);
    }
    if (opts.algorithm && opts.algorithm !== meta.algorithm) {
        needsUpgrade = true;
        upgradeReasons.push(`algorithm (${meta.algorithm} -> ${opts.algorithm})`);
    }
    if (opts.encoding && opts.encoding !== meta.encoding) {
        needsUpgrade = true;
        upgradeReasons.push(`encoding (${meta.encoding} -> ${opts.encoding})`);
    }

    let upgradedPassport = null;
    let upgradedMetadata = null;

    if (valid && needsUpgrade) {
        const newMeta = { ...meta, ...opts };
        newMeta.history = (meta.history || []).concat([
            {
                date: new Date().toISOString(),
                algorithm: opts.algorithm || meta.algorithm,
                iterations: opts.iterations || meta.iterations,
                encoding: opts.encoding || meta.encoding,
                reason: "security upgrade"
            }
        ]);

        const newSalt = createSalt(newMeta.saltLength);
        const { hash: newHash } = await hashWithSalt(valueWithPepper, newSalt, secret, newMeta);

        newMeta.salt = newSalt;
        newMeta.hash = newHash;
        newMeta.version = "2";

        upgradedPassport = encodePassport(newMeta);
        upgradedMetadata = {
            algorithm: newMeta.algorithm,
            iterations: newMeta.iterations,
            encoding: newMeta.encoding
        };
    }

    return {
        valid,
        needsUpgrade,
        upgradeReasons,
        upgradedPassport,
        upgradedMetadata,
        metadata: {
            algorithm: meta.algorithm,
            iterations: meta.iterations,
            encoding: meta.encoding,
            hashLength: meta.hashLength,
            saltLength: meta.saltLength
        }
    };
};

// New: Batch verify multiple values against same passport
const batchVerify = async (values, passport, secret, opts = {}) => {
    const results = [];
    for (const value of values) {
        try {
            const result = await verify(value, passport, secret, opts);
            results.push({
                value,
                valid: result.valid,
                needsUpgrade: result.needsUpgrade
            });
        } catch (error) {
            results.push({
                value,
                error: error.message,
                valid: false
            });
        }
    }
    return results;
};

// New: Extract metadata without verification
const inspectPassport = (passport) => {
    try {
        const meta = decodePassport(passport);
        return {
            valid: true,
            ...meta,
            history: meta.history || []
        };
    } catch (error) {
        return {
            valid: false,
            error: error.message
        };
    }
};

// New: Compare two passports
const comparePassports = (passport1, passport2) => {
    try {
        const meta1 = decodePassport(passport1);
        const meta2 = decodePassport(passport2);

        return {
            sameAlgorithm: meta1.algorithm === meta2.algorithm,
            sameIterations: meta1.iterations === meta2.iterations,
            sameSalt: meta1.salt === meta2.salt,
            sameHash: meta1.hash === meta2.hash,
            sameEncoding: (meta1.encoding || "hex") === (meta2.encoding || "hex"),
            完全相同: meta1.hash === meta2.hash && meta1.salt === meta2.salt
        };
    } catch (error) {
        return {
            error: error.message,
            identical: false
        };
    }
};

// New: Estimate security strength
const estimateSecurity = (passport) => {
    try {
        const meta = decodePassport(passport);
        const now = new Date();
        const year = now.getFullYear();

        // Rough estimate of security level
        let score = 0;
        let recommendations = [];

        // Algorithm score
        if (meta.algorithm === "sha512") score += 40;
        else if (meta.algorithm === "sha384") score += 35;
        else if (meta.algorithm === "sha256") score += 30;

        // Iterations score (based on year)
        if (meta.iterations >= 300000) score += 40;
        else if (meta.iterations >= 200000) score += 35;
        else if (meta.iterations >= 150000) score += 30;
        else if (meta.iterations >= 100000) score += 25;
        else {
            score += 15;
            recommendations.push("Increase iterations (current: " + meta.iterations + ")");
        }

        // Salt length
        if (meta.saltLength >= 32) score += 20;
        else if (meta.saltLength >= 16) score += 15;
        else {
            score += 5;
            recommendations.push("Increase salt length (current: " + meta.saltLength + ")");
        }

        // Hash length
        if (meta.hashLength >= 32) score += 10;

        let level = "Weak";
        if (score >= 90) level = "Excellent";
        else if (score >= 75) level = "Strong";
        else if (score >= 60) level = "Good";
        else if (score >= 40) level = "Fair";

        return {
            score,
            level,
            recommendations,
            metadata: {
                algorithm: meta.algorithm,
                iterations: meta.iterations,
                saltLength: meta.saltLength,
                hashLength: meta.hashLength
            }
        };
    } catch (error) {
        return {
            error: error.message,
            score: 0,
            level: "Invalid"
        };
    }
};

// Export everything
module.exports = {
    // Core functions
    hash,
    verify,
    encodePassport,
    decodePassport,

    // API configuration
    configure,

    // New enhanced functions
    batchVerify,
    inspectPassport,
    comparePassports,
    estimateSecurity,
    generateApiKey,

    // Utilities
    DEFAULTS,
    SUPPORTED_ALGORITHMS,
    SUPPORTED_ENCODINGS,

    // Version info
    VERSION: "1.2.0"
};