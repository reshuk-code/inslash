const express = require('express');
const router = express.Router();
const inslash = require('inslash');

router.post('/', async (req, res) => {
    try {
        const { value, secret, options = {} } = req.body;

        if (!value || typeof value !== 'string') {
            return res.status(400).json({
                error: 'BAD_REQUEST',
                message: 'value is required and must be a string'
            });
        }

        const secretToUse = secret || process.env.DEFAULT_SECRET;

        // Use defaults if settings are missing on the key
        const settings = req.apiKey.settings || {};

        // Fallback defaults in case inslash.DEFAULTS is missing
        const defaults = inslash.DEFAULTS || {
            iterations: 100000,
            algorithm: 'sha256',
            hashLength: 32,
            saltLength: 16
        };

        const result = await inslash.hash(value, secretToUse, {
            iterations: options.iterations || settings.defaultIterations || defaults.iterations,
            algorithm: options.algorithm || settings.defaultAlgorithm || defaults.algorithm,
            hashLength: options.hashLength || 32,
            saltLength: options.saltLength || 16
        });

        res.json({
            success: true,
            passport: result.passport,
            metadata: {
                algorithm: result.algorithm,
                iterations: result.iterations,
                saltLength: result.saltLength,
                hashLength: result.hashLength
            }
        });

    } catch (error) {
        res.status(400).json({
            error: 'HASH_FAILED',
            message: error.message
        });
    }
});

module.exports = router;