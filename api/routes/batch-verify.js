const express = require('express');
const router = express.Router();
const inslash = require('inslash');

/**
 * POST /api/batch-verify
 * Verify multiple values against the same passport.
 * Body: { values: string[], passport: string, secret?: string, options?: object }
 */
router.post('/', async (req, res) => {
    try {
        const { values, passport, secret, options = {} } = req.body;

        if (!Array.isArray(values) || values.length === 0) {
            return res.status(400).json({
                error: 'BAD_REQUEST',
                message: 'values must be a non-empty array of strings'
            });
        }

        if (values.length > 50) {
            return res.status(400).json({
                error: 'BAD_REQUEST',
                message: 'Maximum 50 values per batch request'
            });
        }

        if (!passport || typeof passport !== 'string') {
            return res.status(400).json({
                error: 'BAD_REQUEST',
                message: 'passport is required and must be a string'
            });
        }

        const secretToUse = secret || process.env.DEFAULT_SECRET;
        const concurrency = Math.min(options.concurrency || 4, 8); // cap at 8

        const results = await inslash.batchVerify(values, passport, secretToUse, {
            ...options,
            concurrency
        });

        const summary = {
            total: results.length,
            valid: results.filter(r => r.valid).length,
            invalid: results.filter(r => !r.valid && !r.error).length,
            errors: results.filter(r => r.error).length,
            needsUpgrade: results.filter(r => r.needsUpgrade).length,
        };

        res.json({
            success: true,
            summary,
            results
        });

    } catch (error) {
        res.status(400).json({
            error: 'BATCH_VERIFY_FAILED',
            message: error.message
        });
    }
});

module.exports = router;
