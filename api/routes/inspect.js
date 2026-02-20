const express = require('express');
const router = express.Router();
const inslash = require('inslash');

/**
 * POST /api/inspect
 * Decode a passport and return its metadata without verifying.
 * Body: { passport: string }
 */
router.post('/', (req, res) => {
    try {
        const { passport } = req.body;

        if (!passport || typeof passport !== 'string') {
            return res.status(400).json({
                error: 'BAD_REQUEST',
                message: 'passport is required and must be a string'
            });
        }

        const result = inslash.inspectPassport(passport);

        if (!result.valid) {
            return res.status(400).json({
                error: 'INVALID_PASSPORT',
                message: result.error || 'Could not decode passport'
            });
        }

        res.json({
            success: true,
            ...result
        });

    } catch (error) {
        res.status(400).json({
            error: 'INSPECT_FAILED',
            message: error.message
        });
    }
});

module.exports = router;
