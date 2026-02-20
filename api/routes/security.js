const express = require('express');
const router = express.Router();
const inslash = require('inslash');

/**
 * POST /api/security
 * Estimate the security strength of a passport.
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

        const result = inslash.estimateSecurity(passport);

        if (result.level === 'Invalid') {
            return res.status(400).json({
                error: 'INVALID_PASSPORT',
                message: result.error || 'Could not analyse passport'
            });
        }

        // Colour hint for UI
        const levelColor = {
            Excellent: 'green',
            Strong: 'green',
            Good: 'blue',
            Fair: 'yellow',
            Weak: 'orange',
            Critical: 'red',
        }[result.level] || 'gray';

        res.json({
            success: true,
            score: result.score,
            level: result.level,
            levelColor,
            recommendations: result.recommendations,
            metadata: result.metadata
        });

    } catch (error) {
        res.status(400).json({
            error: 'SECURITY_CHECK_FAILED',
            message: error.message
        });
    }
});

module.exports = router;
