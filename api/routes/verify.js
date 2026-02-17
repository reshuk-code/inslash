const express = require('express');
const router = express.Router();
const inslash = require('inslash');

router.post('/', async (req, res) => {
    try {
        const { value, passport, secret } = req.body;

        if (!value || typeof value !== 'string' || !passport || typeof passport !== 'string') {
            return res.status(400).json({
                error: 'BAD_REQUEST',
                message: 'value and passport are required and must be strings'
            });
        }

        const secretToUse = secret || process.env.DEFAULT_SECRET;

        const result = await inslash.verify(value, passport, secretToUse);

        res.json({
            success: true,
            valid: result.valid,
            needsUpgrade: result.needsUpgrade,
            upgradedPassport: result.upgradedPassport
        });

    } catch (error) {
        res.status(400).json({
            error: 'VERIFY_FAILED',
            message: error.message
        });
    }
});

module.exports = router;