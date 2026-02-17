const Project = require('../models/Project');

const authenticateApiKey = async (req, res, next) => {
    // Skip auth for public paths
    if (req.path === '/' || req.path === '/health') {
        return next();
    }

    const apiKey = req.headers['x-api-key'];

    if (!apiKey) {
        return res.status(401).json({
            error: 'UNAUTHORIZED',
            message: 'API key is required. Include x-api-key header.'
        });
    }

    try {
        // Find the API key in Projects collection
        const keyDoc = await Project.findByKey(apiKey);

        if (!keyDoc) {
            return res.status(403).json({
                error: 'FORBIDDEN',
                message: 'Invalid API key'
            });
        }

        // Update usage statistics (simplified)
        // Note: keyDoc.save() is a wrapper we made in Project.js to save the parent doc
        keyDoc.usage.count += 1;

        // Track specific endpoint
        if (req.path.includes('/hash')) {
            keyDoc.usage.hashes += 1;
        } else if (req.path.includes('/verify')) {
            keyDoc.usage.verifications += 1;
        }

        await keyDoc.save();

        // Attach to request
        req.apiKey = keyDoc;

        next();
    } catch (error) {
        console.error('Auth error:', error);
        res.status(500).json({
            error: 'SERVER_ERROR',
            message: 'Authentication failed'
        });
    }
};

module.exports = {
    authenticateApiKey
};