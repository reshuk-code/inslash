const express = require('express');
const router = express.Router();
const ApiKey = require('../models/ApiKey');

// Get all API keys for the authenticated user
router.get('/', async (req, res) => {
    try {
        const keys = await ApiKey.find({ 
            userId: req.userId,
            status: { $ne: 'revoked' }
        }).sort({ createdAt: -1 });

        // Don't send the actual keys, just metadata
        const safeKeys = keys.map(key => ({
            id: key._id,
            name: key.name,
            projectName: key.projectName,
            maskedKey: key.maskedKey(),
            permissions: key.permissions,
            settings: key.settings,
            usage: key.usage,
            status: key.status,
            createdAt: key.createdAt,
            lastUsed: key.usage.lastUsed,
            expiresAt: key.expiresAt
        }));

        res.json({
            success: true,
            keys: safeKeys
        });
    } catch (error) {
        console.error('Error fetching keys:', error);
        res.status(500).json({
            error: 'SERVER_ERROR',
            message: 'Failed to fetch API keys'
        });
    }
});

// Create a new API key
router.post('/create', async (req, res) => {
    try {
        const { 
            name, 
            projectName, 
            permissions, 
            settings,
            expiresIn 
        } = req.body;

        if (!name) {
            return res.status(400).json({
                error: 'BAD_REQUEST',
                message: 'API key name is required'
            });
        }

        // Calculate expiration if provided
        let expiresAt = null;
        if (expiresIn) {
            expiresAt = new Date();
            if (expiresIn === '30d') {
                expiresAt.setDate(expiresAt.getDate() + 30);
            } else if (expiresIn === '90d') {
                expiresAt.setDate(expiresAt.getDate() + 90);
            } else if (expiresIn === '1y') {
                expiresAt.setFullYear(expiresAt.getFullYear() + 1);
            }
        }

        // Create new API key
        const apiKey = new ApiKey({
            name,
            projectName: projectName || 'Default Project',
            userId: req.userId,
            permissions: permissions || ['hash', 'verify'],
            settings: {
                defaultIterations: settings?.defaultIterations || 150000,
                defaultAlgorithm: settings?.defaultAlgorithm || 'sha256',
                rateLimit: {
                    requests: settings?.rateLimit?.requests || 1000,
                    perSeconds: settings?.rateLimit?.perSeconds || 900
                }
            },
            expiresAt
        });

        await apiKey.save();

        // Return the ACTUAL key (only time it's shown)
        res.status(201).json({
            success: true,
            message: 'API key created successfully. Save this key now - it will not be shown again!',
            key: {
                id: apiKey._id,
                name: apiKey.name,
                apiKey: apiKey.key, // The actual key - only shown once!
                projectName: apiKey.projectName,
                permissions: apiKey.permissions,
                settings: apiKey.settings,
                expiresAt: apiKey.expiresAt,
                createdAt: apiKey.createdAt
            }
        });

    } catch (error) {
        console.error('Error creating API key:', error);
        res.status(500).json({
            error: 'SERVER_ERROR',
            message: 'Failed to create API key'
        });
    }
});

// Revoke an API key
router.post('/:keyId/revoke', async (req, res) => {
    try {
        const apiKey = await ApiKey.findOne({
            _id: req.params.keyId,
            userId: req.userId
        });

        if (!apiKey) {
            return res.status(404).json({
                error: 'NOT_FOUND',
                message: 'API key not found'
            });
        }

        apiKey.status = 'revoked';
        await apiKey.save();

        res.json({
            success: true,
            message: 'API key revoked successfully'
        });

    } catch (error) {
        console.error('Error revoking key:', error);
        res.status(500).json({
            error: 'SERVER_ERROR',
            message: 'Failed to revoke API key'
        });
    }
});

// Delete an API key (permanent)
router.delete('/:keyId', async (req, res) => {
    try {
        const result = await ApiKey.deleteOne({
            _id: req.params.keyId,
            userId: req.userId
        });

        if (result.deletedCount === 0) {
            return res.status(404).json({
                error: 'NOT_FOUND',
                message: 'API key not found'
            });
        }

        res.json({
            success: true,
            message: 'API key deleted permanently'
        });

    } catch (error) {
        console.error('Error deleting key:', error);
        res.status(500).json({
            error: 'SERVER_ERROR',
            message: 'Failed to delete API key'
        });
    }
});

// Update API key settings
router.patch('/:keyId', async (req, res) => {
    try {
        const { name, projectName, permissions, settings } = req.body;
        
        const apiKey = await ApiKey.findOne({
            _id: req.params.keyId,
            userId: req.userId
        });

        if (!apiKey) {
            return res.status(404).json({
                error: 'NOT_FOUND',
                message: 'API key not found'
            });
        }

        // Update fields
        if (name) apiKey.name = name;
        if (projectName) apiKey.projectName = projectName;
        if (permissions) apiKey.permissions = permissions;
        if (settings) {
            apiKey.settings = {
                ...apiKey.settings,
                ...settings
            };
        }

        await apiKey.save();

        res.json({
            success: true,
            message: 'API key updated successfully',
            key: {
                id: apiKey._id,
                name: apiKey.name,
                projectName: apiKey.projectName,
                permissions: apiKey.permissions,
                settings: apiKey.settings,
                maskedKey: apiKey.maskedKey()
            }
        });

    } catch (error) {
        console.error('Error updating key:', error);
        res.status(500).json({
            error: 'SERVER_ERROR',
            message: 'Failed to update API key'
        });
    }
});

// Get usage statistics for a specific key
router.get('/:keyId/stats', async (req, res) => {
    try {
        const apiKey = await ApiKey.findOne({
            _id: req.params.keyId,
            userId: req.userId
        });

        if (!apiKey) {
            return res.status(404).json({
                error: 'NOT_FOUND',
                message: 'API key not found'
            });
        }

        res.json({
            success: true,
            stats: {
                totalRequests: apiKey.usage.count,
                totalHashes: apiKey.usage.totalHashes,
                totalVerifications: apiKey.usage.totalVerifications,
                lastUsed: apiKey.usage.lastUsed,
                createdAt: apiKey.createdAt,
                status: apiKey.status
            }
        });

    } catch (error) {
        console.error('Error fetching stats:', error);
        res.status(500).json({
            error: 'SERVER_ERROR',
            message: 'Failed to fetch usage statistics'
        });
    }
});

module.exports = router;