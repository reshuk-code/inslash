const mongoose = require('mongoose');
const crypto = require('crypto');

const apiKeySchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    key: {
        type: String,
        unique: true,
        default: () => {
            // Generate a beautiful API key format: inslash_live_XXXXXXXXXXXX
            const random = crypto.randomBytes(24).toString('hex');
            return `inslash_live_${random}`;
        }
    },
    hashedKey: {
        type: String,
        required: true
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    projectName: {
        type: String,
        default: 'Default Project'
    },
    permissions: {
        type: [String],
        enum: ['hash', 'verify', 'decode', 'manage'],
        default: ['hash', 'verify']
    },
    settings: {
        defaultIterations: {
            type: Number,
            default: 150000
        },
        defaultAlgorithm: {
            type: String,
            enum: ['sha256', 'sha512'],
            default: 'sha256'
        },
        rateLimit: {
            requests: {
                type: Number,
                default: 1000
            },
            perSeconds: {
                type: Number,
                default: 900 // 15 minutes
            }
        }
    },
    usage: {
        count: {
            type: Number,
            default: 0
        },
        lastUsed: Date,
        totalHashes: {
            type: Number,
            default: 0
        },
        totalVerifications: {
            type: Number,
            default: 0
        }
    },
    status: {
        type: String,
        enum: ['active', 'revoked', 'expired'],
        default: 'active'
    },
    expiresAt: {
        type: Date,
        default: null // null means never expires
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Hash the API key before saving
apiKeySchema.pre('save', async function(next) {
    if (this.isModified('key')) {
        // Create a secure hash of the API key
        const salt = crypto.randomBytes(16).toString('hex');
        const hash = crypto
            .createHmac('sha256', salt)
            .update(this.key)
            .digest('hex');
        
        // Store salt + hash together
        this.hashedKey = `${salt}:${hash}`;
    }
    next();
});

// Method to verify an API key
apiKeySchema.methods.verifyKey = function(providedKey) {
    const [salt, storedHash] = this.hashedKey.split(':');
    
    const computedHash = crypto
        .createHmac('sha256', salt)
        .update(providedKey)
        .digest('hex');
    
    return crypto.timingSafeEqual(
        Buffer.from(computedHash),
        Buffer.from(storedHash)
    );
};

// Static method to find by API key
apiKeySchema.statics.findByKey = async function(apiKey) {
    // Only check active keys
    const keys = await this.find({ status: 'active' });
    
    for (const keyDoc of keys) {
        if (keyDoc.verifyKey(apiKey)) {
            return keyDoc;
        }
    }
    return null;
};

// Method to mask API key for display
apiKeySchema.methods.maskedKey = function() {
    if (!this.key) return '';
    const visible = 8;
    const masked = '*'.repeat(this.key.length - visible);
    return this.key.substring(0, visible) + masked;
};

module.exports = mongoose.model('ApiKey', apiKeySchema);