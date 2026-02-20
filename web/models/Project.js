const mongoose = require('mongoose');

const projectSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    description: {
        type: String,
        default: ''
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    apiKeys: [{
        key: String,
        name: String,
        createdAt: {
            type: Date,
            default: Date.now
        },
        lastUsed: Date,
        usage: {
            count: { type: Number, default: 0 },
            hashes: { type: Number, default: 0 },
            verifications: { type: Number, default: 0 },
            inspects: { type: Number, default: 0 },
            batchVerifications: { type: Number, default: 0 },
            securityChecks: { type: Number, default: 0 }
        }
    }],
    settings: {
        defaultIterations: {
            type: Number,
            default: 150000
        },
        defaultAlgorithm: {
            type: String,
            default: 'sha256'
        }
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('Project', projectSchema);