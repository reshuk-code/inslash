const mongoose = require('mongoose');

const usageLogSchema = new mongoose.Schema({
    projectId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Project',
        required: true,
        index: true
    },
    keyId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true
    },
    // Type of operation: 'hash' or 'verify'
    type: {
        type: String,
        enum: ['hash', 'verify'],
        required: true
    },
    // Status of operation: 'success', 'failed', 'error'
    status: {
        type: String,
        enum: ['success', 'failed', 'error'],
        default: 'success'
    },
    // Response time in ms (optional)
    responseTime: Number,
    // Client IP (optional, for security audits)
    ip: String,
    timestamp: {
        type: Date,
        default: Date.now,
        index: true // Important for range queries
    }
});

// TTL Index: Automatically delete logs after 30 days to manage database size
// You can adjust this or remove it if you want to keep logs forever
usageLogSchema.index({ timestamp: 1 }, { expireAfterSeconds: 30 * 24 * 60 * 60 });

module.exports = mongoose.model('UsageLog', usageLogSchema);
