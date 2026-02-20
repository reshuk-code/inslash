const mongoose = require('mongoose');

// Define Schema for Project (Shared with Web)
const projectSchema = new mongoose.Schema({
    apiKeys: [{
        key: String,
        name: String,
        usage: {
            count: { type: Number, default: 0 },
            hashes: { type: Number, default: 0 },
            verifications: { type: Number, default: 0 },
            inspects: { type: Number, default: 0 },
            batchVerifications: { type: Number, default: 0 },
            securityChecks: { type: Number, default: 0 }
        }
    }]
});

// Helper to find by key in the nested array
projectSchema.statics.findByKey = async function (apiKey) {
    const project = await this.findOne({
        'apiKeys.key': apiKey
    });

    if (project) {
        // Return a normalized object that middleware expects
        const keyData = project.apiKeys.find(k => k.key === apiKey);
        return {
            ...keyData.toObject(),
            projectId: project._id,
            // Add verify method or logic here if needed, but since we store plain keys in Web for now (based on Project.js), 
            // we might need to handle raw string comparison. 
            // NOTE: Real prod apps should hash keys. user's current Project.js stores plain strings?
            // Let's check Project.js line 19: key: String. 
            // If they are plain strings, direct comparison works.
            save: async () => await project.save()
        };
    }
    return null;
};

module.exports = mongoose.model('Project', projectSchema);
