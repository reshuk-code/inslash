const mongoose = require('mongoose');
const User = require('../models/User');
const Project = require('../models/Project');
require('dotenv').config({ path: '../.env' });

async function seed() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('✅ MongoDB connected');

        // Create test user
        let user = await User.findOne({ email: 'test@inslash.com' });
        if (!user) {
            user = await User.create({
                username: 'testuser',
                email: 'test@inslash.com',
                passport: 'placeholder',
                active: true
            });
            console.log('✅ Test user created');
        } else {
            console.log('ℹ️ Test user already exists');
        }

        // Create API key within a Project
        const apiKeyString = 'inslash_test_key_12345';

        // Check if project exists
        let project = await Project.findOne({ 'apiKeys.key': apiKeyString });

        if (!project) {
            await Project.create({
                name: 'Test Project',
                description: 'Project for testing API keys',
                userId: user._id,
                apiKeys: [{
                    key: apiKeyString,
                    name: 'Test Key',
                    createdAt: new Date(),
                    usage: { count: 0, hashes: 0, verifications: 0 }
                }],
                settings: {
                    defaultIterations: 100000,
                    defaultAlgorithm: 'sha256'
                }
            });
            console.log('✅ Test Project with API key created:', apiKeyString);
        } else {
            console.log('ℹ️ Test Project with API key already exists');
        }

        console.log('🌱 Seed complete');
        process.exit(0);
    } catch (error) {
        console.error('❌ Seed failed:', error);
        process.exit(1);
    }
}

seed();
