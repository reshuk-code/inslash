const mongoose = require('mongoose');
const User = require('../models/User');
const ApiKey = require('../models/ApiKey');
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

        // Create API key
        const key = 'inslash_test_key_12345';
        const existingKey = await ApiKey.findOne({ key });

        if (!existingKey) {
            await ApiKey.create({
                key: key,
                user: user._id,
                name: 'Test Key',
                active: true
            });
            console.log('✅ Test API key created:', key);
        } else {
            console.log('ℹ️ Test API key already exists');
        }

        console.log('🌱 Seed complete');
        process.exit(0);
    } catch (error) {
        console.error('❌ Seed failed:', error);
        process.exit(1);
    }
}

seed();
