require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./models/User');

async function checkUsers() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('✅ Connected to MongoDB');

        const users = await User.find({});
        console.log(`\n📊 Found ${users.length} user(s) in database:\n`);

        for (const user of users) {
            console.log('-----------------------------------');
            console.log('Username:', user.username);
            console.log('Email:', user.email);
            console.log('Passport exists:', !!user.passport);
            console.log('Passport value:', user.passport ? user.passport.substring(0, 50) + '...' : 'UNDEFINED');

            if (user.passport) {
                const parts = user.passport.split('$');
                console.log('Passport parts count:', parts.length);
                console.log('Passport parts:', parts.map((p, i) => `[${i}]: ${p.substring(0, 20)}${p.length > 20 ? '...' : ''}`));
            }

            console.log('Created at:', user.createdAt);
            console.log('Active:', user.isActive);
        }

        console.log('\n-----------------------------------');

        // Check for users with undefined passport
        const corruptedUsers = users.filter(u => !u.passport);
        if (corruptedUsers.length > 0) {
            console.log(`\n⚠️  WARNING: Found ${corruptedUsers.length} user(s) with undefined passport!`);
            console.log('These users will not be able to log in.');
            console.log('You should delete these users and have them re-register.');
        }

    } catch (error) {
        console.error('❌ Error:', error);
    } finally {
        await mongoose.disconnect();
        console.log('\n✅ Disconnected from MongoDB');
    }
}

checkUsers();
