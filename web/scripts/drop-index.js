const mongoose = require('mongoose');
require('dotenv').config({ path: '../.env' }); // Adjust path to .env

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/inslash';

async function fixDb() {
    try {
        console.log('Connecting to MongoDB...');
        await mongoose.connect(MONGODB_URI);
        console.log('✅ Connected.');

        const Project = require('../models/Project'); // Adjust path to Project model

        console.log('Listing indexes for Projects collection...');
        const indexes = await Project.collection.indexes();
        console.log('Current indexes:', indexes);

        const indexName = 'apiKey_1';
        const indexExists = indexes.some(idx => idx.name === indexName);

        if (indexExists) {
            console.log(`Found legacy index '${indexName}'. Dropping it...`);
            await Project.collection.dropIndex(indexName);
            console.log('✅ Index dropped successfully.');
        } else {
            console.log(`Index '${indexName}' not found. It might have already been removed.`);
        }

    } catch (error) {
        console.error('❌ Error:', error);
    } finally {
        await mongoose.disconnect();
        console.log('Disconnected.');
    }
}

fixDb();
