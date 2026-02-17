const mongoose = require('mongoose');
const UsageLog = require('../models/UsageLog');
const Project = require('../models/Project');
require('dotenv').config({ path: '../.env' });

async function checkLogs() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('✅ MongoDB connected');

        const logs = await UsageLog.find().sort({ timestamp: -1 });
        console.log(`\n📊 Total Logs Found: ${logs.length}`);

        if (logs.length > 0) {
            console.log('Last 5 logs:');
            logs.slice(0, 5).forEach(log => {
                console.log(`- [${log.timestamp.toISOString()}] Type: ${log.type}, Status: ${log.status}, ID: ${log._id}`);
            });
        } else {
            console.log('⚠️ No logs found! Middleware might not be firing.');
        }

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

checkLogs();
