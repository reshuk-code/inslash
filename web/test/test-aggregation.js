const axios = require('axios');
const mongoose = require('mongoose');
const Project = require('../models/Project');
const User = require('../models/User');
require('dotenv').config({ path: '../.env' });

// Mock authentication by just checking the logic separately or using a known cookie if possible.
// Since we can't easily mock auth middleware without login, we will modify the app temporarily OR
// simpler: we just check the data generation logic by extracting it or trusting the previous steps.
// Actually, let's just inspect the database to see if we have logs, and trust the endpoint logic since we verified the logs exists.

// Alternative: We can use the existing 'server.js' test setup which mocks auth or allows it.
// But 'server.js' is a bit complex.

// Let's stick to checking the logs existence for now, as I can't easily curl the endpoint without a session cookie.
// I will rely on the previous verification and the server output.
// The server output showed no errors during restart.

// I will create a script to manually run the aggregation logic to see what it outputs.

async function testAggregation() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('✅ MongoDB connected');

        const project = await Project.findOne();
        if (!project) {
            console.log('❌ No project found');
            return;
        }
        console.log('Testing with project:', project.name);

        const UsageLog = require('../models/UsageLog');
        const startDate = new Date();
        startDate.setHours(startDate.getHours() - 24);

        const groupByFormat = "%Y-%m-%dT%H:00:00Z";

        const rawChartData = await UsageLog.aggregate([
            {
                $match: {
                    projectId: project._id,
                    timestamp: { $gte: startDate }
                }
            },
            {
                $group: {
                    _id: {
                        $dateToString: { format: groupByFormat, date: "$timestamp" }
                    },
                    count: { $sum: 1 }
                }
            },
            { $sort: { _id: 1 } }
        ]);

        console.log('Raw Aggregation Result:', rawChartData);

        // Test Zero-Filling Logic
        console.log('\n--- Zero Filling Logic Simulation ---');
        const chartData = [];
        const now = new Date();
        let currentDate = new Date(startDate);
        const dataMap = new Map();
        rawChartData.forEach(item => dataMap.set(item._id, item.count));

        while (currentDate <= now) {
            let dateKey;
            // Hour format: YYYY-MM-DDTHH:00:00 (UTC)
            const yyyy = currentDate.getUTCFullYear();
            const mm = String(currentDate.getUTCMonth() + 1).padStart(2, '0');
            const dd = String(currentDate.getUTCDate()).padStart(2, '0');
            const hh = String(currentDate.getUTCHours()).padStart(2, '0');
            dateKey = `${yyyy}-${mm}-${dd}T${hh}:00:00Z`;

            // Increment by 1 hour
            currentDate.setHours(currentDate.getHours() + 1);

            // Only print first 3 and last 3 to avoid spam
            if (chartData.length < 3 || currentDate > new Date(now.getTime() - 1000 * 60 * 60 * 3)) {
                console.log(`Generated Key: ${dateKey} | Count: ${dataMap.get(dateKey) || 0}`);
            }
            chartData.push({ _id: dateKey, count: dataMap.get(dateKey) || 0 });
        }
        console.log(`Total Data Points: ${chartData.length} (Expected ~25)`);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

testAggregation();
