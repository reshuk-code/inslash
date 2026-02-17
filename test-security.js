const mongoose = require('mongoose');
const Project = require('./api/models/Project');
require('dotenv').config({ path: './api/.env' });

async function run() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('Connected to DB');

        const project = await Project.findOne();
        if (!project || !project.apiKeys || project.apiKeys.length === 0) {
            console.log('No API keys found. Cannot test.');
            process.exit(1);
        }

        const apiKey = project.apiKeys[0].key;
        console.log('Using API Key:', apiKey);

        // Test Helper
        async function test(endpoint, body, expectedStatus, description) {
            try {
                const res = await fetch(`http://localhost:3001/api/${endpoint}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'x-api-key': apiKey
                    },
                    body: JSON.stringify(body)
                });

                const data = await res.json();
                console.log(`[${res.status === expectedStatus ? 'PASS' : 'FAIL'}] ${description} (Status: ${res.status})`);
                if (res.status !== expectedStatus) {
                    console.log('Response:', data);
                }
            } catch (err) {
                console.error('Request failed:', err.message);
            }
        }

        // 1. Valid Request (Control)
        await test('hash', { value: 'password123' }, 200, 'Valid Hash Request');

        // 2. Invalid Type (Number) - Security Fix Test
        const numericBody = { value: 12345 };
        await test('hash', numericBody, 400, 'Invalid Type (Number) for Hash');

        // 3. Invalid Type (Object) - Security Fix Test
        const objectBody = { value: { $ne: null } }; // NoSQL Injection attempt
        await test('hash', objectBody, 400, 'Invalid Type (Object) for Hash');

        // 4. Verify Route - Invalid Type
        await test('verify', { value: 123, passport: 'valid' }, 400, 'Invalid value type for Verify');
        await test('verify', { value: 'valid', passport: 123 }, 400, 'Invalid passport type for Verify');

        process.exit(0);

    } catch (err) {
        console.error(err);
        process.exit(1);
    }
}

run();
