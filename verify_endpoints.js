const axios = require('axios');

const API_BASE = 'http://localhost:3001';
const API_KEY = 'inslash_test_key_123'; // I'll need a real key or mock it
// Actually, I can just use a real key from a project in the DB

async function runTests() {
    console.log('--- Testing API Endpoints ---');

    try {
        // 0. Setup: Get or Create an API Key
        // For simplicity, let's assume we can mock or find one.
        // I'll use a known test key if I added one, or just try to hit the server.

        const passport = '$inslash$sha256$100000$16$32$hex$76739665893375807903260799304383$9237699391038596001221711821868469389279549925242785465596395358$W10=';

        // 1. Test Hash
        console.log('\n[1] Testing /api/hash...');
        const hashRes = await axios.post(`${API_BASE}/api/hash`, {
            value: 'password123',
            secret: 'test-secret'
        }, { headers: { 'x-api-key': 'inslash_test_key' } }).catch(e => e.response);
        console.log('Status:', hashRes?.status);
        if (hashRes?.data) console.log('Data:', JSON.stringify(hashRes.data).slice(0, 100));

        // 2. Test Inspect
        console.log('\n[2] Testing /api/inspect...');
        const inspectRes = await axios.post(`${API_BASE}/api/inspect`, {
            passport: passport
        }, { headers: { 'x-api-key': 'inslash_test_key' } }).catch(e => e.response);
        console.log('Status:', inspectRes?.status);
        if (inspectRes?.data) console.log('Data:', inspectRes.data);

        // 3. Test Batch Verify
        console.log('\n[3] Testing /api/batch-verify...');
        const batchRes = await axios.post(`${API_BASE}/api/batch-verify`, {
            values: ['p1', 'p2'],
            passport: passport,
            secret: 'test-secret'
        }, { headers: { 'x-api-key': 'inslash_test_key' } }).catch(e => e.response);
        console.log('Status:', batchRes?.status);
        if (batchRes?.data) console.log('Data:', batchRes.data.summary);

        // 4. Test Security
        console.log('\n[4] Testing /api/security...');
        const secRes = await axios.post(`${API_BASE}/api/security`, {
            passport: passport
        }, { headers: { 'x-api-key': 'inslash_test_key' } }).catch(e => e.response);
        console.log('Status:', secRes?.status);
        if (secRes?.data) console.log('Data:', secRes.data);

    } catch (err) {
        console.error('Test error:', err.message);
    }
}

runTests();
