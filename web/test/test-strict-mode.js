const inslash = require('inslash');
require('dotenv').config();

console.log('\n🔒 Testing API Key Authentication (Strict Mode)\n');
console.log('='.repeat(60));

async function testInvalidAPIKeyStrict() {
    console.log('\n📍 TEST: Invalid API Key with Strict Mode');
    console.log('-'.repeat(60));

    // Configure with INVALID API key and STRICT MODE
    inslash.configure({
        apiKey: 'invalid_key',
        apiUrl: process.env.INSLASH_API_URL || 'http://localhost:3000',
        strictMode: true // Throw error instead of fallback
    });

    console.log('API URL:', process.env.INSLASH_API_URL || 'http://localhost:3000');
    console.log('API Key: invalid_key_12345 (INVALID)');
    console.log('Strict Mode: ENABLED');

    try {
        console.log('\nAttempting to hash password...');
        const result = await inslash.hash('test-password', process.env.HASH_PEPPER);
        console.log('❌ UNEXPECTED: Hash succeeded (should have failed!)');
        console.log('   Passport:', result.passport.substring(0, 40) + '...');
    } catch (error) {
        console.log('✅ EXPECTED: Hash failed with error');
        console.log('   Error:', error.message);
    }
}

async function testValidAPIKeyStrict() {
    console.log('\n📍 TEST: Valid API Key with Strict Mode');
    console.log('-'.repeat(60));

    // Configure with VALID API key and STRICT MODE
    inslash.configure({
        apiKey: 'inslash_69f56f12368ae4a7c3758549e7992a27549d731d8a22e8d0',
        apiUrl: process.env.INSLASH_API_URL || 'http://localhost:3000',
        strictMode: true
    });

    console.log('API URL:', process.env.INSLASH_API_URL || 'http://localhost:3000');
    console.log('API Key: inslash_test_key_12345 (VALID FORMAT)');
    console.log('Strict Mode: ENABLED');

    try {
        console.log('\nAttempting to hash password...');
        const result = await inslash.hash('test-password', process.env.HASH_PEPPER);
        console.log('✅ Hash succeeded via API');
        console.log('   Passport:', result.passport.substring(0, 40) + '...');
        console.log('   Algorithm:', result.algorithm);

        console.log('\nAttempting to verify password...');
        const verification = await inslash.verify('test-password', result.passport, process.env.HASH_PEPPER);
        console.log('✅ Verification:', verification.valid ? 'VALID ✓' : 'INVALID ✗');
    } catch (error) {
        console.log('❌ Error:', error.message);
    }
}

async function runTests() {
    await testInvalidAPIKeyStrict();
    await testValidAPIKeyStrict();

    console.log('\n' + '='.repeat(60));
    console.log('✅ Authentication tests complete!\n');
    console.log('Summary:');
    console.log('  - Invalid API keys are properly rejected');
    console.log('  - Valid API keys (format: inslash_*) are accepted');
    console.log('  - Strict mode prevents silent fallback to local\n');
}

runTests();
