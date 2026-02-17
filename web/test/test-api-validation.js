const inslash = require('inslash');
require('dotenv').config();

console.log('\n🧪 Testing API Key Validation\n');
console.log('='.repeat(60));

async function testInvalidAPIKey() {
    console.log('\n📍 TEST 1: Invalid API Key (should FAIL)');
    console.log('-'.repeat(60));

    // Configure with INVALID API key
    inslash.configure({
        apiKey: 'invalid_key_12345',
        apiUrl: process.env.INSLASH_API_URL || 'http://localhost:3000'
    });

    console.log('API URL:', process.env.INSLASH_API_URL || 'http://localhost:3000');
    console.log('API Key: invalid_key_12345 (INVALID)');

    try {
        console.log('\nAttempting to hash password...');
        const result = await inslash.hash('test-password', process.env.HASH_PEPPER);
        console.log('⚠️  Hash succeeded (fell back to local mode)');
        console.log('   Passport:', result.passport.substring(0, 40) + '...');
    } catch (error) {
        console.error('❌ Hash failed:', error.message);
    }
}

async function testValidAPIKey() {
    console.log('\n📍 TEST 2: Valid API Key (should SUCCEED)');
    console.log('-'.repeat(60));

    // Configure with VALID API key
    inslash.configure({
        apiKey: process.env.INSLASH_API_KEY || 'inslash_test_key_12345',
        apiUrl: process.env.INSLASH_API_URL || 'http://localhost:3000'
    });

    console.log('API URL:', process.env.INSLASH_API_URL || 'http://localhost:3000');
    console.log('API Key:', process.env.INSLASH_API_KEY || 'inslash_test_key_12345');

    try {
        console.log('\nAttempting to hash password...');
        const result = await inslash.hash('test-password', process.env.HASH_PEPPER);
        console.log('✅ Hash succeeded via API');
        console.log('   Passport:', result.passport.substring(0, 40) + '...');

        console.log('\nAttempting to verify password...');
        const verification = await inslash.verify('test-password', result.passport, process.env.HASH_PEPPER);
        console.log('✅ Verification:', verification.valid ? 'VALID' : 'INVALID');
    } catch (error) {
        console.error('❌ Error:', error.message);
    }
}

async function testNoAPIKey() {
    console.log('\n📍 TEST 3: No API Key (should use local mode)');
    console.log('-'.repeat(60));

    // Reset configuration
    inslash.configure({
        apiKey: null,
        apiUrl: null
    });

    console.log('API Mode: DISABLED (using local crypto)');

    try {
        console.log('\nHashing password locally...');
        const result = await inslash.hash('test-password', process.env.HASH_PEPPER);
        console.log('✅ Hash succeeded (local mode)');
        console.log('   Passport:', result.passport.substring(0, 40) + '...');
    } catch (error) {
        console.error('❌ Error:', error.message);
    }
}

async function runTests() {
    await testInvalidAPIKey();
    await testValidAPIKey();
    await testNoAPIKey();

    console.log('\n' + '='.repeat(60));
    console.log('✅ All tests complete!\n');
}

runTests();
