const inslash = require('inslash');
require('dotenv').config();

console.log('\n🧪 Testing Inslash API Mode\n');
console.log('='.repeat(50));

async function testWithoutAPI() {
    console.log('\n📍 TEST 1: Without API Key (Local Mode)');
    console.log('-'.repeat(50));

    try {
        const password = 'test-password-123';

        // Hash
        console.log('Hashing password...');
        const result = await inslash.hash(password, process.env.HASH_PEPPER);
        console.log('✅ Hash successful');
        console.log('   Passport:', result.passport.substring(0, 40) + '...');
        console.log('   Algorithm:', result.algorithm);
        console.log('   Iterations:', result.iterations);

        // Verify
        console.log('\nVerifying password...');
        const verification = await inslash.verify(password, result.passport, process.env.HASH_PEPPER);
        console.log('✅ Verification:', verification.valid ? 'VALID' : 'INVALID');

    } catch (error) {
        console.error('❌ Error:', error.message);
    }
}

async function testWithAPI() {
    console.log('\n📍 TEST 2: With API Key (API Mode)');
    console.log('-'.repeat(50));

    // Configure API mode
    inslash.configure({
        apiKey: process.env.INSLASH_API_KEY,
        apiUrl: process.env.INSLASH_API_URL || 'http://localhost:3000'
    });

    console.log('API URL:', process.env.INSLASH_API_URL || 'http://localhost:3000');
    console.log('API Key:', process.env.INSLASH_API_KEY ? '***' + process.env.INSLASH_API_KEY.slice(-8) : 'NOT SET');

    try {
        const password = 'api-test-password-456';

        // Hash
        console.log('\nHashing password via API...');
        const result = await inslash.hash(password, process.env.HASH_PEPPER);
        console.log('✅ Hash successful');
        console.log('   Passport:', result.passport.substring(0, 40) + '...');

        // Verify
        console.log('\nVerifying password via API...');
        const verification = await inslash.verify(password, result.passport, process.env.HASH_PEPPER);
        console.log('✅ Verification:', verification.valid ? 'VALID' : 'INVALID');

    } catch (error) {
        console.error('❌ Error:', error.message);
        console.log('   (This is expected if API server is not running or API key is invalid)');
        console.log('   Inslash will automatically fall back to local mode');
    }
}

async function runTests() {
    await testWithoutAPI();
    await testWithAPI();

    console.log('\n' + '='.repeat(50));
    console.log('✅ Tests complete!\n');
}

runTests();
