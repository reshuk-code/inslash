const inslash = require('inslash');
require('dotenv').config();

console.log('\n🔐 Testing API Key Validation Messages\n');
console.log('='.repeat(60));

async function testNoAPIKey() {
    console.log('\n📍 TEST 1: No API Key');
    console.log('-'.repeat(60));

    inslash.configure({
        apiKey: null,
        apiUrl: 'http://localhost:3000',
        strictMode: true
    });

    try {
        await inslash.hash('test', process.env.HASH_PEPPER);
        console.log('❌ Should have failed');
    } catch (error) {
        console.log('✅ Correctly rejected');
        console.log('   Error:', error.message);
    }
}

async function testInvalidFormat() {
    console.log('\n📍 TEST 2: Invalid API Key Format');
    console.log('-'.repeat(60));

    inslash.configure({
        apiKey: 'wrong_format_key',
        apiUrl: 'http://localhost:3000',
        strictMode: true
    });

    console.log('Using key: wrong_format_key');

    try {
        await inslash.hash('test', process.env.HASH_PEPPER);
        console.log('❌ Should have failed');
    } catch (error) {
        console.log('✅ Correctly rejected');
        console.log('   Error:', error.message);
        if (error.message.includes('Invalid API key')) {
            console.log('   ✓ Clear error message provided');
        }
    }
}

async function testValidFormat() {
    console.log('\n📍 TEST 3: Valid API Key Format');
    console.log('-'.repeat(60));

    inslash.configure({
        apiKey: 'inslash_valid_key_12345',
        apiUrl: 'http://localhost:3000',
        strictMode: true
    });

    console.log('Using key: inslash_valid_key_12345');

    try {
        const result = await inslash.hash('test', process.env.HASH_PEPPER);
        console.log('✅ Hash succeeded');
        console.log('   Passport:', result.passport.substring(0, 30) + '...');
    } catch (error) {
        console.log('❌ Error:', error.message);
    }
}

async function runTests() {
    await testNoAPIKey();
    await testInvalidFormat();
    await testValidFormat();

    console.log('\n' + '='.repeat(60));
    console.log('✅ All validation tests complete!\n');
}

runTests();
