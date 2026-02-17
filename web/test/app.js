const { hash, verify } = require('inslash');
require('dotenv').config();

async function test() {
  const password = 'test-password-123';
  
  // Hash
  const result = await hash(password, process.env.HASH_PEPPER);
  console.log('Passport:', result.passport);
  
  // Verify
  const verification = await verify(password, result.passport, process.env.HASH_PEPPER);
  console.log('Valid:', verification.valid);
  console.log('Needs Upgrade:', verification.needsUpgrade);
}

test();