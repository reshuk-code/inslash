const axios = require('axios');
const querystring = require('querystring');

async function run() {
    try {
        console.log('Testing Signup on Test App...');
        const response = await axios.post('http://localhost:3002/signup', querystring.stringify({
            username: 'test_script_user_' + Date.now(),
            password: 'password123'
        }), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            maxRedirects: 0,
            validateStatus: status => status >= 200 && status < 400
        });

        console.log('Signup Response Status:', response.status);
        if (response.status === 302) {
            console.log('PASS: Signup redirected to login (Success)');
        } else {
            console.log('Unexpected status:', response.status);
        }

    } catch (err) {
        if (err.response && err.response.status === 302) {
            console.log('PASS: Signup redirected to login (Success)');
        } else {
            console.error('FAIL: Signup failed:', err.message);
            if (err.response) {
                console.error('Data:', err.response.data);
            }
        }
    }
}

run();
