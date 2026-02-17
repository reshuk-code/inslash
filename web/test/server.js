const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const inslash = require('inslash');
require('dotenv').config();

const app = express();
const PORT = 3002;

// Configure Inslash to use API mode
inslash.configure({
    apiKey: process.env.INSLASH_API_KEY,
    apiUrl: process.env.INSLASH_API_URL || 'http://localhost:3000'
});

console.log('✅ Inslash configured in API mode');
console.log('   API URL:', process.env.INSLASH_API_URL || 'http://localhost:3000');
console.log('   API Key:', process.env.INSLASH_API_KEY ? '***' + process.env.INSLASH_API_KEY.slice(-8) : 'NOT SET');

// Mock Database (In-Memory)
const users = [];

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// Routes
app.get('/', (req, res) => {
    if (req.query.user) {
        return res.render('home', { username: req.query.user });
    }
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);

    if (!user) {
        return res.render('login', { error: 'User not found' });
    }

    // VERIFY using Inslash API
    console.log(`Verifying user ${username} via API...`);
    try {
        const result = await inslash.verify(password, user.passport, process.env.HASH_PEPPER);

        if (result.valid) {
            // Check for upgrade
            if (result.needsUpgrade) {
                console.log(`Upgrading passport for ${username}...`);
                user.passport = result.upgradedPassport;
            }
            res.redirect(`/?user=${username}`);
        } else {
            res.render('login', { error: 'Invalid password' });
        }
    } catch (error) {
        console.error('Verify error:', error);
        res.render('login', { error: 'Verification failed' });
    }
});

app.get('/signup', (req, res) => {
    res.render('signup', { error: null });
});

app.post('/signup', async (req, res) => {
    const { username, password } = req.body;

    if (users.find(u => u.username === username)) {
        return res.render('signup', { error: 'Username already taken' });
    }

    // HASH using Inslash API
    console.log(`Hashing password for ${username} via API...`);
    try {
        const result = await inslash.hash(password, process.env.HASH_PEPPER);

        users.push({ username, passport: result.passport });
        console.log(`User ${username} created with passport: ${result.passport.substring(0, 20)}...`);
        res.redirect('/login');
    } catch (error) {
        console.error('Signup failed:', error);
        res.render('signup', { error: 'Hashing failed: ' + error.message });
    }
});

// Start
app.listen(PORT, () => {
    console.log(`🧪 Test App running on http://localhost:${PORT}`);
    console.log(`� Using Inslash with pepper from .env`);
});
