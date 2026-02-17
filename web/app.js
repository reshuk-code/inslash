require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const flash = require('connect-flash');
const mongoose = require('mongoose');
const crypto = require('crypto');
const inslash = require('../index.js'); // Import local inslash library
const nodemailer = require('nodemailer');
const { hashWithFallback: hash, verifyWithFallback: verify } = require('./utils/apiClient');
const { generateAvatarSvg } = require('./utils/avatarGenerator');
const User = require('./models/User');
const Project = require('./models/Project');
const path = require('path');
const expressLayouts = require('express-ejs-layouts');
const app = express();

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('✅ MongoDB connected'))
    .catch(err => console.error('❌ MongoDB connection error:', err));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser(process.env.COOKIE_SECRET));

let MongoStore;

// Try to use MongoDB store, fallback to memory store if it fails
try {
    MongoStore = require('connect-mongo')(session);
    console.log('✅ Using MongoDB session store');
} catch (error) {
    console.log('⚠️ MongoDB session store not available, using memory store');
    MongoStore = null;
}

// Session configuration
const sessionConfig = {
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        sameSite: 'lax'
    }
};

// Add MongoDB store if available
if (MongoStore) {
    try {
        sessionConfig.store = new MongoStore({
            url: process.env.MONGODB_URI,
            touchAfter: 24 * 3600,
            autoRemove: 'native'
        });
        console.log('✅ MongoDB session store connected');
    } catch (err) {
        console.log('⚠️ Failed to connect MongoDB store, using memory store:', err.message);
    }
}

app.use(session(sessionConfig));

app.use(flash());

// Set up EJS with layouts
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');

// ============= EMAIL CONFIGURATION =============
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// ============= MIDDLEWARE =============

// Make user available to all templates - FIXED VERSION
app.use(async (req, res, next) => {
    res.locals.currentUser = null;
    res.locals.error = req.flash('error');
    res.locals.success = req.flash('success');
    res.locals.info = req.flash('info');

    try {
        // Check session first
        if (req.session && req.session.userId) {
            const user = await User.findById(req.session.userId).lean();
            if (user) {
                res.locals.currentUser = {
                    id: user._id,
                    username: user.username,
                    username: user.username,
                    email: user.email,
                    emoji: user.emoji,
                    avatarSvg: user.avatarSvg,
                    createdAt: user.createdAt
                };
                return next();
            }
        }

        // Check remember me cookie
        if (req.cookies && req.cookies.remember) {
            try {
                const { userId, token } = JSON.parse(req.cookies.remember);

                // Validate token exists
                if (!userId || !token) {
                    res.clearCookie('remember');
                    return next();
                }

                const user = await User.findById(userId);

                if (user && user.validateRememberToken && user.validateRememberToken(token)) {
                    // Set session
                    req.session.userId = user._id;
                    req.session.username = user.username;

                    res.locals.currentUser = {
                        id: user._id,
                        username: user.username,
                        username: user.username,
                        email: user.email,
                        emoji: user.emoji,
                        avatarSvg: user.avatarSvg,
                        createdAt: user.createdAt
                    };

                    // Clean up old tokens
                    user.cleanupTokens();
                    await user.save();
                } else {
                    // Invalid token, clear cookie
                    res.clearCookie('remember');
                }
            } catch (cookieError) {
                console.error('Remember cookie error:', cookieError);
                res.clearCookie('remember');
            }
        }
    } catch (error) {
        console.error('Middleware error:', error);
    }

    next();
});

// Auth middleware for protected routes
const requireAuth = (req, res, next) => {
    if (!res.locals.currentUser) {
        req.flash('error', 'Please log in to access this page');
        return res.redirect('/login');
    }
    next();
};

// ============= ROUTES =============

// Home page
app.get('/', (req, res) => {
    // If user is logged in, redirect to dashboard
    if (res.locals.currentUser) {
        return res.redirect('/dashboard');
    }

    res.render('index', {
        title: 'Inslash - Secure Password Hashing',
        layout: false // Disable layout wrapper for landing page
    });
});

// ============= LEGAL PAGES =============
app.get('/terms', (req, res) => {
    res.render('terms', {
        title: 'Terms of Service - Inslash',
        layout: false
    });
});

app.get('/privacy', (req, res) => {
    res.render('privacy', {
        title: 'Privacy Policy - Inslash',
        layout: false
    });
});

// ============= SIGNUP =============
app.get('/signup', (req, res) => {
    if (res.locals.currentUser) {
        return res.redirect('/dashboard');
    }
    res.render('signup', {
        title: 'Create Account - Inslash',
        layout: false
    });
});

app.post('/signup', async (req, res) => {
    try {
        const { username, email, password, confirmPassword, acceptTerms } = req.body;

        // Validation
        if (!username || !email || !password) {
            req.flash('error', 'All fields are required');
            return res.redirect('/signup');
        }

        if (password !== confirmPassword) {
            req.flash('error', 'Passwords do not match');
            return res.redirect('/signup');
        }

        if (password.length < 8) {
            req.flash('error', 'Password must be at least 8 characters');
            return res.redirect('/signup');
        }

        if (!acceptTerms) {
            req.flash('error', 'You must accept the terms and conditions');
            return res.redirect('/signup');
        }

        // Check if user exists
        const existingUser = await User.findOne({
            $or: [{ username }, { email }]
        });

        if (existingUser) {
            req.flash('error', 'Username or email already exists');
            return res.redirect('/signup');
        }

        // Hash password using inslash
        const hashResult = await hash(password, process.env.HASH_PEPPER, {
            iterations: 150000,
            algorithm: 'sha256'
        });

        // Create email verification token
        const emailVerificationToken = crypto.randomBytes(32).toString('hex');

        // Create user
        const user = new User({
            username,
            email,
            passport: hashResult.passport,
            passportMetadata: {
                algorithm: hashResult.algorithm,
                iterations: hashResult.iterations,
                saltLength: hashResult.saltLength,
                hashLength: hashResult.hashLength,
                salt: hashResult.salt,
                hash: hashResult.hash,
                history: hashResult.history
            },
            emailVerificationToken,
            loginHistory: [{
                date: new Date(),
                ip: req.ip,
                userAgent: req.get('user-agent')
            }]
        });

        await user.save();

        // Send verification email (optional - you can enable this later)
        if (process.env.EMAIL_USER) {
            const verificationUrl = `${req.protocol}://${req.get('host')}/verify-email/${emailVerificationToken}`;

            try {
                await transporter.sendMail({
                    from: '"Inslash" <noreply@inslash.com>',
                    to: email,
                    subject: 'Verify Your Email Address',
                    html: `
                        <h1>Welcome to Inslash!</h1>
                        <p>Please click the link below to verify your email address:</p>
                        <a href="${verificationUrl}">${verificationUrl}</a>
                        <p>This link will expire in 24 hours.</p>
                    `
                });
            } catch (emailError) {
                console.error('Email send error:', emailError);
            }
        }

        // Log the user in
        req.session.userId = user._id;
        req.session.username = user.username;

        req.flash('success', 'Account created successfully!');
        res.redirect('/dashboard');

    } catch (error) {
        console.error('Signup error:', error);
        req.flash('error', 'An error occurred during signup');
        res.redirect('/signup');
    }
});

// ============= EMAIL VERIFICATION =============
app.get('/verify-email/:token', async (req, res) => {
    try {
        const user = await User.findOne({
            emailVerificationToken: req.params.token
        });

        if (!user) {
            req.flash('error', 'Invalid or expired verification link');
            return res.redirect('/');
        }

        user.emailVerified = true;
        user.emailVerificationToken = undefined;
        await user.save();

        req.flash('success', 'Email verified successfully!');
        res.redirect('/dashboard');

    } catch (error) {
        console.error('Email verification error:', error);
        req.flash('error', 'An error occurred');
        res.redirect('/');
    }
});

// ============= LOGIN WITH FORGOT PASSWORD OPTION =============
app.get('/login', (req, res) => {
    if (res.locals.currentUser) {
        return res.redirect('/dashboard');
    }
    res.render('login', {
        title: 'Sign In - Inslash',
        layout: false
    });
});

app.post('/login', async (req, res) => {
    try {
        const { username, password, rememberMe } = req.body;

        if (!username || !password) {
            req.flash('error', 'Username and password are required');
            return res.redirect('/login');
        }

        // Find user
        const user = await User.findOne({
            $or: [{ username }, { email: username }]
        });

        if (!user) {
            req.flash('error', 'Invalid credentials');
            return res.redirect('/login');
        }

        if (user.active === false) {
            req.flash('error', 'This account has been deactivated');
            return res.redirect('/login');
        }

        // Check if passport exists
        if (!user.passport) {
            console.error('User passport is undefined for user:', user.username);
            req.flash('error', 'Account data is corrupted. Please contact support.');
            return res.redirect('/login');
        }

        // Verify password using inslash
        let verification;
        try {
            console.log('Attempting verification for user:', user.username);
            console.log('Passport exists:', !!user.passport);
            console.log('Passport length:', user.passport ? user.passport.length : 'N/A');
            console.log('Password provided:', !!password);
            console.log('Pepper exists:', !!process.env.HASH_PEPPER);

            verification = await verify(password, user.passport, process.env.HASH_PEPPER);
        } catch (verifyError) {
            console.error('Verification error details:', {
                message: verifyError.message,
                stack: verifyError.stack,
                userPassport: user.passport ? user.passport.substring(0, 100) : 'undefined'
            });
            req.flash('error', 'Login verification failed. Please try again.');
            return res.redirect('/login');
        }

        if (!verification.valid) {
            req.flash('error', 'Invalid credentials');
            return res.redirect('/login');
        }

        // Check if device is known
        const deviceId = req.cookies.device_id;
        let isKnownDevice = false;

        if (deviceId && user.knownDevices) {
            isKnownDevice = user.knownDevices.some(d => d.deviceId === deviceId);
        }

        // If new device or no cookie, trigger verification
        if (!isKnownDevice) {
            console.log(`New device detected for user: ${user.username}`);

            // Generate OTP
            const otp = Math.floor(100000 + Math.random() * 900000).toString();
            const pendingDeviceId = crypto.randomBytes(16).toString('hex');

            user.deviceVerificationToken = otp;
            user.deviceVerificationExpires = Date.now() + 600000; // 10 minutes
            user.pendingDeviceId = pendingDeviceId;
            await user.save();

            // Send Email
            if (process.env.EMAIL_USER) {
                try {
                    await transporter.sendMail({
                        from: '"Inslash Security" <noreply@inslash.com>',
                        to: user.email,
                        subject: 'New Device Verification Code',
                        html: `
                            <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
                                <h1>New Device Login Attempt</h1>
                                <p>We detected a login attempt from a new device.</p>
                                <p>Please use the following code to verify your identity:</p>
                                <h2 style="font-size: 32px; letter-spacing: 5px; background: #f3f4f6; padding: 20px; text-align: center; border-radius: 8px;">${otp}</h2>
                                <p>This code expires in 10 minutes.</p>
                                <p>If this wasn't you, please reset your password immediately.</p>
                            </div>
                        `
                    });
                } catch (emailError) {
                    console.error('Email send error:', emailError);
                }
            } else {
                // Development mode log
                console.log('\n=================================');
                console.log(`DEVICE VERIFICATION CODE: ${otp}`);
                console.log('=================================\n');
            }

            // Temporarily store userId in session for verification workflow (cleared on success)
            req.session.pendingUserId = user._id;

            return res.render('verify-device', {
                title: 'Verify Device - Inslash',
                userId: user._id
            });
        }

        // If known device, proceed with login
        user.lastLogin = new Date();
        user.lastLoginIP = req.ip;

        // Update device last seen
        if (deviceId && user.knownDevices) {
            const deviceIndex = user.knownDevices.findIndex(d => d.deviceId === deviceId);
            if (deviceIndex > -1) {
                user.knownDevices[deviceIndex].lastLogin = new Date();
                user.knownDevices[deviceIndex].ip = req.ip;
            }
        }

        user.addLoginHistory(req.ip, req.get('user-agent'));

        // Check if password needs upgrade
        if (verification.needsUpgrade && verification.upgradedPassport) {
            user.passport = verification.upgradedPassport;
            const upgradedMeta = verification.upgradedMetadata || {};
            user.passportMetadata = {
                ...user.passportMetadata,
                ...upgradedMeta
            };
        }

        await user.save();

        // Set session
        req.session.userId = user._id;
        req.session.username = user.username;

        // Set remember me cookie
        if (rememberMe) {
            const token = user.generateRememberToken();
            await user.save();

            res.cookie('remember', JSON.stringify({
                userId: user._id,
                token: token
            }), {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
                sameSite: 'lax'
            });
        }

        req.flash('success', `Welcome back, ${user.username}!`);
        res.redirect('/dashboard');

    } catch (error) {
        console.error('Login error:', error);
        req.flash('error', 'An error occurred during login');
        res.redirect('/login');
    }
});

// ============= DEVICE VERIFICATION ROUTES =============
app.get('/verify-device', (req, res) => {
    // Should verify session pendingUserId exists, else redirect to login
    if (!req.session.pendingUserId) {
        return res.redirect('/login');
    }
    res.render('verify-device', {
        title: 'Verify Device - Inslash',
        userId: req.session.pendingUserId
    });
});

app.post('/verify-device', async (req, res) => {
    try {
        const { userId, otp1, otp2, otp3, otp4, otp5, otp6 } = req.body;
        const inputOtp = `${otp1}${otp2}${otp3}${otp4}${otp5}${otp6}`;

        if (!userId || !inputOtp || inputOtp.length !== 6) {
            req.flash('error', 'Invalid code format');
            return res.render('verify-device', { title: 'Verify Device - Inslash', userId });
        }

        const user = await User.findById(userId);

        if (!user ||
            user.deviceVerificationToken !== inputOtp ||
            user.deviceVerificationExpires < Date.now()) {

            req.flash('error', 'Invalid or expired code. Please try logging in again.');
            return res.redirect('/login');
        }

        // Verification Successful
        // 1. Set Device Cookie
        const newDeviceId = user.pendingDeviceId || crypto.randomBytes(16).toString('hex');

        res.cookie('device_id', newDeviceId, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 365 * 24 * 60 * 60 * 1000, // 1 year (long-lived)
            sameSite: 'lax'
        });

        // 2. Add to Known Devices
        if (!user.knownDevices) user.knownDevices = [];

        user.knownDevices.push({
            deviceId: newDeviceId,
            ip: req.ip,
            userAgent: req.get('user-agent'),
            lastLogin: new Date()
        });

        // 3. Clear verification fields
        user.deviceVerificationToken = undefined;
        user.deviceVerificationExpires = undefined;
        user.pendingDeviceId = undefined;

        // 4. Update login stats
        user.lastLogin = new Date();
        user.lastLoginIP = req.ip;
        user.addLoginHistory(req.ip, req.get('user-agent'));

        await user.save();

        // 5. Complete Login (Set Session)
        req.session.userId = user._id;
        req.session.username = user.username;
        delete req.session.pendingUserId;

        req.flash('success', 'Device verified successfully!');
        res.redirect('/dashboard');

    } catch (error) {
        console.error('Device verification error:', error);
        req.flash('error', 'An error occurred');
        res.redirect('/login');
    }
});

// ============= FORGOT PASSWORD =============
app.get('/forgot-password', (req, res) => {
    res.render('forgot-password', {
        title: 'Forgot Password - Inslash',
        layout: false
    });
});

app.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            req.flash('error', 'Email is required');
            return res.redirect('/forgot-password');
        }

        const user = await User.findOne({ email });

        // Always return success even if user doesn't exist (security)
        if (!user) {
            req.flash('success', 'If an account exists with this email, you will receive reset instructions.');
            return res.redirect('/login');
        }

        // Generate reset token
        const resetToken = crypto.randomBytes(32).toString('hex');
        user.resetPasswordToken = resetToken;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        await user.save();

        // Send reset email
        const resetUrl = `${req.protocol}://${req.get('host')}/reset-password/${resetToken}`;

        // Check if email is configured
        if (!process.env.EMAIL_USER) {
            // Development mode - show token in console
            console.log('\n=================================');
            console.log('FORGOT PASSWORD - DEVELOPMENT MODE');
            console.log('Reset URL:', resetUrl);
            console.log('=================================\n');

            req.flash('info', 'Development mode: Check console for reset link');
            return res.redirect('/login');
        }

        try {
            await transporter.sendMail({
                from: '"Inslash" <noreply@inslash.com>',
                to: email,
                subject: 'Password Reset Request',
                html: `
                    <h1>Password Reset</h1>
                    <p>You requested a password reset. Click the link below to reset your password:</p>
                    <a href="${resetUrl}">${resetUrl}</a>
                    <p>This link will expire in 1 hour.</p>
                    <p>If you didn't request this, please ignore this email.</p>
                `
            });
        } catch (emailError) {
            console.error('Email send error:', emailError);
            // Still show success for security
        }

        req.flash('success', 'Password reset instructions sent to your email');
        res.redirect('/login');

    } catch (error) {
        console.error('Forgot password error:', error);
        req.flash('error', 'An error occurred');
        res.redirect('/forgot-password');
    }
});

// ============= RESET PASSWORD =============
app.get('/reset-password/:token', async (req, res) => {
    try {
        const user = await User.findOne({
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            req.flash('error', 'Password reset token is invalid or has expired');
            return res.redirect('/forgot-password');
        }

        res.render('reset-password', {
            title: 'Reset Password - Inslash',
            token: req.params.token,
            layout: false
        });

    } catch (error) {
        console.error('Reset password page error:', error);
        req.flash('error', 'An error occurred');
        res.redirect('/forgot-password');
    }
});

app.post('/reset-password/:token', async (req, res) => {
    try {
        const { password, confirmPassword } = req.body;

        if (password !== confirmPassword) {
            req.flash('error', 'Passwords do not match');
            return res.redirect(`/reset-password/${req.params.token}`);
        }

        if (password.length < 8) {
            req.flash('error', 'Password must be at least 8 characters');
            return res.redirect(`/reset-password/${req.params.token}`);
        }

        const user = await User.findOne({
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            req.flash('error', 'Password reset token is invalid or has expired');
            return res.redirect('/forgot-password');
        }

        // Hash new password using inslash
        const hashResult = await hash(password, process.env.HASH_PEPPER, {
            iterations: 150000,
            algorithm: 'sha256'
        });

        // Update user
        user.passport = hashResult.passport;
        user.passportMetadata = {
            algorithm: hashResult.algorithm,
            iterations: hashResult.iterations,
            saltLength: hashResult.saltLength,
            hashLength: hashResult.hashLength,
            salt: hashResult.salt,
            hash: hashResult.hash,
            history: hashResult.history
        };
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        await user.save();

        req.flash('success', 'Password reset successfully! Please log in with your new password.');
        res.redirect('/login');

    } catch (error) {
        console.error('Reset password error:', error);
        req.flash('error', 'An error occurred');
        res.redirect('/forgot-password');
    }
});

// ============= DASHBOARD (Protected) =============
app.get('/dashboard', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(res.locals.currentUser.id);
        const Project = require('./models/Project');
        // Fetch all projects for stats
        const allProjects = await Project.find({ userId: user._id }).sort({ createdAt: -1 });

        // Calculate stats
        let totalRequests = 0;
        let totalValidations = 0;

        allProjects.forEach(p => {
            if (p.apiKeys) {
                p.apiKeys.forEach(k => {
                    if (k.usage) {
                        totalRequests += (k.usage.count || 0);
                        totalValidations += (k.usage.verifications || 0);
                    }
                });
            }
        });

        res.render('dashboard', {
            title: 'Dashboard - Inslash',
            user,
            projects: allProjects, // Pass all projects, let view slice for "Recent"
            stats: {
                totalRequests,
                totalValidations
            },
            passportMetadata: user.passportMetadata
        });
    } catch (error) {
        console.error('Dashboard error:', error);
        req.flash('error', 'An error occurred');
        res.redirect('/');
    }
});

// ============= SANDBOX CONSOLE =============
app.get('/console', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(res.locals.currentUser.id);
        const Project = require('./models/Project');

        // Find a project with API keys to pre-fill
        const project = await Project.findOne({
            userId: user._id,
            'apiKeys.0': { $exists: true }
        });

        let defaultKey = '';
        if (project && project.apiKeys.length > 0) {
            defaultKey = project.apiKeys[0].key;
        }

        res.render('console', {
            title: 'Sandbox Console - Inslash',
            user,
            defaultKey
        });
    } catch (error) {
        console.error('Console error:', error);
        res.status(500).send('Server Error');
    }
});

// ============= CHANGE PASSWORD =============
// ============= API KEYS CONSOLE =============
// (Moved to correct location)

// ============= CHANGE PASSWORD =============
app.post('/profile/change-password', requireAuth, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const user = await User.findById(res.locals.currentUser.id);

        // Verify current password
        const verification = await verify(currentPassword, user.passport, process.env.HASH_PEPPER);

        if (!verification.valid) {
            return res.status(400).json({ error: 'Current password is incorrect' });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({ error: 'New password must be at least 8 characters' });
        }

        // Hash new password
        const hashResult = await hash(newPassword, process.env.HASH_PEPPER, {
            iterations: 200000, // Upgrade to stronger iterations
            algorithm: 'sha256'
        });

        // Update user
        user.passport = hashResult.passport;
        user.passportMetadata = {
            algorithm: hashResult.algorithm,
            iterations: hashResult.iterations,
            saltLength: hashResult.saltLength,
            hashLength: hashResult.hashLength,
            salt: hashResult.salt,
            hash: hashResult.hash,
            history: hashResult.history
        };

        await user.save();

        res.json({ success: true });

    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ error: 'An error occurred' });
    }
});
// ============= PROJECTS =============
app.get('/projects', requireAuth, async (req, res) => {
    try {
        const Project = require('./models/Project');
        const projects = await Project.find({ userId: res.locals.currentUser.id })
            .sort({ createdAt: -1 });

        res.render('projects', {
            title: 'My Projects - Inslash',
            projects
        });
    } catch (error) {
        console.error('Projects error:', error);
        req.flash('error', 'Failed to load projects');
        res.redirect('/dashboard');
    }
});

// Create Project Page
app.get('/projects/new', requireAuth, (req, res) => {
    res.render('new-project', {
        title: 'Create New Project - Inslash'
    });
});

// Create Project
app.post('/projects/create', requireAuth, async (req, res) => {
    try {
        const { name, description, defaultIterations } = req.body;

        if (!name) {
            req.flash('error', 'Project name is required');
            return res.redirect('/projects/new');
        }

        const Project = require('./models/Project');

        // Generate initial API key
        const apiKey = 'inslash_' + crypto.randomBytes(24).toString('hex');

        const project = new Project({
            name,
            description,
            userId: res.locals.currentUser.id,
            settings: {
                defaultIterations: defaultIterations || 150000
            },
            apiKeys: [{
                key: apiKey,
                name: 'Default Key',
                createdAt: new Date()
            }]
        });

        await project.save();

        // Store the key in flash message to show once
        req.flash('success', 'Project created successfully!');
        req.flash('new_api_key', JSON.stringify({
            key: apiKey,
            name: 'Default Key',
            projectId: project._id,
            projectName: name
        }));

        res.redirect('/projects');

    } catch (error) {
        console.error('Create project error:', error);
        req.flash('error', 'Failed to create project');
        res.redirect('/projects/new');
    }
});
// View Single Project
app.get('/projects/:id', requireAuth, async (req, res) => {
    try {
        const Project = require('./models/Project');
        const project = await Project.findOne({
            _id: req.params.id,
            userId: res.locals.currentUser.id
        });

        if (!project) {
            req.flash('error', 'Project not found');
            return res.redirect('/projects');
        }

        res.render('project-detail', {
            title: `${project.name} - Inslash`,
            project
        });

    } catch (error) {
        console.error('Project detail error:', error);
        req.flash('error', 'Failed to load project');
        res.redirect('/projects');
    }
});

// Generate New API Key for Project
app.post('/projects/:id/generate-key', requireAuth, async (req, res) => {
    try {
        const Project = require('./models/Project');
        const project = await Project.findOne({
            _id: req.params.id,
            userId: res.locals.currentUser.id
        });

        if (!project) {
            return res.status(404).json({ error: 'Project not found' });
        }

        const keyName = req.body.name || `Key ${project.apiKeys.length + 1}`;
        const newKey = 'inslash_' + crypto.randomBytes(24).toString('hex');

        project.apiKeys.push({
            key: newKey,
            name: keyName
        });

        await project.save();

        res.json({
            success: true,
            key: newKey,
            name: keyName
        });

    } catch (error) {
        console.error('Generate key error:', error);
        res.status(500).json({ error: 'Failed to generate key' });
    }
});

// Revoke API Key
app.post('/projects/:projectId/revoke-key/:keyId', requireAuth, async (req, res) => {
    try {
        const Project = require('./models/Project');
        const project = await Project.findOne({
            _id: req.params.projectId,
            userId: res.locals.currentUser.id
        });

        if (!project) {
            return res.status(404).json({ error: 'Project not found' });
        }

        // Use pull() instead of deprecated id().remove()
        project.apiKeys.pull({ _id: req.params.keyId });
        await project.save();

        res.json({ success: true });

    } catch (error) {
        console.error('Revoke key error:', error);
        res.status(500).json({ error: 'Failed to revoke key' });
    }
});

// Get Project Stats (filtered)
app.get('/projects/:id/stats', requireAuth, async (req, res) => {
    try {
        const Project = require('./models/Project');
        const UsageLog = require('./models/UsageLog');

        // Verify ownership
        const project = await Project.findOne({
            _id: req.params.id,
            userId: res.locals.currentUser.id
        });

        if (!project) {
            return res.status(404).json({ error: 'Project not found' });
        }

        const period = req.query.period || '24h';
        let startDate = new Date();

        // Calculate start date based on period
        switch (period) {
            case '24h':
                startDate.setHours(startDate.getHours() - 24);
                break;
            case '7d':
                startDate.setDate(startDate.getDate() - 7);
                break;
            case '30d':
                startDate.setDate(startDate.getDate() - 30);
                break;
            case 'all':
                startDate = new Date(0); // Beginning of time
                break;
            default:
                startDate.setHours(startDate.getHours() - 24);
        }

        // Aggregate logs
        const stats = await UsageLog.aggregate([
            {
                $match: {
                    projectId: project._id,
                    timestamp: { $gte: startDate }
                }
            },
            {
                $group: {
                    _id: null,
                    total: { $sum: 1 },
                    hashes: {
                        $sum: { $cond: [{ $eq: ["$type", "hash"] }, 1, 0] }
                    },
                    verifications: {
                        $sum: { $cond: [{ $eq: ["$type", "verify"] }, 1, 0] }
                    },
                    failed: {
                        $sum: { $cond: [{ $eq: ["$status", "failed"] }, 1, 0] }
                    }
                }
            }
        ]);

        // Get time-series data for chart
        // Check "Aggregate by hour" or "Aggregate by day" based on period
        let groupByFormat = "%Y-%m-%dT%H:00:00Z"; // Default by hour (UTC)
        if (period === '7d' || period === '30d' || period === 'all') {
            groupByFormat = "%Y-%m-%dT00:00:00Z"; // By day (UTC)
        }

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

        // Post-process to fill gaps with zeros
        const chartData = [];
        const now = new Date();
        let currentDate = new Date(startDate);

        // Map existing data for quick lookup
        const dataMap = new Map();
        rawChartData.forEach(item => dataMap.set(item._id, item.count));

        while (currentDate <= now) {
            let dateKey;

            if (groupByFormat.includes("%H")) {
                // Hour format: YYYY-MM-DDTHH:00:00 (UTC)
                const yyyy = currentDate.getUTCFullYear();
                const mm = String(currentDate.getUTCMonth() + 1).padStart(2, '0');
                const dd = String(currentDate.getUTCDate()).padStart(2, '0');
                const hh = String(currentDate.getUTCHours()).padStart(2, '0');
                dateKey = `${yyyy}-${mm}-${dd}T${hh}:00:00Z`;

                // Increment by 1 hour
                currentDate.setHours(currentDate.getHours() + 1);
            } else {
                // Day format: YYYY-MM-DDTHH:00:00 (UTC)
                const yyyy = currentDate.getUTCFullYear();
                const mm = String(currentDate.getUTCMonth() + 1).padStart(2, '0');
                const dd = String(currentDate.getUTCDate()).padStart(2, '0');
                dateKey = `${yyyy}-${mm}-${dd}T00:00:00Z`;

                // Increment by 1 day
                currentDate.setDate(currentDate.getDate() + 1);
            }

            chartData.push({
                _id: dateKey,
                count: dataMap.get(dateKey) || 0
            });
        }

        const result = stats[0] || { total: 0, hashes: 0, verifications: 0, failed: 0 };

        res.json({
            ...result,
            chartData
        });

    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});


// Get Project Usage Logs (Paginated)
app.get('/projects/:id/logs', requireAuth, async (req, res) => {
    try {
        const Project = require('./models/Project');
        const UsageLog = require('./models/UsageLog');

        // Verify ownership
        const project = await Project.findOne({
            _id: req.params.id,
            userId: res.locals.currentUser.id
        });

        if (!project) {
            return res.status(404).json({ error: 'Project not found' });
        }

        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 50;
        const skip = (page - 1) * limit;

        const logs = await UsageLog.find({ projectId: project._id })
            .sort({ timestamp: -1 })
            .skip(skip)
            .limit(limit)
            .lean();

        // Map keyId to key name for display
        // Create a map of keyId -> keyName
        const keyMap = {};
        if (project.apiKeys) {
            project.apiKeys.forEach(k => {
                keyMap[k._id.toString()] = k.name;
            });
        }

        const enrichedLogs = logs.map(log => ({
            ...log,
            keyName: keyMap[log.keyId.toString()] || 'Unknown Key',
            timestamp: log.timestamp // Send ISO date
        }));

        const total = await UsageLog.countDocuments({ projectId: project._id });

        res.json({
            logs: enrichedLogs,
            pagination: {
                current: page,
                pages: Math.ceil(total / limit),
                total
            }
        });

    } catch (error) {
        console.error('Fetch logs error:', error);
        res.status(500).json({ error: 'Failed to fetch logs' });
    }
});

// ============= API KEYS CONSOLE =============
app.get('/api-keys', requireAuth, async (req, res) => {
    try {
        const Project = require('./models/Project');
        // Fetch all projects for the user
        const projects = await Project.find({ userId: res.locals.currentUser.id }).sort({ createdAt: -1 });

        // Aggregate all keys
        let allKeys = [];
        projects.forEach(project => {
            if (project.apiKeys && project.apiKeys.length > 0) {
                project.apiKeys.forEach(key => {
                    allKeys.push({
                        name: key.name,
                        // Extract prefix from key (inslash_xxxx...)
                        prefix: key.key.substring(8, 16),
                        projectName: project.name,
                        projectId: project._id,
                        keyId: key._id, // Added for revocation
                        createdAt: key.createdAt,
                        lastUsed: key.lastUsed, // Assuming this field exists or is null
                        fullKey: key.key // Only if you want to show it, usually obscured
                    });
                });
            }
        });

        // Sort by creation date (newest first)
        allKeys.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

        res.render('api-keys', {
            title: 'API Keys - Inslash',
            keys: allKeys
        });

    } catch (error) {
        console.error('API Keys page error:', error);
        req.flash('error', 'Failed to load API keys');
        res.redirect('/dashboard');
    }
});
// ============= LOGOUT =============
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.clearCookie('remember');
    res.redirect('/');
});

// ============= PROFILE SETTINGS// Profile page
app.get('/profile', requireAuth, async (req, res) => {
    try {
        const Project = require('./models/Project');
        const projects = await Project.find({ userId: res.locals.currentUser.id });

        // Calculate total API keys
        const totalKeys = projects.reduce((sum, project) => sum + project.apiKeys.length, 0);

        // Fetch user details for the profile page
        const user = await User.findById(res.locals.currentUser.id);

        res.render('profile', {
            title: 'Profile Settings - Inslash',
            currentUser: user, // Use the fully fetched user object
            projects: projects,
            totalKeys: totalKeys
        });
    } catch (error) {
        console.error('Profile error:', error);
        req.flash('error', 'An error occurred');
        res.redirect('/dashboard');
    }
});

app.post('/profile/update-email', requireAuth, async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findById(res.locals.currentUser.id);

        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }

        // Check if email is already taken
        if (email !== user.email) {
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                return res.status(400).json({ error: 'Email already in use' });
            }
            user.email = email;
            user.emailVerified = false;
        }

        await user.save();

        res.json({ success: true });

    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ error: 'An error occurred' });
    }
});

app.post('/profile/regenerate-avatar', requireAuth, async (req, res) => {
    try {
        const svg = generateAvatarSvg();

        await User.findByIdAndUpdate(res.locals.currentUser.id, {
            avatarSvg: svg,
            // optional: clear emoji so frontend prefers svg, or keep it as backup
        });

        res.json({ success: true, avatarSvg: svg });
    } catch (error) {
        console.error('Avatar regeneration error:', error);
        res.status(500).json({ error: 'Failed to regenerate avatar' });
    }
});

app.post('/profile/delete', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(res.locals.currentUser.id);
        const Project = require('./models/Project');

        // Delete all user's projects
        await Project.deleteMany({ userId: user._id });

        // Delete user
        await User.findByIdAndDelete(user._id);

        // Clear session and cookies
        req.session.destroy();
        res.clearCookie('remember');

        res.json({ success: true });

    } catch (error) {
        console.error('Account deletion error:', error);
        res.status(500).json({ error: 'Failed to delete account' });
    }
});

// ============= API ENDPOINTS =============
// API Key Authentication Middleware
const authenticateAPIKey = async (req, res, next) => {
    const apiKey = req.headers['x-api-key'];

    if (!apiKey) {
        return res.status(401).json({
            error: 'UNAUTHORIZED',
            message: 'API key is required. Get your API key from the dashboard at /api-keys',
            hint: 'Add the x-api-key header to your request'
        });
    }

    try {
        // Simple first check: must start with 'inslash_'
        if (!apiKey.startsWith('inslash_')) {
            return res.status(401).json({
                error: 'INVALID_API_KEY',
                message: 'Invalid API key format. Please get a valid API key from your dashboard.',
                hint: 'API keys must start with "inslash_". Visit /api-keys to generate one.'
            });
        }

        // Database Validation: Find project containing this API key
        const Project = require('./models/Project');
        const project = await Project.findOne({ 'apiKeys.key': apiKey });

        if (!project) {
            return res.status(401).json({
                error: 'INVALID_API_KEY',
                message: 'API key not found, inactive, or revoked',
                hint: 'Check if your API key is active in the dashboard'
            });
        }

        // Get the specific key object
        const keyObj = project.apiKeys.find(k => k.key === apiKey);

        // Update usage stats (async, don't wait)
        // Increment general usage count and update lastUsed
        Project.updateOne(
            { _id: project._id, 'apiKeys.key': apiKey },
            {
                $set: { 'apiKeys.$.lastUsed': new Date() },
                $inc: { 'apiKeys.$.usage.count': 1 }
            }
        ).exec();

        req.apiKey = keyObj.key;
        req.project = project;
        req.keyId = keyObj._id; // Store keyId for logging
        req.user = project.userId;

        // --- USAGE LOGGING START ---
        // We log asynchronously to not slow down the request
        const UsageLog = require('./models/UsageLog');
        const startTime = Date.now();

        // Hook into response finish to log status and duration
        res.on('finish', () => {
            const duration = Date.now() - startTime;
            const status = res.statusCode >= 400 ? 'failed' : 'success';
            // Determine type based on URL (hash or verify)
            const type = req.url.includes('verify') ? 'verify' : 'hash';

            // Fire and forget log entry
            UsageLog.create({
                projectId: project._id,
                keyId: keyObj._id,
                type: type,
                status: status,
                responseTime: duration,
                ip: req.ip
            }).catch(err => console.error('Failed to log usage:', err));
        });
        // --- USAGE LOGGING END ---

        next();
    } catch (error) {
        console.error('API key validation error:', error);
        res.status(500).json({
            error: 'INTERNAL_ERROR',
            message: 'Failed to validate API key'
        });
    }
};

// POST /api/hash - Hash a password
app.post('/api/hash', authenticateAPIKey, async (req, res) => {
    try {
        const { value, secret, options } = req.body;

        if (!value) {
            return res.status(400).json({
                error: 'MISSING_VALUE',
                message: 'Value to hash is required'
            });
        }

        if (!secret) {
            return res.status(400).json({
                error: 'MISSING_SECRET',
                message: 'Secret key is required'
            });
        }

        // Use the inslash library to hash
        const result = await inslash.hash(value, secret, options || {});

        res.json(result);
    } catch (error) {
        console.error('API hash error:', error);
        res.status(500).json({
            error: 'HASH_FAILED',
            message: error.message
        });
    }
});

// POST /api/verify - Verify a password
app.post('/api/verify', authenticateAPIKey, async (req, res) => {
    try {
        const { value, passport, secret, options } = req.body;

        if (!value) {
            return res.status(400).json({
                error: 'MISSING_VALUE',
                message: 'Value to verify is required'
            });
        }

        if (!passport) {
            return res.status(400).json({
                error: 'MISSING_PASSPORT',
                message: 'Passport is required'
            });
        }

        if (!secret) {
            return res.status(400).json({
                error: 'MISSING_SECRET',
                message: 'Secret key is required'
            });
        }

        // Use the inslash library to verify
        const result = await inslash.verify(value, passport, secret, options || {});

        res.json(result);
    } catch (error) {
        console.error('API verify error:', error);
        res.status(500).json({
            error: 'VERIFY_FAILED',
            message: error.message
        });
    }
});

// ============= TEST ROUTE =============
app.get('/test', (req, res) => {
    res.send('Server is working! Views are being served correctly.');
});

// ============= DOCUMENTATION =============
app.get('/docs', (req, res) => {
    res.render('docs-wrapper', {
        title: 'Documentation',
        layout: false
    });
});
// ============= ERROR HANDLING =============
// 404 handler - keep this at the end
app.use((req, res) => {
    // Check if the route starts with /api
    if (req.path.startsWith('/api')) {
        return res.status(404).json({
            error: 'NOT_FOUND',
            message: 'API endpoint not found'
        });
    }

    // For web routes, render 404 page
    res.status(404).render('404', {
        title: 'Page Not Found - Inslash',
        layout: 'layout'
    });
});

// 500 error handler
app.use((err, req, res, next) => {
    console.error('Server error:', err);

    // Check if it's an API request
    if (req.path.startsWith('/api')) {
        return res.status(500).json({
            error: 'SERVER_ERROR',
            message: 'Internal server error'
        });
    }

    // For web routes, render 500 page
    res.status(500).render('500', {
        title: 'Server Error - Inslash',
        layout: 'layout',
        error: process.env.NODE_ENV === 'development' ? err.message : null
    });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🌐 Web app running on http://localhost:${PORT}`);
    console.log(`✅ MongoDB connected`);
    console.log(`🔧 Environment: ${process.env.NODE_ENV || 'development'}`);
});