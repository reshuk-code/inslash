const mongoose = require('mongoose');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        minlength: 3
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    passport: {
        type: String,
        required: true
    },
    passportMetadata: {
        algorithm: String,
        iterations: Number,
        saltLength: Number,
        hashLength: Number,
        salt: String,
        hash: String,
        history: [{
            date: Date,
            algorithm: String,
            iterations: Number
        }]
    },
    // For "Remember Me" functionality
    rememberTokens: [{
        token: String,
        expires: Date
    }],
    // For password reset
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    // Email verification
    emailVerified: {
        type: Boolean,
        default: false
    },
    emailVerificationToken: String,
    emailVerificationExpires: Date,
    pendingEmail: {
        type: String,
        lowercase: true,
        trim: true
    },
    // Account status
    active: {
        type: Boolean,
        default: true
    },
    lastLogin: Date,
    loginHistory: [{
        date: {
            type: Date,
            default: Date.now
        },
        ip: String,
        userAgent: String,
        device: String, // Parsed from userAgent
        location: String // Placeholder for IP geolocation
    }],
    // Device Verification
    knownDevices: [{
        deviceId: String,
        ip: String,
        userAgent: String,
        lastLogin: Date
    }],
    deviceVerificationToken: String,
    deviceVerificationExpires: Date,
    pendingDeviceId: String,
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: Date,
    // Emoji avatar
    emoji: {
        type: String,
        default: '😊'
    },
    // Generated SVG Avatar
    avatarSvg: {
        type: String
    }
});

// Update timestamp on save
userSchema.pre('save', function (next) {
    this.updatedAt = new Date();
    next();
});

// Method to add login history
userSchema.methods.addLoginHistory = function (ip, userAgent) {
    let device = 'Unknown Device';

    if (userAgent) {
        // Simple parsing logic
        const ua = userAgent.toLowerCase();
        let os = 'Unknown OS';
        let browser = 'Unknown Browser';

        // OS Detection
        if (ua.includes('win')) os = 'Windows';
        else if (ua.includes('mac')) os = 'macOS';
        else if (ua.includes('linux')) os = 'Linux';
        else if (ua.includes('android')) os = 'Android';
        else if (ua.includes('ios') || ua.includes('iphone') || ua.includes('ipad')) os = 'iOS';

        // Browser Detection
        if (ua.includes('firefox')) browser = 'Firefox';
        else if (ua.includes('chrome') && !ua.includes('edg')) browser = 'Chrome';
        else if (ua.includes('safari') && !ua.includes('chrome')) browser = 'Safari';
        else if (ua.includes('edg')) browser = 'Edge';
        else if (ua.includes('opera') || ua.includes('opr')) browser = 'Opera';

        device = `${os} • ${browser}`;
    }

    this.loginHistory.push({
        date: new Date(),
        ip: ip,
        userAgent: userAgent,
        device: device
    });

    // Keep only last 10 logins
    if (this.loginHistory.length > 10) {
        this.loginHistory = this.loginHistory.slice(-10);
    }
};

// Method to generate remember me token
userSchema.methods.generateRememberToken = function () {
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date();
    expires.setDate(expires.getDate() + 30); // 30 days

    this.rememberTokens.push({ token, expires });

    // Keep only last 5 tokens
    if (this.rememberTokens.length > 5) {
        this.rememberTokens = this.rememberTokens.slice(-5);
    }

    return token;
};

// Method to validate remember token
// Method to validate remember token
userSchema.methods.validateRememberToken = function (token) {
    if (!this.rememberTokens || !Array.isArray(this.rememberTokens)) {
        return false;
    }

    const found = this.rememberTokens.find(t =>
        t.token === token && new Date(t.expires) > new Date()
    );
    return !!found;
};

// Method to cleanup expired tokens
userSchema.methods.cleanupTokens = function () {
    if (!this.rememberTokens) return;

    this.rememberTokens = this.rememberTokens.filter(t =>
        t.expires && new Date(t.expires) > new Date()
    );
};



module.exports = mongoose.model('User', userSchema);