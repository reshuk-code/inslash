require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const { authenticateApiKey } = require('./middleware/auth');
const hashRoutes = require('./routes/hash');
const verifyRoutes = require('./routes/verify');
const keyRoutes = require('./routes/keys'); // Add this

const app = express();
const PORT = process.env.PORT || 3001;

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('✅ API: MongoDB connected'))
    .catch(err => console.error('❌ API: MongoDB error:', err));

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Public routes (no auth required)
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: 'inslash-api',
        version: '1.0.3',
        timestamp: new Date().toISOString()
    });
});

app.get('/', (req, res) => {
    res.json({
        name: 'Inslash API',
        version: '1.0.3',
        description: 'Secure password hashing API',
        documentation: {
            authentication: 'Use x-api-key header',
            endpoints: {
                'POST /api/hash': 'Hash a password',
                'POST /api/verify': 'Verify a password',
                'GET /api/keys': 'List your API keys',
                'POST /api/keys/create': 'Create a new API key',
                'POST /api/keys/:id/revoke': 'Revoke an API key'
            }
        }
    });
});

// Protected routes (require API key)
app.use('/api', authenticateApiKey);

// Rate limiting per API key
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: (req) => req.apiKey?.settings?.rateLimit?.requests || 100,
    keyGenerator: (req) => req.apiKey._id.toString(),
    handler: (req, res) => {
        res.status(429).json({
            error: 'RATE_LIMIT_EXCEEDED',
            message: 'Too many requests. Please try again later.'
        });
    }
});

app.use('/api', apiLimiter);

// Routes
app.use('/api/hash', hashRoutes);
app.use('/api/verify', verifyRoutes);
app.use('/api/keys', keyRoutes); // Add key management routes

// Error handler
app.use((err, req, res, next) => {
    console.error('API Error:', err);
    res.status(err.status || 500).json({
        error: err.code || 'INTERNAL_ERROR',
        message: err.message || 'An unexpected error occurred'
    });
});

app.listen(PORT, () => {
    console.log(`🚀 API running on http://localhost:${PORT}`);
    console.log(`📚 API Docs: http://localhost:${PORT}`);
});