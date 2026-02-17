const axios = require('axios');

const API_URL = process.env.API_URL || 'http://localhost:3001';

/**
 * API Client for Inslash API
 * Handles all password hashing and verification operations
 */
class InslashAPIClient {
    constructor(apiKey) {
        this.apiKey = apiKey;
        this.client = axios.create({
            baseURL: API_URL,
            headers: {
                'x-api-key': apiKey,
                'Content-Type': 'application/json'
            },
            timeout: 10000 // 10 second timeout
        });
    }

    /**
     * Hash a password using the API
     * @param {string} password - Plain text password to hash
     * @param {object} options - Hashing options (iterations, algorithm, etc.)
     * @returns {Promise<object>} Hash result with passport and metadata
     */
    async hashPassword(password, options = {}) {
        try {
            const response = await this.client.post('/api/hash', {
                value: password,  // API expects 'value', not 'password'
                secret: process.env.HASH_PEPPER,  // API expects 'secret'
                options
            });

            return {
                success: true,
                data: response.data
            };
        } catch (error) {
            console.error('Hash API error:', error.response?.data || error.message);
            return {
                success: false,
                error: this._formatError(error)
            };
        }
    }

    /**
     * Verify a password against a passport
     * @param {string} password - Plain text password to verify
     * @param {string} passport - Stored passport string
     * @param {object} options - Verification options
     * @returns {Promise<object>} Verification result
     */
    async verifyPassword(password, passport, options = {}) {
        try {
            const response = await this.client.post('/api/verify', {
                value: password,  // API expects 'value', not 'password'
                passport,
                secret: process.env.HASH_PEPPER,  // API expects 'secret'
                options
            });

            return {
                success: true,
                data: response.data
            };
        } catch (error) {
            console.error('Verify API error:', error.response?.data || error.message);
            return {
                success: false,
                error: this._formatError(error)
            };
        }
    }

    /**
     * Check if API is available
     * @returns {Promise<boolean>}
     */
    async healthCheck() {
        try {
            const response = await axios.get(`${API_URL}/health`, { timeout: 3000 });
            return response.data.status === 'healthy';
        } catch (error) {
            return false;
        }
    }

    /**
     * Format error for consistent error handling
     * @private
     */
    _formatError(error) {
        if (error.response) {
            // API returned an error
            return {
                code: error.response.data?.error || 'API_ERROR',
                message: error.response.data?.message || 'API request failed',
                status: error.response.status
            };
        } else if (error.request) {
            // No response received (API down)
            return {
                code: 'API_UNAVAILABLE',
                message: 'Could not reach the API service. Please try again later.',
                status: 503
            };
        } else {
            // Request setup error
            return {
                code: 'REQUEST_ERROR',
                message: error.message,
                status: 500
            };
        }
    }
}

/**
 * Get API client instance for a project
 * @param {string} apiKey - Project API key
 * @returns {InslashAPIClient}
 */
function getApiClient(apiKey) {
    if (!apiKey) {
        throw new Error('API key is required');
    }
    return new InslashAPIClient(apiKey);
}

/**
 * Fallback: Use local inslash package if API is unavailable
 * This provides redundancy for critical authentication operations
 */
const localInslash = require('inslash');

/**
 * Hash a password with API fallback to local processing
 * For use in web app - doesn't require API key
 */
async function hashWithFallback(password, pepper, options = {}) {
    const apiUrl = process.env.API_URL || 'http://localhost:3001';
    const systemApiKey = process.env.SYSTEM_API_KEY;

    // Try API if system key is available
    if (systemApiKey) {
        try {
            const client = new InslashAPIClient(systemApiKey);
            const apiResult = await client.hashPassword(password, options);

            if (apiResult.success) {
                console.log('✅ Used API for hashing');
                return apiResult.data;
            }
        } catch (error) {
            console.warn('⚠️ API hash failed, using local fallback:', error.message);
        }
    }

    // Fallback to local hashing
    console.log('🔄 Using local hashing');
    return await localInslash.hash(password, pepper, options);
}

/**
 * Verify a password with API fallback to local processing
 * For use in web app - doesn't require API key
 */
async function verifyWithFallback(password, passport, pepper, options = {}) {
    const apiUrl = process.env.API_URL || 'http://localhost:3001';
    const systemApiKey = process.env.SYSTEM_API_KEY;

    // Try API if system key is available
    if (systemApiKey) {
        try {
            const client = new InslashAPIClient(systemApiKey);
            const apiResult = await client.verifyPassword(password, passport, options);

            if (apiResult.success) {
                console.log('✅ Used API for verification');
                return apiResult.data;
            }
        } catch (error) {
            console.warn('⚠️ API verify failed, using local fallback:', error.message);
        }
    }

    // Fallback to local verification
    console.log('🔄 Using local verification');
    return await localInslash.verify(password, passport, pepper, options);
}

module.exports = {
    InslashAPIClient,
    getApiClient,
    hashWithFallback,
    verifyWithFallback
};
