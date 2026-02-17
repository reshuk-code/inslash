const axios = require('axios');

const API_URL = process.env.API_URL || 'http://localhost:3001';

class InslashAPIClient {
    constructor(apiKey) {
        this.apiKey = apiKey;
        this.client = axios.create({
            baseURL: API_URL,
            headers: {
                'x-api-key': apiKey,
                'Content-Type': 'application/json'
            },
            timeout: 10000
        });
    }

    async hashPassword(password, options = {}) {
        try {
            const response = await this.client.post('/api/hash', {
                value: password,
                secret: process.env.HASH_PEPPER, // Optional usually, but passed if env var exists
                options
            });
            return { success: true, data: response.data };
        } catch (error) {
            return this._formatError(error);
        }
    }

    async verifyPassword(password, passport, options = {}) {
        try {
            const response = await this.client.post('/api/verify', {
                value: password,
                passport,
                secret: process.env.HASH_PEPPER,
                options
            });
            return { success: true, data: response.data };
        } catch (error) {
            return this._formatError(error);
        }
    }

    _formatError(error) {
        const errData = error.response?.data || { message: error.message };
        return {
            success: false,
            error: {
                code: errData.error || 'UNKNOWN',
                message: errData.message || 'Unknown error',
                status: error.response?.status || 500
            }
        };
    }
}

module.exports = { InslashAPIClient };
