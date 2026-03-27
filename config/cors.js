/**
 * Shared CORS configuration for all LOGI microservices.
 * Used by both auth-server.js and logbook-server.js.
 */

const cors = require('cors');

const isProduction = process.env.NODE_ENV === 'production';

const allowedOrigins = isProduction
    ? ['https://sreehari-m-dev.github.io'] // Production: only GitHub Pages
    : [
        'http://localhost',
        'http://localhost:3000',
        'http://localhost:8080',
        'http://127.0.0.1',
        'http://127.0.0.1:3000',
        'http://127.0.0.1:3003',
        'http://10.196.162.19',
        'http://10.154.126.1:5000'
    ];

const corsMiddleware = cors({
    origin: function(origin, callback) {
        // Allow requests with no Origin header (health checks, server-to-server, curl, etc.)
        // These are not browser cross-origin requests, so CORS doesn't apply.
        // Browsers ALWAYS send an Origin header on cross-origin requests.
        if (!origin) {
            return callback(null, true);
        }
        if (allowedOrigins.includes(origin)) {
            return callback(null, true);
        }
        console.log(`[CORS] Origin ${origin} is NOT allowed`);
        return callback(new Error('Not allowed by CORS'));
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: false,
    maxAge: 86400
});

module.exports = corsMiddleware;
