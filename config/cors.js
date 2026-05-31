/**
 * Shared CORS configuration for all LOGI microservices.
 * Used by both auth-server.js and logbook-server.js.
 */

const cors = require('cors');

const isProduction = process.env.NODE_ENV === 'production';

const allowedOrigins = isProduction
    ? ['https://sreehari-m-dev.github.io'] // Production: only GitHub Pages
    : [
        // Development: specific origins are checked dynamically below
        // to allow any localhost port (Live Server, Live Preview, Vite, etc.)
        'http://10.196.162.19',
        'http://10.154.126.1:5000'
    ];

/**
 * Check if an origin is a local development origin (any port on localhost/127.0.0.1).
 * This avoids the recurring issue of forgetting to add a new port when switching
 * dev servers (Live Server 5500, Live Preview 3000, Vite 5173, etc.).
 */
function isLocalOrigin(origin) {
    try {
        const url = new URL(origin);
        const hostname = url.hostname;
        return hostname === 'localhost'
            || hostname === '127.0.0.1'
            || hostname.startsWith('192.168.')
            || hostname.startsWith('10.');
    } catch {
        return false;
    }
}

const corsMiddleware = cors({
    origin: function(origin, callback) {
        // Allow requests with no Origin header (health checks, server-to-server, curl, etc.)
        // These are not browser cross-origin requests, so CORS doesn't apply.
        // Browsers ALWAYS send an Origin header on cross-origin requests.
        if (!origin) {
            return callback(null, true);
        }
        // In development, allow any local origin (any port on localhost/127.0.0.1/LAN)
        if (!isProduction && isLocalOrigin(origin)) {
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
