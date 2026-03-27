/**
 * Combined LOGI Server - Production Entry Point
 * 
 * Merges auth-server and logbook-server into a single Express process.
 * This reduces Render free-tier service count and eliminates network overhead
 * for inter-service communication (auth ↔ logbook calls become localhost self-calls).
 * 
 * Usage:
 *   node server.js            # Production (or Render start command)
 *   npm run dev               # Local dev (still runs both separately via concurrently)
 */

// Load environment variables FIRST
require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const rateLimit = require('express-rate-limit');
const corsMiddleware = require('./config/cors');

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== SELF-REFERENTIAL SERVICE URLS ====================
// In combined mode, inter-service calls go to the same process via localhost.
// Set these BEFORE requiring sub-apps so they pick up the correct URLs.
process.env.COMBINED_MODE = 'true';
process.env.AUTH_SERVICE_URL = `http://localhost:${PORT}`;
process.env.LOGBOOK_SERVICE_URL = `http://localhost:${PORT}`;

// ==================== SHARED MIDDLEWARE (applied once) ====================

// Request logging (skip noisy health checks and preflight)
app.use((req, res, next) => {
    if (req.path === '/health' || req.method === 'OPTIONS') return next();
    console.log(`[REQUEST] ${req.method} ${req.path}`);
    if (process.env.NODE_ENV !== 'production') {
        console.log(`[HEADERS] Origin: ${req.headers.origin}, Host: ${req.headers.host}`);
    }
    next();
});

// CORS
app.use(corsMiddleware);

// Security headers
app.use(helmet());

// Prevent NoSQL injection (Express 5 compatibility)
app.use((req, res, next) => {
    if (req.body) req.body = mongoSanitize.sanitize(req.body);
    next();
});

// General rate limiting (route-specific limiters still apply in sub-apps)
const generalLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 200, // generous — route-specific limiters handle sensitive endpoints
    message: { success: false, error: 'Too many requests. Please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});
app.use(generalLimiter);

// JSON/URL-encoded body parsing (use the higher limit needed by logbook)
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ==================== HEALTH CHECK (before sub-apps for fast response) ====================

app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        mode: 'combined',
        server: 'LOGI Combined Server',
        port: PORT,
        timestamp: new Date().toISOString()
    });
});

// ==================== MOUNT SUB-APPLICATIONS ====================
// Both files detect COMBINED_MODE and skip their own middleware + app.listen().
// They export their Express app with routes attached.

const authApp = require('./auth-server');
const logbookApp = require('./logbook-server');

app.use(authApp);
app.use(logbookApp);

// ==================== START SERVER ====================

app.listen(PORT, () => {
    console.log('');
    console.log('🚀 ═══════════════════════════════════════════════');
    console.log(`   LOGI Combined Server running on port ${PORT}`);
    console.log('   ───────────────────────────────────────────────');
    console.log('   Auth routes:    /api/auth/*');
    console.log('   Logbook routes: /api/logbook/*');
    console.log('   File routes:    /api/files/*');
    console.log('   Health check:   /health');
    console.log('   Mode:           Combined (single process)');
    console.log('═══════════════════════════════════════════════════');
    console.log('');
});
