/**
 * LOGI Client-Side Load Balancer
 * 
 * Distributes frontend requests across multiple backend server replicas.
 * Health-checks servers on page load, selects the fastest healthy one,
 * and provides failover if a server becomes unresponsive.
 * 
 * Usage: Include <script src="load-balancer.js"></script> in HTML pages
 *        BEFORE any scripts that use window.REACT_APP_AUTH_API or LOGBOOK_API.
 * 
 * How it works:
 *   1. On load, pings /health on all servers in parallel
 *   2. Picks the fastest healthy server
 *   3. Sets window.REACT_APP_AUTH_API and window.REACT_APP_LOGBOOK_API
 *   4. Provides fetchWithFailover() for automatic retry on another server
 */

(function () {
    'use strict';

    // ==================== SERVER CONFIGURATION ====================
    // Each entry is a combined server (auth + logbook on one instance).
    // Add or remove URLs as you deploy more replicas.
    const SERVERS = [
        'https://logi-server-avbs.onrender.com',
        'https://logi-server-2.onrender.com',
        'https://logi-server-3.onrender.com',
    ];

    // ==================== LOCAL DEV DETECTION ====================
    const hostname = window.location.hostname;
    const isLocal = ['localhost', '127.0.0.1', '10.154.126.1'].includes(hostname)
        || hostname.startsWith('192.168.')
        || hostname.startsWith('10.');

    if (isLocal) {
        // Local development — use direct local servers, no load balancing
        const host = hostname === 'localhost' ? 'localhost' : hostname;
        window.REACT_APP_AUTH_API = `http://${host}:3002/api/auth`;
        window.REACT_APP_LOGBOOK_API = `http://${host}:3005/api/logbook`;
        window.REACT_APP_FILES_API = `http://${host}:3002/api/files`;
        window.API_BASE = `http://${host}:3002`;
        console.log('[LB] Local dev detected — using local servers');
        return; // Skip all load balancing logic
    }

    // ==================== CONSTANTS ====================
    const HEALTH_TIMEOUT_MS = 8000;  // Max wait for a health check response
    const REQUEST_TIMEOUT_MS = 15000; // Max wait for a regular API request
    const CACHE_KEY = 'logi_lb_server';
    const CACHE_TTL_MS = 5 * 60 * 1000; // Cache healthy server choice for 5 minutes

    // ==================== STATE ====================
    let serverHealth = SERVERS.map(url => ({
        url,
        healthy: null,   // null = unknown, true = up, false = down
        latency: Infinity
    }));

    // ==================== HEALTH CHECKING ====================

    /**
     * Ping a single server's /health endpoint.
     * Returns { url, healthy, latency } 
     */
    async function checkServer(serverUrl) {
        const start = performance.now();
        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), HEALTH_TIMEOUT_MS);

            const res = await fetch(`${serverUrl}/health`, {
                method: 'GET',
                signal: controller.signal,
                mode: 'cors',
                cache: 'no-store'
            });

            clearTimeout(timeout);
            const latency = Math.round(performance.now() - start);

            if (res.ok) {
                console.log(`[LB] ✅ ${serverUrl} → healthy (${latency}ms)`);
                return { url: serverUrl, healthy: true, latency };
            } else {
                console.log(`[LB] ❌ ${serverUrl} → unhealthy (HTTP ${res.status})`);
                return { url: serverUrl, healthy: false, latency: Infinity };
            }
        } catch (err) {
            const latency = Math.round(performance.now() - start);
            console.log(`[LB] ❌ ${serverUrl} → unreachable (${latency}ms) - ${err.message}`);
            return { url: serverUrl, healthy: false, latency: Infinity };
        }
    }

    /**
     * Health-check ALL servers in parallel and update state.
     */
    async function healthCheckAll() {
        const results = await Promise.allSettled(
            SERVERS.map(url => checkServer(url))
        );

        results.forEach((result, i) => {
            if (result.status === 'fulfilled') {
                serverHealth[i] = result.value;
            } else {
                serverHealth[i] = { url: SERVERS[i], healthy: false, latency: Infinity };
            }
        });
    }

    /**
     * Get the best (fastest healthy) server URL.
     * Falls back to the first server if none are healthy (might be waking up).
     */
    function getBestServer() {
        const healthy = serverHealth
            .filter(s => s.healthy === true)
            .sort((a, b) => a.latency - b.latency);

        if (healthy.length > 0) {
            return healthy[0].url;
        }

        // No healthy server found — fall back to first (it'll cold-start)
        console.warn('[LB] ⚠️ No healthy servers found, using default:', SERVERS[0]);
        return SERVERS[0];
    }

    /**
     * Get a list of all servers ordered by preference (healthy first, then by latency).
     */
    function getServersByPreference() {
        return [...serverHealth]
            .sort((a, b) => {
                // Healthy servers first
                if (a.healthy && !b.healthy) return -1;
                if (!a.healthy && b.healthy) return 1;
                // Then by latency
                return a.latency - b.latency;
            })
            .map(s => s.url);
    }

    // ==================== CACHING ====================

    function getCachedServer() {
        try {
            const cached = sessionStorage.getItem(CACHE_KEY);
            if (!cached) return null;
            const { url, timestamp } = JSON.parse(cached);
            if (Date.now() - timestamp < CACHE_TTL_MS && SERVERS.includes(url)) {
                return url;
            }
            sessionStorage.removeItem(CACHE_KEY);
        } catch (e) { /* ignore */ }
        return null;
    }

    function cacheServer(url) {
        try {
            sessionStorage.setItem(CACHE_KEY, JSON.stringify({
                url,
                timestamp: Date.now()
            }));
        } catch (e) { /* ignore */ }
    }

    // ==================== API URL SETUP ====================

    function setApiUrls(serverUrl) {
        // Combined server: both auth and logbook are on the same server
        window.REACT_APP_AUTH_API = `${serverUrl}/api/auth`;
        window.REACT_APP_LOGBOOK_API = `${serverUrl}/api/logbook`;
        window.REACT_APP_FILES_API = `${serverUrl}/api/files`;
        window.API_BASE = serverUrl;
        console.log(`[LB] 🎯 Selected server: ${serverUrl}`);
    }

    // ==================== FETCH WITH FAILOVER ====================

    /**
     * Enhanced fetch that retries on a different server if the first one fails.
     * Drop-in replacement for window.fetch() for API calls.
     * 
     * Usage:
     *   const res = await window.fetchWithFailover('/api/auth/profile', { headers: ... });
     * 
     * The URL should start with /api/ — the server base URL is prepended automatically.
     */
    window.fetchWithFailover = async function (path, options = {}) {
        const servers = getServersByPreference();

        for (let i = 0; i < servers.length; i++) {
            const serverUrl = servers[i];
            const fullUrl = path.startsWith('http') ? path : `${serverUrl}${path}`;

            try {
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

                const res = await fetch(fullUrl, {
                    ...options,
                    signal: options.signal || controller.signal
                });

                clearTimeout(timeout);

                // If server responded (even with 4xx), it's working — don't failover
                return res;
            } catch (err) {
                console.warn(`[LB] Request to ${serverUrl} failed, trying next server...`, err.message);
                // Mark this server as unhealthy for future requests
                const idx = serverHealth.findIndex(s => s.url === serverUrl);
                if (idx !== -1) serverHealth[idx].healthy = false;

                if (i === servers.length - 1) {
                    // Last server also failed — throw the error
                    throw err;
                }
            }
        }
    };

    // ==================== BACKGROUND WAKE-UP ====================

    /**
     * Wake up sleeping servers in the background so they're ready for future requests.
     * Called after initial server selection is done.
     */
    function wakeUpSleepingServers(currentServer) {
        SERVERS.forEach(url => {
            if (url !== currentServer) {
                // Fire-and-forget health check to wake up cold servers
                fetch(`${url}/health`, { method: 'GET', mode: 'cors', cache: 'no-store' })
                    .then(res => {
                        if (res.ok) console.log(`[LB] 🔄 Woke up sleeping server: ${url}`);
                    })
                    .catch(() => { /* silently ignore — it'll wake up eventually */ });
            }
        });
    }

    // ==================== INITIALIZATION ====================

    async function initialize() {
        // Try cached server first (avoids health check delay on every page)
        const cached = getCachedServer();
        if (cached) {
            setApiUrls(cached);
            console.log('[LB] Using cached server (will re-check in background)');
            // Re-check health in background to update cache
            healthCheckAll().then(() => {
                const best = getBestServer();
                if (best !== cached) {
                    console.log(`[LB] Cache updated: ${cached} → ${best}`);
                    setApiUrls(best);
                    cacheServer(best);
                }
                wakeUpSleepingServers(best);
            });
            return;
        }

        // No cache — health check all servers
        console.log(`[LB] Checking ${SERVERS.length} server(s)...`);
        await healthCheckAll();

        const best = getBestServer();
        setApiUrls(best);
        cacheServer(best);

        // Wake up other servers in background
        wakeUpSleepingServers(best);
    }

    // Set temporary URLs immediately (in case scripts run before health check completes)
    setApiUrls(SERVERS[0]);

    // Run health check and select best server
    initialize().catch(err => {
        console.error('[LB] Initialization error:', err);
        // Keep default URLs set above
    });
})();
