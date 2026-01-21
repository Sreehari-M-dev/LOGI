// Authentication Helper
const AUTH_API = window.REACT_APP_AUTH_API || 'http://localhost:3002/api/auth';
const INACTIVITY_TIMEOUT = 10 * 60 * 1000; // 10 minutes in milliseconds (server-driven)

class AuthManager {
    static inactivityTimer = null;
    static syncInterval = null;
    
    static getToken() {
        return localStorage.getItem('token');
    }
    
    static setToken(token) {
        localStorage.setItem('token', token);
    }
    
    static removeToken() {
        localStorage.removeItem('token');
    }
    
    static getUser() {
        const user = localStorage.getItem('user');
        return user ? JSON.parse(user) : null;
    }
    
    static setUser(user) {
        localStorage.setItem('user', JSON.stringify(user));
    }
    
    static removeUser() {
        localStorage.removeItem('user');
    }
    
    static isLoggedIn() {
        return !!this.getToken();
    }
    
    static resetInactivityTimer(remainingMs = INACTIVITY_TIMEOUT) {
        // Clear existing timer
        if (this.inactivityTimer) {
            clearTimeout(this.inactivityTimer);
        }

        if (this.isLoggedIn()) {
            const safeRemaining = Math.max(0, remainingMs);
            this.timeoutEndTime = Date.now() + safeRemaining;
            
            console.log('[AUTH] Timer reset - Will expire in', Math.floor(safeRemaining / 1000), 'seconds');

            this.inactivityTimer = setTimeout(() => {
                this.logout('inactivity');
            }, safeRemaining);

            this.updateTimerDisplay();
        }
    }
    
    static displayUpdateInterval = null;
    
    static updateTimerDisplay(retryCount = 0) {
        const timerElement = document.getElementById('inactivityTimer');
        if (!timerElement) {
            // Timer element not ready yet, retry up to 10 times
            if (retryCount < 10) {
                setTimeout(() => this.updateTimerDisplay(retryCount + 1), 100);
            }
            return;
        }
        
        // Clear any existing display interval to prevent multiple loops
        if (this.displayUpdateInterval) {
            clearInterval(this.displayUpdateInterval);
            this.displayUpdateInterval = null;
        }
        
        // Update function that runs every second
        const updateDisplay = () => {
            const el = document.getElementById('inactivityTimer');
            if (!el || !this.isLoggedIn() || !this.timeoutEndTime) {
                if (this.displayUpdateInterval) {
                    clearInterval(this.displayUpdateInterval);
                    this.displayUpdateInterval = null;
                }
                return;
            }
            
            const remaining = Math.max(0, this.timeoutEndTime - Date.now());
            const minutes = Math.floor(remaining / 60000);
            const seconds = Math.floor((remaining % 60000) / 1000);
            
            el.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
            el.style.color = remaining < 120000 ? '#e74c3c' : '#ffffffff'; // Red if < 2 min
            
            if (remaining <= 0) {
                el.textContent = '0:00';
                if (this.displayUpdateInterval) {
                    clearInterval(this.displayUpdateInterval);
                    this.displayUpdateInterval = null;
                }
            }
        };
        
        // Run immediately
        updateDisplay();
        
        // Then update every second
        this.displayUpdateInterval = setInterval(updateDisplay, 1000);
    }
    
    static async startInactivityMonitoring() {
        // Super-admin users don't have session timeout
        const user = this.getUser();
        if (user && user.role === 'super-admin') {
            console.log('[AUTH] Super-admin detected - skipping inactivity monitoring');
            return;
        }
        
        // Check if "Stay logged in" is enabled
        const stayLoggedIn = localStorage.getItem('stayLoggedIn') === 'true';
        if (stayLoggedIn) {
            console.log('[AUTH] Stay logged in enabled - skipping inactivity monitoring');
            // Hide timer display if it exists
            const timerEl = document.getElementById('inactivityTimer');
            if (timerEl) {
                timerEl.parentElement.style.display = 'none';
            }
            return;
        }
        
        // Do not reset on user activity; only refresh when page loads or navigation occurs.
        await this.syncRemainingWithServer();

        // Periodically resync with server (does not extend session)
        if (!this.syncInterval) {
            this.syncInterval = setInterval(() => this.syncRemainingWithServer(), 60000);
        }
        
        // Handle page visibility - sync when user returns to the page
        if (!this.visibilityHandler) {
            this.visibilityHandler = () => {
                if (!document.hidden && this.isLoggedIn()) {
                    // Page became visible again - resync with server
                    this.syncRemainingWithServer();
                }
            };
            document.addEventListener('visibilitychange', this.visibilityHandler);
        }
    }
    
    static stopInactivityMonitoring() {
        if (this.inactivityTimer) {
            clearTimeout(this.inactivityTimer);
            this.inactivityTimer = null;
        }
        this.timeoutEndTime = null;

        if (this.syncInterval) {
            clearInterval(this.syncInterval);
            this.syncInterval = null;
        }
        
        // Clear display update interval
        if (this.displayUpdateInterval) {
            clearInterval(this.displayUpdateInterval);
            this.displayUpdateInterval = null;
        }
        
        // Remove visibility handler
        if (this.visibilityHandler) {
            document.removeEventListener('visibilitychange', this.visibilityHandler);
            this.visibilityHandler = null;
        }
    }

    static async syncRemainingWithServer() {
        if (!this.isLoggedIn()) return;
        try {
            const res = await fetch(`${AUTH_API}/session-remaining`, {
                method: 'GET',
                headers: this.getAuthHeader()
            });

            if (res.status === 401) {
                // Session already expired on server
                console.log('[AUTH] Session expired on server, logging out');
                return this.logout('inactivity');
            }

            const data = await res.json();
            if (data.success && typeof data.remainingMs === 'number') {
                console.log('[AUTH] Server sync - Remaining time:', Math.floor(data.remainingMs / 1000), 'seconds');
                this.resetInactivityTimer(data.remainingMs);
            } else {
                // Fallback to client timer if server doesn't respond properly
                console.log('[AUTH] Using fallback client timer');
                this.resetInactivityTimer();
            }
        } catch (error) {
            console.error('Failed to sync session remaining time:', error);
            // Do not reset timer on error; rely on existing timer if any
        }
    }
    
    static isStudent() {
        const user = this.getUser();
        return user && user.role === 'student';
    }
    
    static isFaculty() {
        const user = this.getUser();
        return user && user.role === 'faculty';
    }
    
    static isAdmin() {
        const user = this.getUser();
        return user && user.role === 'admin';
    }
    
    static async logout(reason = 'manual') {
        // Stop inactivity monitoring
        this.stopInactivityMonitoring();
        
        // Store logout reason for display on login page
        if (reason === 'inactivity') {
            sessionStorage.setItem('logoutReason', 'Your session expired due to 10 minutes of inactivity.');
        } else if (reason === 'manual') {
            sessionStorage.setItem('logoutReason', 'You have been successfully logged out.');
        }
        
        try {
            await fetch(`${AUTH_API}/logout`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.getToken()}`
                }
            });
        } catch (error) {
            console.error('Logout error:', error);
        }
        
        this.removeToken();
        this.removeUser();
        window.location.href = 'login-page.html';
    }
    
    static getAuthHeader() {
        return {
            'Authorization': `Bearer ${this.getToken()}`,
            'Content-Type': 'application/json'
        };
    }
}

// Protect pages - redirect to login if not authenticated
function checkAuthentication() {
    if (!AuthManager.isLoggedIn()) {
        window.location.href = 'login-page.html';
        return false;
    }
    
    return true;
}

// Initialize authentication on page load
document.addEventListener('DOMContentLoaded', () => {
    // Get current page filename
    const currentPage = window.location.pathname.split('/').pop();
    
    // Pages that don't require authentication
    const publicPages = ['login-page.html', 'register.html', 'home.html'];
    
    // Check if current page requires authentication
    if (!publicPages.includes(currentPage) && !currentPage.includes('login') && !currentPage.includes('register')) {
        checkAuthentication();
    }

    // Setup authentication buttons (login/logout) on navbar FIRST
    // This creates the timer element before we try to update it
    setupAuthButtons();
    
    // THEN start inactivity monitoring when logged in (except for super-admin)
    if (AuthManager.isLoggedIn()) {
        const user = AuthManager.getUser();
        // Super-admin does NOT have session timeout
        if (user && user.role !== 'super-admin') {
            AuthManager.startInactivityMonitoring();
        } else if (user && user.role === 'super-admin') {
            // Hide timer for super-admin
            const timerSpan = document.getElementById('inactivityTimer');
            if (timerSpan && timerSpan.parentElement) {
                timerSpan.parentElement.style.display = 'none';
            }
        }
    }
});

function setupAuthButtons() {
    const navMenu = document.querySelector('.nav-menu');
    
    if (!navMenu) return;
    
    // Remove existing auth buttons if any
    const existingAuthItem = document.getElementById('authNavItem');
    if (existingAuthItem) {
        existingAuthItem.remove();
    }
    
    const isLoggedIn = AuthManager.isLoggedIn();
    const user = AuthManager.getUser();
    
    const authItem = document.createElement('li');
    authItem.id = 'authNavItem';
    
    if (isLoggedIn) {
        // Check if user is super-admin (no timer needed)
        const isSuperAdmin = user && user.role === 'super-admin';
        
        // Show logged-in user info and logout button
        authItem.innerHTML = `
            <div style="display: flex; align-items: center; gap: 15px; color: white; padding: 8px 16px; border-radius: 25px; background: rgba(255,255,255,0.15); border: 1px solid rgba(255,255,255,0.3);">
                <span style="font-weight: 500; font-size: 14px;">
                    <i class="fas fa-user-circle"></i> ${user?.name || 'User'}
                </span>
                ${!isSuperAdmin ? `<span style="font-size: 12px; background: rgba(40, 32, 32, 0.66); padding: 4px 8px; border-radius: 4px; font-weight: 600;" title="Session timeout">
                    <i class="fas fa-clock"></i> <span id="inactivityTimer">10:00</span>
                </span>` : ''}
                <button id="logoutBtn" style="background: #e74c3c; border: none; color: white; cursor: pointer; font-size: 13px; padding: 6px 12px; border-radius: 6px; font-weight: 600; transition: all 0.3s ease;" onclick="AuthManager.logout()">
                    <i class="fas fa-sign-out-alt"></i> Logout
                </button>
            </div>
        `;
    } else {
        // Show login and register buttons
        authItem.innerHTML = `
            <div style="display: flex; align-items: center; gap: 10px;">
                <a href="login-page.html" style="background: #3498db; color: white; padding: 8px 16px; border-radius: 6px; text-decoration: none; font-weight: 600; font-size: 14px; transition: all 0.3s ease;" onmouseover="this.style.background='#2980b9'" onmouseout="this.style.background='#3498db'">
                    <i class="fas fa-sign-in-alt"></i> Login
                </a>
                <a href="register.html" style="background: #27ae60; color: white; padding: 8px 16px; border-radius: 6px; text-decoration: none; font-weight: 600; font-size: 14px; transition: all 0.3s ease;" onmouseover="this.style.background='#229954'" onmouseout="this.style.background='#27ae60'">
                    <i class="fas fa-user-plus"></i> Register
                </a>
            </div>
        `;
    }
    
    navMenu.appendChild(authItem);
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AuthManager;
}
