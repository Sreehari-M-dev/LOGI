/**
 * User-Friendly Error Handler & Logger
 * Converts technical errors into human-readable messages
 * Shows styled pop-up notifications to users
 */

// Error message translations
const ERROR_MESSAGES = {
    // Database errors
    'MONGODB_DRIVER': 'Database driver update in progress. This is normal and will be fixed soon.',
    'useNewUrlParser': 'Database connection is being optimized.',
    'useUnifiedTopology': 'Database driver is being updated for better performance.',
    'MongoDB connection error': 'Could not connect to the database. Please check your connection.',
    
    // Network errors
    'Failed to fetch': 'Network error. Please check your internet connection.',
    'CORS error': 'Connection blocked. Please refresh the page.',
    'Bad Request': 'The request was invalid. Please try again.',
    '400': 'Something went wrong with your request. Please try again.',
    '401': 'You need to log in. Please log in first.',
    '403': 'You do not have permission to do this.',
    '404': 'The requested item was not found.',
    '500': 'Server error. Please try again later.',
    
    // Authentication errors
    'No token provided': 'Please log in to continue.',
    'Invalid token': 'Your login session expired. Please log in again.',
    'Authentication failed': 'Login failed. Please check your credentials.',
    
    // Validation errors
    'required': 'This field is required.',
    'invalid email': 'Please enter a valid email address.',
    'password mismatch': 'Passwords do not match.',
    
    // Password reset errors
    'Invalid or expired token': 'This password reset link has expired. Please request a new one.',
    'Email does not match': 'The email does not match this register number.',
    'No user found': 'User not found. Please check your register number.',
    'Failed to send reset email': 'Could not send reset email. Please try again.',
    
    // Duplicate field errors (match exact server messages)
    'This email is already registered': 'This email is already registered. Please use a different email.',
    'This register number is already registered': 'This register number is already registered.',
    'duplicate key error': 'This information is already registered. Please use a different email or register number.',
    'E11000': 'This information is already in use. Please try again with different details.',
    
    // File upload errors
    'File too large': 'The file is too large. Maximum size is 10MB.',
    'Invalid file type': 'This file type is not allowed.'
};

// Severity levels with colors matching project theme
const SEVERITY_LEVELS = {
    info: {
        color: '#2196F3',
        bgColor: '#E3F2FD',
        icon: 'ℹ️',
        title: 'Information'
    },
    warning: {
        color: '#FF9800',
        bgColor: '#FFF3E0',
        icon: '⚠️',
        title: 'Warning'
    },
    error: {
        color: '#F44336',
        bgColor: '#FFEBEE',
        icon: '❌',
        title: 'Error'
    },
    success: {
        color: '#4CAF50',
        bgColor: '#E8F5E9',
        icon: '✅',
        title: 'Success'
    }
};

/**
 * Get user-friendly error message
 */
function getErrorMessage(error) {
    const errorStr = error.toString().toLowerCase();
    
    // Check for exact matches first
    for (const [key, message] of Object.entries(ERROR_MESSAGES)) {
        if (errorStr.includes(key.toLowerCase())) {
            return message;
        }
    }
    
    // If no match found, return generic message
    return 'Something went wrong. Please try again or contact support.';
}

/**
 * Show styled error notification (Browser)
 */
function showErrorNotification(message, severity = 'error') {
    if (typeof window === 'undefined') return; // Server-side check
    
    const style = SEVERITY_LEVELS[severity] || SEVERITY_LEVELS.error;
    
    // Remove existing notification
    const existing = document.querySelector('.user-friendly-notification');
    if (existing) existing.remove();
    
    // Create notification element
    const notification = document.createElement('div');
    notification.className = 'user-friendly-notification';
    notification.innerHTML = `
        <div class="notification-content">
            <span class="notification-icon">${style.icon}</span>
            <div class="notification-message">
                <strong>${style.title}</strong>
                <p>${message}</p>
            </div>
            <button class="notification-close" onclick="this.parentElement.parentElement.remove()">×</button>
        </div>
    `;
    
    // Style the notification
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 10000;
        border-radius: 12px;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.15);
        max-width: 400px;
        animation: slideInRight 0.3s ease-out;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    `;
    
    const content = notification.querySelector('.notification-content');
    content.style.cssText = `
        display: flex;
        align-items: flex-start;
        gap: 15px;
        padding: 16px 20px;
        background: ${style.bgColor};
        border-left: 4px solid ${style.color};
    `;
    
    const icon = notification.querySelector('.notification-icon');
    icon.style.cssText = `
        font-size: 20px;
        flex-shrink: 0;
        margin-top: 2px;
    `;
    
    const messageDiv = notification.querySelector('.notification-message');
    messageDiv.style.cssText = `
        flex: 1;
        color: #333;
        font-size: 14px;
    `;
    
    messageDiv.querySelector('strong').style.cssText = `
        display: block;
        color: ${style.color};
        margin-bottom: 4px;
        font-size: 15px;
    `;
    
    messageDiv.querySelector('p').style.cssText = `
        margin: 0;
        color: #666;
        font-size: 13px;
        line-height: 1.4;
    `;
    
    const closeBtn = notification.querySelector('.notification-close');
    closeBtn.style.cssText = `
        background: none;
        border: none;
        font-size: 24px;
        color: ${style.color};
        cursor: pointer;
        padding: 0;
        margin-left: 10px;
        flex-shrink: 0;
    `;
    
    closeBtn.addEventListener('mouseover', () => {
        closeBtn.style.opacity = '0.7';
    });
    
    closeBtn.addEventListener('mouseout', () => {
        closeBtn.style.opacity = '1';
    });
    
    // Add to page
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds (unless error)
    if (severity !== 'error') {
        setTimeout(() => {
            if (notification.parentElement) {
                notification.style.animation = 'slideOutRight 0.3s ease-in';
                setTimeout(() => notification.remove(), 300);
            }
        }, 5000);
    }
}

/**
 * Show SweetAlert2 notification (if available)
 */
function showAlertNotification(message, severity = 'error') {
    if (typeof Swal === 'undefined') {
        showErrorNotification(message, severity);
        return;
    }
    
    const iconMap = {
        error: 'error',
        warning: 'warning',
        success: 'success',
        info: 'info'
    };
    
    Swal.fire({
        title: SEVERITY_LEVELS[severity].title,
        text: message,
        icon: iconMap[severity],
        confirmButtonColor: SEVERITY_LEVELS[severity].color,
        confirmButtonText: 'OK',
        allowOutsideClick: true,
        allowEscapeKey: true,
        toast: false,
        position: 'center'
    });
}

/**
 * Safe error logging (doesn't expose sensitive info)
 */
function logError(context, error, isSensitive = false) {
    const timestamp = new Date().toLocaleTimeString();
    const message = error.message || error.toString();
    
    if (isSensitive) {
        console.log(`[${timestamp}] ${context}: Error occurred (details hidden for security)`);
    } else {
        console.log(`[${timestamp}] ${context}: ${message}`);
    }
}

/**
 * Add CSS animations
 */
function injectStyles() {
    if (document.getElementById('user-friendly-styles')) return;
    
    const style = document.createElement('style');
    style.id = 'user-friendly-styles';
    style.textContent = `
        @keyframes slideInRight {
            from {
                transform: translateX(420px);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        @keyframes slideOutRight {
            from {
                transform: translateX(0);
                opacity: 1;
            }
            to {
                transform: translateX(420px);
                opacity: 0;
            }
        }
        
        .user-friendly-notification {
            transition: all 0.3s ease;
        }
        
        .notification-close:active {
            transform: scale(0.9);
        }
        
        @media (max-width: 600px) {
            .user-friendly-notification {
                left: 10px !important;
                right: 10px !important;
                max-width: none !important;
                top: 10px !important;
            }
        }
    `;
    document.head.appendChild(style);
}

// Initialize styles on load
if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', injectStyles);
} else {
    injectStyles();
}

// Global error handlers to show friendly popups for uncaught errors
if (typeof window !== 'undefined') {
    // Lightweight ignore list for noisy/benign messages
    const IGNORE_PATTERNS = [
        'deprecated',
        'usenewurlparser',
        'useunifiedtopology',
        'warning',
        'favicon.ico',
        'source-map',
        'chrome-extension',
        'webpack',
        'devtools',
        'failed to load resource',
        'refused to connect',
        'manifest.json',
        'serviceworker',
        'overrode',
    ];

    // Rate-limit / de-dupe popups to avoid noisy UX
    let _lastPopupAt = 0;
    let _lastPopupMsg = '';
    const POPUP_COOLDOWN_MS = 4000; // at most one every 4s

    function _shouldIgnoreMessage(msg) {
        if (!msg) return true;
        const s = msg.toString().toLowerCase();
        for (const p of IGNORE_PATTERNS) {
            if (s.includes(p)) return true;
        }
        return false;
    }

    function _maybeShowPopup(rawMsg, defaultSeverity = 'error') {
        try {
            const now = Date.now();
            const msg = (rawMsg || '').toString();

            // ignore short/empty
            if (!msg || msg.trim().length < 3) return;

            // ignore noisy patterns
            if (_shouldIgnoreMessage(msg)) {
                console.debug('Ignored noisy message:', msg);
                return;
            }

            // de-dupe identical messages
            if (msg === _lastPopupMsg && (now - _lastPopupAt) < POPUP_COOLDOWN_MS) {
                console.debug('Suppressed duplicate popup:', msg);
                return;
            }

            // rate limit
            if ((now - _lastPopupAt) < POPUP_COOLDOWN_MS) {
                console.debug('Popup rate-limited:', msg);
                return;
            }

            _lastPopupAt = now;
            _lastPopupMsg = msg;

            // map some technical messages to less-invasive severities
            let severity = defaultSeverity;
            if (msg.toLowerCase().includes('failed to fetch')) {
                // network blips are often transient — show as warning (auto-hide)
                severity = 'warning';
            }

            const friendly = getErrorMessage(msg);
            showErrorNotification(friendly, severity);
            logError('GlobalHandler', msg, true);
        } catch (e) {
            console.error('Error handler failed:', e);
        }
    }

    window.addEventListener('error', (ev) => {
        const msg = ev && (ev.message || (ev.error && ev.error.message)) || '';
        _maybeShowPopup(msg, 'error');
    });

    window.addEventListener('unhandledrejection', (ev) => {
        const reason = ev && ev.reason ? (ev.reason.message || ev.reason.toString()) : '';
        _maybeShowPopup(reason, 'error');
    });
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        showErrorNotification,
        showAlertNotification,
        getErrorMessage,
        logError,
        ERROR_MESSAGES,
        SEVERITY_LEVELS
    };
}
