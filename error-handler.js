/**
 * User-Friendly Error Handler & Logger
 * Converts technical errors into human-readable messages
 * Shows styled pop-up notifications to users using SweetAlert2
 */

// Error message translations - Natural language messages
const ERROR_MESSAGES = {
    // Database errors
    'MONGODB_DRIVER': 'We\'re updating our systems. Please try again in a moment.',
    'useNewUrlParser': 'We\'re optimizing our connection. Please wait.',
    'useUnifiedTopology': 'We\'re improving our service. Please be patient.',
    'MongoDB connection error': 'We couldn\'t connect to our servers. Please check your internet connection and try again.',
    'database error': 'There was a problem accessing our database. Please try again later.',
    
    // Network errors
    'Failed to fetch': 'We couldn\'t reach our servers. Please check your internet connection and try again.',
    'NetworkError': 'You seem to be offline. Please check your internet connection.',
    'CORS error': 'There was a connection issue. Please refresh the page and try again.',
    'Bad Request': 'We couldn\'t process your request. Please check your information and try again.',
    '400': 'Something doesn\'t look right. Please check your information and try again.',
    '401': 'You need to log in to access this. Please sign in and try again.',
    '403': 'You don\'t have permission to do this. Please contact an administrator if you think this is a mistake.',
    '404': 'We couldn\'t find what you were looking for. It may have been moved or deleted.',
    '500': 'Something went wrong on our end. Please try again later.',
    '502': 'Our servers are temporarily unavailable. Please try again in a few minutes.',
    '503': 'Our service is temporarily unavailable. Please try again later.',
    
    // Authentication errors
    'No token provided': 'You need to be logged in to do this. Please sign in and try again.',
    'Invalid token': 'Your session has expired. Please log in again to continue.',
    'Authentication failed': 'We couldn\'t verify your credentials. Please check your email and password.',
    'Incorrect password': 'The password you entered is incorrect. Please try again.',
    'User not found': 'We couldn\'t find an account with those details. Please check and try again.',
    'Session expired': 'Your session has expired for security reasons. Please log in again.',
    
    // Validation errors
    'required': 'Please fill in all required fields.',
    'invalid email': 'Please enter a valid email address.',
    'password mismatch': 'The passwords you entered don\'t match. Please try again.',
    'too short': 'The information you entered is too short. Please provide more details.',
    'too long': 'The information you entered is too long. Please shorten it.',
    
    // Password reset errors
    'Invalid or expired token': 'This password reset link has expired. Please request a new one from the login page.',
    'Email does not match': 'The email address doesn\'t match our records for this account.',
    'No user found': 'We couldn\'t find an account with that information. Please check and try again.',
    'Failed to send reset email': 'We couldn\'t send the reset email. Please try again or contact support.',
    'Reset link expired': 'This reset link has expired. Please request a new password reset.',
    
    // Registration hierarchy errors
    'No approved faculty found': 'No faculty has been registered and approved for your college/department yet. A faculty member must register and be approved before students can register.',
    'No approved principal found': 'No principal has been registered and approved for your college yet. The principal must register and be approved before faculty can register.',
    'A faculty member must be registered': 'A faculty member needs to be registered and approved for your college/department before students can register.',
    'A principal must be registered': 'The principal needs to be registered and approved for your college before faculty can register.',
    'Only one principal is allowed': 'A principal is already registered for this college. Only one principal is allowed per college. If the previous principal transferred, please contact them or the super-admin.',
    'principal is already registered': 'A principal is already registered for this college. Contact the existing principal to transfer the account or ask the super-admin to remove the old account.',
    'principal registration is already pending': 'A principal registration is already pending approval for this college. Please wait or contact the super-admin.',
    'pending registration': 'This account has a pending registration. Please wait for approval.',
    'has a pending registration': 'This has a pending registration. Please wait for approval before trying again.',
    
    // Duplicate field errors (match exact server messages)
    'This email is already registered': 'This email address is already in use. Please use a different email or try logging in.',
    'This register number is already registered': 'This register number is already in use. Please check if you already have an account.',
    'This register number has a pending registration': 'This register number has a pending registration. Please wait for approval.',
    'This email has a pending registration': 'This email has a pending registration. Please wait for approval.',
    'duplicate key error': 'This information is already registered. Please use different details or try logging in.',
    'E11000': 'This information is already in use. Please try with different details.',
    'already exists': 'This already exists in our system. Please try with different information.',
    
    // File upload errors
    'File too large': 'This file is too large. Please use a file smaller than 10MB.',
    'Invalid file type': 'This file type isn\'t supported. Please use a different file format.',
    'upload failed': 'We couldn\'t upload your file. Please try again.',
    
    // Logbook-specific errors
    'template not found': 'We couldn\'t find the logbook template. It may have been deleted.',
    'logbook not found': 'We couldn\'t find this logbook. It may have been removed.',
    'already assigned': 'This student is already assigned to a logbook for this course.',
    'cannot delete': 'This cannot be deleted because it\'s currently in use.',
    'integrity check failed': 'The file integrity check failed. The file may have been modified.',
    'hash mismatch': 'This file appears to have been modified outside the system.',
    
    // Permission errors
    'not authorized': 'You\'re not authorized to perform this action.',
    'students cannot': 'This feature is only available to faculty members.',
    'faculty only': 'Only faculty members can access this feature.'
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
 * Show SweetAlert2 notification (preferred method)
 * Falls back to custom notification if SweetAlert2 is not available
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
    
    const buttonColors = {
        error: '#F44336',
        warning: '#FF9800',
        success: '#4CAF50',
        info: '#2196F3'
    };
    
    Swal.fire({
        title: SEVERITY_LEVELS[severity].title,
        text: message,
        icon: iconMap[severity],
        confirmButtonColor: buttonColors[severity] || '#667eea',
        confirmButtonText: 'Got it',
        allowOutsideClick: true,
        allowEscapeKey: true,
        toast: false,
        position: 'center',
        customClass: {
            popup: 'user-friendly-swal-popup'
        }
    });
}

/**
 * Show error popup - Primary function to use throughout the app
 * Prefers SweetAlert2, falls back to custom notification
 */
function showErrorPopup(message, severity = 'error') {
    const friendlyMessage = typeof message === 'string' 
        ? getErrorMessage(message) 
        : getErrorMessage(message.message || message.toString());
    
    showAlertNotification(friendlyMessage, severity);
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
        showErrorPopup,
        getErrorMessage,
        logError,
        ERROR_MESSAGES,
        SEVERITY_LEVELS
    };
}
