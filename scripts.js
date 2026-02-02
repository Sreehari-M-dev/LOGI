// Hamburger Menu Functionality
function initHamburgerMenu() {
    const hamburger = document.getElementById('hamburger');
    const navMenu = document.getElementById('nav-menu');

    if (!hamburger) {
        console.error('ERROR: Hamburger element not found');
        return;
    }
    
    if (!navMenu) {
        console.error('ERROR: Nav-menu element not found');
        return;
    }

    console.log('✓ Hamburger menu initialized');

    // Toggle menu on hamburger click
    hamburger.addEventListener('click', function(e) {
        console.log('Hamburger clicked');
        e.preventDefault();
        e.stopPropagation();
        
        const isActive = hamburger.classList.contains('active');
        console.log('Current state:', isActive ? 'active' : 'inactive');
        
        hamburger.classList.toggle('active');
        navMenu.classList.toggle('active');
        
        console.log('New state:', hamburger.classList.contains('active') ? 'active' : 'inactive');
    });

    // Close menu when clicking on a link
    const links = navMenu.querySelectorAll('a');
    console.log('Found', links.length, 'menu links');
    
    links.forEach(link => {
        link.addEventListener('click', function() {
            console.log('Menu link clicked, closing menu');
            hamburger.classList.remove('active');
            navMenu.classList.remove('active');
        });
    });

    // Close menu when clicking outside
    document.addEventListener('click', function(e) {
        if (!navMenu.contains(e.target) && !hamburger.contains(e.target) && hamburger.classList.contains('active')) {
            console.log('Clicked outside menu, closing');
            hamburger.classList.remove('active');
            navMenu.classList.remove('active');
        }
    });
}

// Log Book Dynamic Row Functions
function addRow(event) {
    event.preventDefault();
    const table = document.getElementById('t1');
    if (!table) return;
    
    const rowCount = table.rows.length - 4; // Adjust for header rows and button row
    const newRow = table.insertRow(rowCount + 3);
    newRow.innerHTML = `
        <td>${rowCount + 1}</td>
        <td><input type="date" name="date${rowCount + 1}"></td>
        <td><input type="text" name="experiment${rowCount + 1}" id="exp${rowCount + 1}"></td>
        <td><input type="number" name="co${rowCount + 1}" min="0" max="9"></td>
        <td><input type="number" name="rubric${rowCount + 1}-1"></td>
        <td><input type="number" name="rubric${rowCount + 1}-2"></td>
        <td><input type="number" name="rubric${rowCount + 1}-3"></td>
        <td><input type="number" name="rubric${rowCount + 1}-4"></td>
        <td><input type="number" name="rubric${rowCount + 1}-5"></td>
        <td><input type="number" name="total${rowCount + 1}" readonly></td>
        <td><input type="checkbox" name="student${rowCount + 1}"></td>
        <td><input type="checkbox" name="faculty${rowCount + 1}"></td>
    `;
    
    // Attach event listeners to new rubric fields for auto-calculation
    if (typeof attachRubricCalculationListeners === 'function') {
        // Re-attach listeners for the new row's rubric fields
        for (let rubric = 1; rubric <= 5; rubric++) {
            const field = document.querySelector(`[name="rubric${rowCount + 1}-${rubric}"]`);
            if (field) {
                field.addEventListener('change', () => calculateRubricTotal('', rowCount + 1));
                field.addEventListener('input', () => calculateRubricTotal('', rowCount + 1));
            }
        }
    }
}

function delRow(event) {
    event.preventDefault();
    const table = document.getElementById('t1');
    if (!table) return;
    
    // Count the actual data rows (exclude 3 header rows)
    // Table structure: 3 header rows + 7 default rows + button row = rows.length
    // To find last data row index: rows.length - 2 (button row is at end, -1 more for 0-indexing)
    const lastDataRowIndex = table.rows.length - 2;
    
    // Count how many data rows exist (should be >= 7)
    const dataRowCount = table.rows.length - 4; // 3 header rows + 1 button row
    
    if (dataRowCount > 7) {
        // Only allow deletion if we have more than the original 7 rows
        table.deleteRow(lastDataRowIndex);
    } else {
        alert("Cannot delete. Minimum 7 rows required.");
    }
}

// Google Drive Integration Functions
function openUploadDrive() {
    // Replace 'YOUR_DRIVE_FOLDER_ID' with your actual Google Drive folder ID
    // To get the folder ID: Right-click your Google Drive folder > Share > Copy link
    // The folder ID is the string after /folders/ in the URL
    const uploadUrl = 'https://drive.google.com/drive/folders/1TGPb5K_dP2F4glOm_564wU-hi-t1x7M0';
    
    // Open Google Drive upload folder in new tab
    window.open(uploadUrl, '_blank', 'noopener,noreferrer');
    
    // Show instruction alert
    setTimeout(() => {
        alert('📤 Upload Instructions:\n\n1. You will be redirected to Google Drive\n2. Only authorized users can upload files\n3. Drag & drop files or click "New" > "File upload"\n4. Files will be immediately available for download');
    }, 100);
}

function openDownloadDrive() {
    // Replace 'YOUR_DRIVE_FOLDER_ID' with your actual Google Drive folder ID
    const downloadUrl = 'https://drive.google.com/drive/folders/1TGPb5K_dP2F4glOm_564wU-hi-t1x7M0';
    
    // Open Google Drive download folder in new tab
    window.open(downloadUrl, '_blank', 'noopener,noreferrer');
    
    // Show instruction alert
    setTimeout(() => {
        alert('📥 Download Instructions:\n\n1. Browse all available files in Google Drive\n2. Click on any file to preview\n3. Right-click and select "Download" to save locally\n4. Use search box to find specific files');
    }, 100);
}

function openHelpGuide() {
    alert('📚 Help Guide:\n\n📤 UPLOADING:\n• Only authorized emails can upload\n• Supported: PDF, DOC, PPT, TXT, images\n• Files appear instantly after upload\n\n📥 DOWNLOADING:\n• Open to all users\n• Preview files before downloading\n• Right-click to download\n• Use search to find files quickly\n\n🔧 ISSUES:\n• Contact admin if upload is restricted\n• Clear browser cache if files don\'t appear\n• Try different browser if problems persist');
}

function contactSupport() {
    alert('📞 Contact Support:\n\n📧 Email: support@college.edu\n📱 Phone: (555) 123-4567\n🕒 Hours: Mon-Fri 9AM-5PM\n\n🔧 For Technical Issues:\n• Google Drive access problems\n• Upload permission requests\n• File organization questions\n• Account-related queries\n\nResponse time: Within 24 hours');
}

// About Page Functions
function contactUs() {
    alert('📞 Contact Information:\n\n📧 Email: info@digitallabportal.edu\n📱 Phone: (555) 123-4567\n🏢 Office: Digital Innovation Center\n🕒 Hours: Monday - Friday, 9:00 AM - 5:00 PM\n\n💬 We\'d love to hear from you! Whether you have questions about our platform, need technical support, or want to discuss implementation at your institution, our team is here to help.\n\nResponse Time: Within 24 hours for general inquiries, within 4 hours for urgent technical support.');
}

// Inject a shared footer when one isn't present
function renderFooter() {
    if (document.querySelector('.footer')) return;

    const footer = document.createElement('footer');
    footer.className = 'footer';
    footer.innerHTML = `
        <div class="footer-content">
            <div class="footer-section">
                <h3>Quick Links</h3>
                <ul>
                    <li><a href="index.html">Home</a></li>
                    <li><a href="Log_Book1.html">Lab Book</a></li>
                    <li><a href="Studyresources.html">Resources</a></li>
                    <li><a href="About.html">About Us</a></li>
                </ul>
            </div>
            <div class="footer-section">
                <h3>Contact Us</h3>
                <ul>
                    <li>Email: info@college.edu</li>
                    <li>Phone: (555) 123-4567</li>
                    <li>Address: College Campus, City, State ZIP</li>
                </ul>
            </div>
            <div class="footer-section">
                <h3>Help & Support</h3>
                <ul>
                    <li><a href="#">FAQ</a></li>
                    <li><a href="#">Technical Support</a></li>
                    <li><a href="#">Student Guide</a></li>
                </ul>
            </div>
        </div>
        <div class="footer-bottom">
            <p>&copy; 2025 Digital Lab Portal. All rights reserved.</p>
        </div>
    `;

    document.body.appendChild(footer);
}

function learnMore() {
    alert('📚 Learn More About Our Platform:\n\n🎯 CORE FEATURES:\n• Digital lab book management\n• Secure student record keeping\n• Real-time progress tracking\n• Cloud-based file storage\n• Advanced analytics & reporting\n\n🔧 TECHNICAL SPECIFICATIONS:\n• Web-based platform (no installation required)\n• Mobile-responsive design\n• Google Drive integration\n• Role-based access control\n• SSL encryption for data security\n\n🏫 INSTITUTIONAL BENEFITS:\n• Reduced paper waste\n• Streamlined workflows\n• Improved data accuracy\n• Enhanced collaboration\n• Cost-effective solution\n\n📊 SUCCESS METRICS:\n• 95% user satisfaction rate\n• 60% reduction in administrative time\n• 40% improvement in data accuracy\n\nWant a detailed demo? Contact us to schedule a presentation!');
}

// ==================== DARK MODE FUNCTIONALITY ====================

/**
 * Initialize dark mode toggle button and functionality
 * Persists preference in localStorage
 */
function initDarkMode() {
    // Create dark mode toggle button if it doesn't exist
    if (!document.querySelector('.dark-mode-toggle')) {
        const toggleBtn = document.createElement('button');
        toggleBtn.className = 'dark-mode-toggle';
        toggleBtn.setAttribute('aria-label', 'Toggle dark mode');
        toggleBtn.setAttribute('title', 'Toggle dark/light mode');
        toggleBtn.innerHTML = `
            <span class="moon-icon">🌙</span>
            <span class="sun-icon">☀️</span>
        `;
        document.body.appendChild(toggleBtn);
        
        // Add click listener
        toggleBtn.addEventListener('click', toggleDarkMode);
    }
    
    // Check for saved preference
    const savedMode = localStorage.getItem('darkMode');
    if (savedMode === 'enabled') {
        document.body.classList.add('dark-mode');
    } else if (savedMode === null) {
        // Check system preference if no saved preference
        if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
            document.body.classList.add('dark-mode');
            localStorage.setItem('darkMode', 'enabled');
        }
    }
    
    // Listen for system preference changes
    if (window.matchMedia) {
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
            if (localStorage.getItem('darkMode') === null) {
                if (e.matches) {
                    document.body.classList.add('dark-mode');
                } else {
                    document.body.classList.remove('dark-mode');
                }
            }
        });
    }
    
    console.log('✓ Dark mode initialized');
}

/**
 * Toggle dark mode on/off
 */
function toggleDarkMode() {
    const isDark = document.body.classList.toggle('dark-mode');
    localStorage.setItem('darkMode', isDark ? 'enabled' : 'disabled');
    
    // Announce change for accessibility
    const announcement = document.createElement('div');
    announcement.setAttribute('role', 'status');
    announcement.setAttribute('aria-live', 'polite');
    announcement.style.cssText = 'position: absolute; left: -9999px;';
    announcement.textContent = isDark ? 'Dark mode enabled' : 'Light mode enabled';
    document.body.appendChild(announcement);
    setTimeout(() => announcement.remove(), 1000);
}

/**
 * Inject Admin Panel link into navbar for authorized users
 * Shows for: super-admin, principal, faculty
 */
function injectAdminPanelLink() {
    try {
        const userStr = localStorage.getItem('user');
        if (!userStr) return;
        
        const user = JSON.parse(userStr);
        const authorizedRoles = ['super-admin', 'principal', 'hod', 'faculty'];
        
        if (!authorizedRoles.includes(user.role)) return;
        
        const navMenu = document.getElementById('nav-menu');
        if (!navMenu) return;
        
        // Hide logbook link for principals only (they manage, not teach)
        // HOD keeps logbook access since they sometimes teach
        if (user.role === 'principal') {
            const logbookLink = navMenu.querySelector('a[href="Log_Book1.html"]');
            if (logbookLink && logbookLink.parentElement) {
                logbookLink.parentElement.style.display = 'none';
            }
        }
        
        // Check if admin link already exists
        if (navMenu.querySelector('a[href="admin-dashboard.html"]')) return;
        
        // Create admin panel link
        const adminLi = document.createElement('li');
        const adminLink = document.createElement('a');
        adminLink.href = 'admin-dashboard.html';
        adminLink.innerHTML = '<i class="fas fa-shield-halved" style="margin-right: 5px;"></i>Admin';
        
        // Highlight if on admin page
        if (window.location.pathname.includes('admin-dashboard')) {
            adminLink.classList.add('active');
        }
        
        // Style based on role
        if (user.role === 'super-admin') {
            adminLink.style.color = '#ef4444';
        } else if (user.role === 'principal') {
            adminLink.style.color = '#3b82f6';
        } else if (user.role === 'hod') {
            adminLink.style.color = '#8b5cf6';
        } else if (user.role === 'faculty') {
            adminLink.style.color = '#10b981';
        }
        
        adminLi.appendChild(adminLink);
        
        // Insert before Profile link
        const profileLink = navMenu.querySelector('a[href="profile.html"]');
        if (profileLink && profileLink.parentElement) {
            navMenu.insertBefore(adminLi, profileLink.parentElement);
        } else {
            navMenu.appendChild(adminLi);
        }
        
        console.log('✓ Admin panel link injected for', user.role);
    } catch (e) {
        console.error('Error injecting admin link:', e);
    }
}

// Apply navbar preferences for principals and super-admins
async function applyNavbarPreferences() {
    try {
        const user = AuthManager.getUser();
        if (!user) return;
        
        // Only apply for principals and super-admins
        if (!['principal', 'super-admin'].includes(user.role)) return;
        
        const navMenu = document.getElementById('nav-menu');
        if (!navMenu) return;
        
        // Try to get preferences from localStorage first for immediate effect
        let prefs = null;
        const cachedPrefs = localStorage.getItem('navbarPreferences');
        if (cachedPrefs) {
            try {
                prefs = JSON.parse(cachedPrefs);
            } catch (e) {
                console.error('Failed to parse cached navbar prefs:', e);
            }
        }
        
        // If no cached prefs, fetch from server (but don't wait too long)
        if (!prefs) {
            const token = localStorage.getItem('token');
            if (!token) return;
            
            const host = window.location.hostname;
            const isLocal = ['localhost', '127.0.0.1', '10.154.126.1'].includes(host) || host.startsWith('192.168.');
            const apiUrl = isLocal 
                ? `http://${host === 'localhost' ? 'localhost' : host}:3002/api/auth`
                : 'https://logi-auth-service-avbs.onrender.com/api/auth';
            
            try {
                const response = await fetch(`${apiUrl}/navbar-preferences`, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                const data = await response.json();
                if (data.success && data.navbarPreferences) {
                    prefs = data.navbarPreferences;
                    localStorage.setItem('navbarPreferences', JSON.stringify(prefs));
                }
            } catch (e) {
                console.log('Could not fetch navbar prefs, using defaults');
                return;
            }
        }
        
        if (!prefs) return;
        
        // Map of preference keys to link hrefs
        const navLinks = {
            home: 'index.html',
            logbook: 'Log_Book1.html',
            resources: 'Studyresources.html',
            about: 'About.html',
            profile: 'profile.html',
            admin: 'admin-dashboard.html'
        };
        
        // Apply visibility to each nav item
        Object.entries(navLinks).forEach(([key, href]) => {
            if (prefs[key] === false) {
                const link = navMenu.querySelector(`a[href="${href}"]`);
                if (link && link.parentElement) {
                    link.parentElement.style.display = 'none';
                }
            }
        });
        
        console.log('✓ Navbar preferences applied');
    } catch (e) {
        console.error('Error applying navbar preferences:', e);
    }
}

// Initialize all functionality when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize hamburger menu on all pages
    initHamburgerMenu();
    
    // Initialize dark mode
    initDarkMode();
    
    // Inject admin panel link for authorized users
    injectAdminPanelLink();
    
    // Apply navbar preferences for principals/super-admins
    applyNavbarPreferences();
    
    // Render footer on all pages
    renderFooter();
    
    // Add any other page-specific initializations here
    console.log('Digital Lab Portal scripts loaded successfully');
    
    // Show setup reminder for Google Drive integration
    if (window.location.pathname.includes('Studyresources.html')) {
        console.log('📋 Admin Setup Reminder: Update Google Drive folder IDs in scripts.js');
    }
});