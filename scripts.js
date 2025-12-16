// Hamburger Menu Functionality
function initHamburgerMenu() {
    const hamburger = document.getElementById('hamburger');
    const navMenu = document.getElementById('nav-menu');

    if (hamburger && navMenu) {
        hamburger.addEventListener('click', () => {
            hamburger.classList.toggle('active');
            navMenu.classList.toggle('active');
        });

        // Close menu when clicking on a link
        document.querySelectorAll('.nav-menu a').forEach(link => {
            link.addEventListener('click', () => {
                hamburger.classList.remove('active');
                navMenu.classList.remove('active');
            });
        });
    }
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

function learnMore() {
    alert('📚 Learn More About Our Platform:\n\n🎯 CORE FEATURES:\n• Digital lab book management\n• Secure student record keeping\n• Real-time progress tracking\n• Cloud-based file storage\n• Advanced analytics & reporting\n\n🔧 TECHNICAL SPECIFICATIONS:\n• Web-based platform (no installation required)\n• Mobile-responsive design\n• Google Drive integration\n• Role-based access control\n• SSL encryption for data security\n\n🏫 INSTITUTIONAL BENEFITS:\n• Reduced paper waste\n• Streamlined workflows\n• Improved data accuracy\n• Enhanced collaboration\n• Cost-effective solution\n\n📊 SUCCESS METRICS:\n• 95% user satisfaction rate\n• 60% reduction in administrative time\n• 40% improvement in data accuracy\n\nWant a detailed demo? Contact us to schedule a presentation!');
}

// Initialize all functionality when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize hamburger menu on all pages
    initHamburgerMenu();
    
    // Add any other page-specific initializations here
    console.log('Digital Lab Portal scripts loaded successfully');
    
    // Show setup reminder for Google Drive integration
    if (window.location.pathname.includes('Studyresources.html')) {
        console.log('📋 Admin Setup Reminder: Update Google Drive folder IDs in scripts.js');
    }
});