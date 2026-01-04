// Log Book Client-Side Database Manager
const API_URL = window.REACT_APP_LOGBOOK_API || 'http://localhost:3005/api/logbook';
let currentUser = null;
let currentStudentLogbookId = null;

// Helper to check if error handler is available
function handleFetchError(error, context) {
    console.error(`[${context}] Error:`, error);
    
    if (typeof showErrorNotification === 'function') {
        const friendlyMessage = typeof getErrorMessage === 'function' 
            ? getErrorMessage(error) 
            : 'Something went wrong. Please try again.';
        showErrorNotification(friendlyMessage, 'error');
    } else {
        showNotification('❌ Error: ' + error.message, 'error');
    }
}

// Helper function to get auth headers
function getAuthHeaders() {
    const token = localStorage.getItem('token');
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
    };
}

// Set form permissions based on role
function setFormPermissions(role) {
    const form = document.getElementById('logbookForm');
    if (!form) return;

    const permissionIndicator = document.getElementById('permissionIndicator');
    
    if (role === 'student') {
        // Disable all inputs except dates and verification checkboxes
        const allInputs = form.querySelectorAll('input, textarea, select');
        allInputs.forEach(input => {
            if (!input.name.startsWith('date') && !input.name.startsWith('student')) {
                input.disabled = true;
            }
        });

        // Show student mode indicator
        if (permissionIndicator) {
            permissionIndicator.style.display = 'block';
            permissionIndicator.style.backgroundColor = '#e3f2fd';
            permissionIndicator.style.color = '#1565c0';
            permissionIndicator.innerHTML = '🔒 <strong>Student Mode:</strong> You can only verify entries and update dates. All other fields are read-only.';
        }
    } else if (role === 'faculty' || role === 'admin') {
        // Enable all fields but make synced fields readOnly
        const allInputs = form.querySelectorAll('input, textarea, select');
        allInputs.forEach(input => {
            input.disabled = false;
            // Make experiment names and CO fields readOnly (synced from master)
            if (input.name.includes('experimentName') || input.name.includes('exp_co')) {
                input.readOnly = true;
                input.style.backgroundColor = '#f5f5f5';
            }
        });

        // Disable student verification checkboxes (teacher can only see, not change them)
        const studentCheckboxes = form.querySelectorAll('input[name^="student"], input[name^="t2student"], input[name^="t3student"]');
        studentCheckboxes.forEach(checkbox => {
            checkbox.disabled = true;
            checkbox.style.cursor = 'not-allowed';
        });

        // Show teacher mode indicator
        if (permissionIndicator) {
            permissionIndicator.style.display = 'block';
            permissionIndicator.style.backgroundColor = '#f3e5f5';
            permissionIndicator.style.color = '#6a1b9a';
            permissionIndicator.innerHTML = '✏️ <strong>Teacher Mode:</strong> You can edit marks and rubrics. Experiment names and COs are synced from master template.';
        }
    }
}

// Update verification (students only)
async function updateVerification(type, index, date) {
    if (!currentStudentLogbookId) return;

    // Map to actual checkbox names in the form
    let selector = '';
    if (type === 'experiment') selector = `input[name="student${index + 1}"]`;
    else if (type === 'project') selector = 'input[name="t2student1"]';
    else if (type === 'exam') selector = `input[name="t3student${index + 1}"]`;

    const verified = document.querySelector(selector)?.checked;

    try {
        const response = await fetch(`${API_URL}/student/${currentStudentLogbookId}/verify`, {
            method: 'PUT',
            headers: getAuthHeaders(),
            body: JSON.stringify({ type, index, date, verified })
        });

        const data = await response.json();
        if (data.success) {
            console.log('Verification updated');
        }
    } catch (error) {
        console.error('Error updating verification:', error);
        handleFetchError(error, 'Update Verification');
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    console.log('Page loaded, setting up form handler');
    const form = document.getElementById('logbookForm');
    console.log('Form element:', form);
    
    if (form) {
        // Fetch and populate user profile data
        fetchUserProfile();
        
        // Prevent default form submission
        form.addEventListener('submit', function(e) {
            console.log('Form submit event fired!');
            e.preventDefault();
            handleLogBookSubmit();
        });
        
        // Also handle the submit button click
        const submitBtn = form.querySelector('input[type="submit"]');
        console.log('Submit button:', submitBtn);
        if (submitBtn) {
            submitBtn.addEventListener('click', function(e) {
                console.log('Submit button clicked!');
                e.preventDefault();
                handleLogBookSubmit();
            });
        }
        
        // Attach calculation event listeners to all rubric fields
        attachRubricCalculationListeners();
        
        console.log('Form handler setup complete');
    } else {
        console.error('Form not found!');
    }
});

// Fetch user profile and populate fields
async function fetchUserProfile() {
    try {
        const token = localStorage.getItem('token');
        if (!token) {
            console.error('No token found, user not authenticated');
            return;
        }
        
        const response = await fetch(`${window.REACT_APP_AUTH_API || 'http://localhost:3002/api/auth'}/profile`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        
        const result = await response.json();
        
        if (result.success && result.user) {
            const user = result.user;
            currentUser = user;
            
            // Populate the readonly fields
            const nameField = document.getElementById('name');
            const rollnoField = document.getElementById('detail1');
            const rgnoField = document.getElementById('detail');
            
            if (nameField) nameField.value = user.name || '';
            if (rollnoField) rollnoField.value = user.rollno || '';
            if (rgnoField) rgnoField.value = user.rgno || '';
            
            // Set form permissions based on role
            setFormPermissions(user.role);
            
            console.log('User profile loaded:', user);
            
            // Show/hide buttons based on role
            const teacherActions = document.getElementById('teacherActions');
            const studentActions = document.getElementById('studentActions');
            const studentFormContainer = document.getElementById('studentFormContainer');
            const logbookSelectionPanel = document.getElementById('logbookSelectionPanel');
            
            if (user.role === 'faculty' || user.role === 'admin') {
                // Faculty and admins can see all logbooks (viewer buttons only)
                if (teacherActions) teacherActions.style.display = 'block';
                if (studentActions) studentActions.style.display = 'none';
                if (studentFormContainer) studentFormContainer.style.display = 'none';
                if (logbookSelectionPanel) logbookSelectionPanel.style.display = 'none';
            } else {
                // Students can see their logbooks list but NOT create logbooks
                if (teacherActions) teacherActions.style.display = 'none';
                if (studentActions) studentActions.style.display = 'block';
                if (studentFormContainer) studentFormContainer.style.display = 'block';
                if (logbookSelectionPanel) logbookSelectionPanel.style.display = 'block';
                
                // Hide "Create New Log Book" buttons for students
                const createButtons = document.querySelectorAll('button[onclick="createNewLogBook()"]');
                createButtons.forEach(button => {
                    button.style.display = 'none';
                });
                
                // Load student's logbooks
                loadMyLogBooks();
            }
        } else {
            console.error('Failed to fetch user profile:', result.error);
        }
    } catch (error) {
        console.error('Error fetching user profile:', error);
        handleFetchError(error, 'Fetch User Profile');
    }
}

// Load all logbooks for student and show selection panel
async function loadMyLogBooks() {
    try {
        const response = await fetch(`${API_URL}/student/my-logbooks`, {
            method: 'GET',
            headers: getAuthHeaders()
        });
        
        const result = await response.json();
        
        if (result.success) {
            const logbookList = document.getElementById('logbookList');
            const selectionPanel = document.getElementById('logbookSelectionPanel');
            
            if (logbookList) {
                logbookList.innerHTML = '';
                
                if (result.data && result.data.length > 0) {
                    result.data.forEach(logbook => {
                        const card = document.createElement('div');
                        card.style.cssText = 'padding: 15px; background: white; border-radius: 8px; border-left: 4px solid #667eea; cursor: pointer; transition: all 0.3s ease; box-shadow: 0 2px 4px rgba(0,0,0,0.1);';
                        card.innerHTML = `
                            <h4 style="margin: 0 0 10px 0; color: #667eea;">${logbook.subject}</h4>
                            ${logbook.code ? `<p style="margin: 5px 0; font-size: 13px;"><strong>Code:</strong> ${logbook.code}</p>` : ''}
                            <p style="margin: 5px 0; font-size: 13px;"><strong>Created:</strong> ${new Date(logbook.createdAt).toLocaleDateString()}</p>
                            <button style="width: 100%; padding: 8px; margin-top: 10px; background: #667eea; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 600;">Load</button>
                        `;
                        card.onclick = () => loadLogBookById(logbook._id);
                        logbookList.appendChild(card);
                    });
                } else {
                    logbookList.innerHTML = '<p style="grid-column: 1/-1; text-align: center; color: #999;">No logbooks yet. Create your first one!</p>';
                }
            }
            
            if (selectionPanel) {
                selectionPanel.style.display = 'block';
            }
        } else {
            showNotification('❌ Error loading logbooks: ' + result.error, 'error');
        }
    } catch (error) {
        console.error('Error loading logbooks:', error);
        handleFetchError(error, 'Load Logbooks');
    }
}

// Load specific logbook by ID
async function loadLogBookById(logbookId) {
    try {
        console.log('Loading logbook by ID:', logbookId);
        const response = await fetch(`${API_URL}/student/${logbookId}`, {
            method: 'GET',
            headers: getAuthHeaders()
        });
        
        console.log('Response status:', response.status);
        const result = await response.json();
        console.log('API Response:', result);
        
        if (result.success && result.data) {
            console.log('Data found, loading into form');
            currentStudentLogbookId = logbookId;
            const studentFormContainer = document.getElementById('studentFormContainer');
            if (studentFormContainer) studentFormContainer.style.display = 'block';
            loadDataIntoForm(result.data);
            showNotification('✅ Log book loaded successfully!', 'success');
            
            // Hide selection panel and show form
            const selectionPanel = document.getElementById('logbookSelectionPanel');
            if (selectionPanel) selectionPanel.style.display = 'none';
            
            // Scroll to form
            setTimeout(() => {
                const form = document.getElementById('logbookForm');
                if (form) form.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }, 100);
        } else if (result.data && !result.success) {
            // API returns data even if success is false, try using the data
            console.log('Success is false but data exists, loading anyway');
            currentStudentLogbookId = logbookId;
            const studentFormContainer = document.getElementById('studentFormContainer');
            if (studentFormContainer) studentFormContainer.style.display = 'block';
            loadDataIntoForm(result.data);
            showNotification('✅ Log book loaded!', 'success');
            
            const selectionPanel = document.getElementById('logbookSelectionPanel');
            if (selectionPanel) selectionPanel.style.display = 'none';
            
            setTimeout(() => {
                const form = document.getElementById('logbookForm');
                if (form) form.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }, 100);
        } else {
            console.error('No data returned:', result);
            showNotification('❌ Error: ' + (result.error || 'No data returned'), 'error');
        }
    } catch (error) {
        console.error('Error loading logbook:', error);
        handleFetchError(error, 'Load Logbook');
    }
}

// Create new logbook for student
function createNewLogBook() {
    // Check if user is faculty or admin
    if (!currentUser || (currentUser.role !== 'faculty' && currentUser.role !== 'admin')) {
        showNotification('❌ Only faculty can create logbooks. Contact your faculty to request a logbook.', 'error');
        return;
    }
    
    // Clear the form
    document.getElementById('logbookForm').reset();
    
    // Clear selection panel and show form
    const selectionPanel = document.getElementById('logbookSelectionPanel');
    if (selectionPanel) selectionPanel.style.display = 'none';
    
    // Fetch and populate user profile data for new entry
    fetchUserProfile();
    
    showNotification('📝 Create new log book - Enter subject details', 'info');
    
    // Scroll to form
    document.getElementById('logbookForm').scrollIntoView({ behavior: 'smooth' });
}

// Attach change event listeners to rubric fields for auto-calculation
function attachRubricCalculationListeners() {
    // Experiments table (1-7, expandable)
    for (let row = 1; row <= 20; row++) { // Allow up to 20 rows for expansion
        for (let rubric = 1; rubric <= 5; rubric++) {
            const field = document.querySelector(`[name="rubric${row}-${rubric}"]`);
            if (field) {
                field.addEventListener('change', () => calculateRubricTotal('', row));
                field.addEventListener('input', () => calculateRubricTotal('', row));
            }
        }
    }
    
    // Open-ended project table (t2)
    for (let rubric = 1; rubric <= 5; rubric++) {
        const field = document.querySelector(`[name="t2rubric1-${rubric}"]`);
        if (field) {
            field.addEventListener('change', () => calculateRubricTotal('t2', 1));
            field.addEventListener('input', () => calculateRubricTotal('t2', 1));
        }
    }
    
    // Lab exams table (t3, 1-3)
    for (let row = 1; row <= 5; row++) { // Allow up to 5 rows
        for (let rubric = 1; rubric <= 5; rubric++) {
            const field = document.querySelector(`[name="t3rubric${row}-${rubric}"]`);
            if (field) {
                field.addEventListener('change', () => calculateRubricTotal('t3', row));
                field.addEventListener('input', () => calculateRubricTotal('t3', row));
            }
        }
    }
    
    // Final Assessment fields - add listeners to calculate total
    const finalFields = ['final1', 'final2', 'final3', 'final4'];
    finalFields.forEach(fieldName => {
        const field = document.querySelector(`[name="${fieldName}"]`);
        if (field) {
            field.addEventListener('change', calculateFinalAssessmentTotal);
            field.addEventListener('input', calculateFinalAssessmentTotal);
        }
    });
}

// Validate row completeness - if any field in a row has data, all required fields must be filled
function validateRowCompleteness() {
    // Only validate experiment rows that actually exist (have data)
    const form = document.getElementById('logbookForm');
    if (!form) return true;

    // Check actual experiment rows (only those that have been populated)
    const experimentInputs = form.querySelectorAll('input[name^="date"]');
    const maxRow = experimentInputs.length;
    
    for (let rowNum = 1; rowNum <= maxRow; rowNum++) {
        const dateField = document.querySelector(`[name="date${rowNum}"]`);
        const expField = document.querySelector(`[name="experiment${rowNum}"]`);
        const coField = document.querySelector(`[name="co${rowNum}"]`);
        const rubric1 = document.querySelector(`[name="rubric${rowNum}-1"]`);
        const rubric2 = document.querySelector(`[name="rubric${rowNum}-2"]`);
        const rubric3 = document.querySelector(`[name="rubric${rowNum}-3"]`);
        const rubric4 = document.querySelector(`[name="rubric${rowNum}-4"]`);
        const rubric5 = document.querySelector(`[name="rubric${rowNum}-5"]`);
        
        // Check if row has any data
        const hasData = (dateField?.value || expField?.value || coField?.value || 
                        rubric1?.value || rubric2?.value || rubric3?.value || 
                        rubric4?.value || rubric5?.value);
        
        if (hasData) {
            // If row has data, validate required fields
            const emptyFields = [];
            if (!dateField?.value) emptyFields.push(`date${rowNum}`);
            if (!expField?.value) emptyFields.push(`experiment${rowNum}`);
            if (!coField?.value) emptyFields.push(`co${rowNum}`);
            
            // Check if all rubrics are filled
            if (!rubric1?.value) emptyFields.push(`rubric${rowNum}-1`);
            if (!rubric2?.value) emptyFields.push(`rubric${rowNum}-2`);
            if (!rubric3?.value) emptyFields.push(`rubric${rowNum}-3`);
            if (!rubric4?.value) emptyFields.push(`rubric${rowNum}-4`);
            if (!rubric5?.value) emptyFields.push(`rubric${rowNum}-5`);
            
            if (emptyFields.length > 0) {
                showNotification(`❌ Experiment ${rowNum} is incomplete. Missing: ${emptyFields.join(', ')}`, 'error');
                return false;
            }
        }
    }
    
    return true;
}

// Calculate rubric total for a row and update the total field
function calculateRubricTotal(prefix, rowNum) {
    let rubricSum = 0;
    
    // Get all 5 rubric fields for this row
    for (let i = 1; i <= 5; i++) {
        if (prefix === '') {
            // Experiments: rubric1-1, rubric1-2, etc.
            const field = document.querySelector(`[name="rubric${rowNum}-${i}"]`);
            if (field && field.value) {
                rubricSum += parseFloat(field.value) || 0;
            }
        } else if (prefix === 't2') {
            // Open-ended: t2rubric1-1, t2rubric1-2, etc.
            const field = document.querySelector(`[name="t2rubric${rowNum}-${i}"]`);
            if (field && field.value) {
                rubricSum += parseFloat(field.value) || 0;
            }
        } else if (prefix === 't3') {
            // Lab exams: t3rubric1-1, t3rubric1-2, etc.
            const field = document.querySelector(`[name="t3rubric${rowNum}-${i}"]`);
            if (field && field.value) {
                rubricSum += parseFloat(field.value) || 0;
            }
        }
    }
    
    // Update total field
    let totalFieldName;
    if (prefix === '') {
        totalFieldName = `total${rowNum}`;
    } else if (prefix === 't2') {
        totalFieldName = `t2total${rowNum}`;
    } else if (prefix === 't3') {
        totalFieldName = `t3total${rowNum}`;
    }
    
    const totalField = document.querySelector(`[name="${totalFieldName}"]`);
    if (totalField) {
        totalField.value = rubricSum;
    }
}

// Calculate final assessment total (sum of attendance, lab work, open-ended project, and lab exam)
function calculateFinalAssessmentTotal() {
    // Get the four component fields
    const attendance = parseFloat(document.querySelector('[name="final1"]')?.value) || 0;
    const labWork = parseFloat(document.querySelector('[name="final2"]')?.value) || 0;
    const openEndedProject = parseFloat(document.querySelector('[name="final3"]')?.value) || 0;
    const labExam = parseFloat(document.querySelector('[name="final4"]')?.value) || 0;
    
    // Calculate total (max 75)
    const total = attendance + labWork + openEndedProject + labExam;
    
    // Update the total marks field (final5)
    const totalField = document.querySelector('[name="final5"]');
    if (totalField) {
        totalField.value = total;
    }
}

// Handle form submission
// Helper function to parse number safely
function parseNumber(value) {
    const num = parseFloat(value);
    return isNaN(num) ? 0 : num;
}

// Build logbook payload from form
function buildLogbookPayload() {
    const form = document.getElementById('logbookForm');
    const getVal = (name) => {
        const el = form.querySelector(`[name="${name}"]`);
        return el ? el.value : '';
    };
    const getNum = (name) => parseNumber(getVal(name));
    const getChecked = (name) => {
        const el = form.querySelector(`[name="${name}"]`);
        return el ? el.checked : false;
    };

    // Experiments: read rows by existing experiment inputs
    const experiments = [];
    const expFields = form.querySelectorAll('input[name^="experiment"]');
    const expCount = expFields.length;
    for (let i = 1; i <= expCount; i++) {
        const expName = getVal(`experiment${i}`);
        const date = getVal(`date${i}`);
        const co = getVal(`co${i}`);
        const hasAny = expName || date || co || getVal(`rubric${i}-1`) || getVal(`rubric${i}-2`) || getVal(`rubric${i}-3`) || getVal(`rubric${i}-4`) || getVal(`rubric${i}-5`);
        if (!hasAny) continue; // skip completely empty rows
        experiments.push({
            slNo: i,
            date: date || '',
            experimentName: expName || '',
            co: co || '',
            rubric1: getNum(`rubric${i}-1`),
            rubric2: getNum(`rubric${i}-2`),
            rubric3: getNum(`rubric${i}-3`),
            rubric4: getNum(`rubric${i}-4`),
            rubric5: getNum(`rubric${i}-5`),
            total: getNum(`total${i}`),
            studentSignature: getChecked(`student${i}`),
            facultySignature: getChecked(`faculty${i}`)
        });
    }

    // Open ended project (t2 fields)
    const openEndedProject = {
        date: getVal('t2date1') || '',
        projectName: getVal('t2experiment1') || '',
        co: getVal('t2co1') || '',
        rubric1: getNum('t2rubric1-1'),
        rubric2: getNum('t2rubric1-2'),
        rubric3: getNum('t2rubric1-3'),
        rubric4: getNum('t2rubric1-4'),
        rubric5: getNum('t2rubric1-5'),
        total: getNum('t2total1'),
        studentSignature: getChecked('t2student1'),
        facultySignature: getChecked('t2faculty1')
    };

    // Lab exams (t3 fields)
    const labExams = [];
    // Assume up to 3 rows as in the template
    for (let i = 1; i <= 3; i++) {
        const examName = getVal(`exam${i}`);
        const date = getVal(`t3date${i}`);
        const co = getVal(`t3co${i}`);
        const hasAny = examName || date || co || getVal(`t3rubric${i}-1`) || getVal(`t3rubric${i}-2`) || getVal(`t3rubric${i}-3`) || getVal(`t3rubric${i}-4`) || getVal(`t3rubric${i}-5`);
        if (!hasAny) continue;
        labExams.push({
            slNo: i,
            date: date || '',
            examName: examName || '',
            co: co || '',
            rubric1: getNum(`t3rubric${i}-1`),
            rubric2: getNum(`t3rubric${i}-2`),
            rubric3: getNum(`t3rubric${i}-3`),
            rubric4: getNum(`t3rubric${i}-4`),
            rubric5: getNum(`t3rubric${i}-5`),
            total: getNum(`t3total${i}`),
            studentSignature: getChecked(`t3student${i}`),
            facultySignature: getChecked(`t3faculty${i}`)
        });
    }

    // Final assessment fields
    const finalAssessment = {
        attendance: getNum('final1'),
        labWork: getNum('final2'),
        openEndedProject: getNum('final3'),
        labExam: getNum('final4'),
        totalMarks: getNum('final5')
    };

    return {
        experiments,
        openEndedProject,
        labExams,
        finalAssessment
    };
}

async function handleLogBookSubmit() {
    try {
        // Check if student - students cannot submit
        if (currentUser && currentUser.role === 'student') {
            showNotification('ℹ️ Students cannot submit marks. Only verification is allowed.', 'info');
            return;
        }
        
        // Validate row completeness first
        if (!validateRowCompleteness()) {
            return;
        }
        
        // Build payload
        const payload = buildLogbookPayload();
        
        console.log('===== SUBMITTING LOGBOOK =====');
        console.log(JSON.stringify(payload, null, 2));
        console.log('==============================');
        
        // Teachers submit to student logbook endpoint
        if (currentStudentLogbookId) {
            const response = await fetch(`${API_URL}/student/${currentStudentLogbookId}/marks`, {
                method: 'PUT',
                headers: getAuthHeaders(),
                body: JSON.stringify(payload)
            });
            
            const result = await response.json();
            console.log('Server response:', result);
            
            if (result.success) {
                showNotification('✅ Marks updated successfully!', 'success');
            } else {
                showNotification('❌ Error: ' + result.error, 'error');
            }
        } else {
            showNotification('❌ No logbook loaded. Please load a student logbook first.', 'error');
        }
    } catch (error) {
        console.error('Error submitting form:', error);
        handleFetchError(error, 'Submit Logbook');
    }
}

// Load log book by roll number
async function loadLogBookByRoll() {
    let rollno;
    
    // Use SweetAlert2 if available, otherwise fallback to prompt
    if (typeof Swal !== 'undefined') {
        const result = await Swal.fire({
            title: 'Load Log Book',
            html: '<i class="fas fa-user"></i> Enter Roll Number:',
            input: 'number',
            inputAttributes: {
                min: 1,
                max: 99,
                step: 1
            },
            width: '600px',
            customClass: {
                input: 'swal-wide-input'
            },
            didOpen: () => {
                const input = Swal.getInput();
                if (input) {
                    input.style.width = '400px';
                    input.style.fontSize = '18px';
                    input.style.padding = '12px';
                }
            },
            showCancelButton: true,
            confirmButtonText: '<i class="fas fa-download"></i> Load',
            cancelButtonText: '<i class="fas fa-times"></i> Cancel',
            confirmButtonColor: '#2196f3',
            inputValidator: (value) => {
                if (!value) {
                    return 'Please enter a roll number!';
                }
            }
        });
        
        if (!result.isConfirmed) return;
        rollno = result.value;
    } else {
        rollno = prompt('Enter Roll Number:');
        if (!rollno) return;
    }
    
    try {
        const response = await fetch(`${API_URL}/student/roll/${rollno}`, {
            method: 'GET',
            headers: getAuthHeaders()
        });
        const result = await response.json();
        
        console.log('API Response for roll:', result);
        
        if (result.success && result.data) {
            console.log('Data found, populating form with:', result.data.name, result.data.rollno);
            currentStudentLogbookId = result.data._id;
            // Ensure form is visible for faculty/admin when a student logbook is loaded
            const studentFormContainer = document.getElementById('studentFormContainer');
            if (studentFormContainer) studentFormContainer.style.display = 'block';
            loadDataIntoForm(result.data);
            showNotification('✅ Data loaded successfully!', 'success');
        } else {
            console.error('API returned no data:', result);
            showNotification('❌ No data found for roll number: ' + rollno, 'error');
        }
    } catch (error) {
        console.error('Fetch error:', error);
        handleFetchError(error, 'Load by Roll Number');
    }
}

// Load log book by register number
async function loadLogBookByRegister() {
    let rgno;
    
    // Use SweetAlert2 if available, otherwise fallback to prompt
    if (typeof Swal !== 'undefined') {
        const result = await Swal.fire({
            title: 'Load Log Book',
            html: '<i class="fas fa-id-card"></i> Enter Register Number:',
            input: 'number',
            inputAttributes: {
                min: 0,
                max: 3000000000,
                step: 1
            },
            width: '600px',
            customClass: {
                input: 'swal-wide-input'
            },
            didOpen: () => {
                const input = Swal.getInput();
                if (input) {
                    input.style.width = '400px';
                    input.style.fontSize = '18px';
                    input.style.padding = '12px';
                }
            },
            showCancelButton: true,
            confirmButtonText: '<i class="fas fa-download"></i> Load',
            cancelButtonText: '<i class="fas fa-times"></i> Cancel',
            confirmButtonColor: '#ff9800',
            inputValidator: (value) => {
                if (!value) {
                    return 'Please enter a register number!';
                }
            }
        });
        
        if (!result.isConfirmed) return;
        rgno = result.value;
    } else {
        rgno = prompt('Enter Register Number:');
        if (!rgno) return;
    }
    
    try {
        const response = await fetch(`${API_URL}/student/register/${rgno}`, {
            method: 'GET',
            headers: getAuthHeaders()
        });
        const result = await response.json();
        
        console.log('API Response for register:', result);
        
        if (result.success && result.data) {
            console.log('Data found, populating form with:', result.data.name, result.data.rgno);
            currentStudentLogbookId = result.data._id;
            // Ensure form is visible for faculty/admin when a student logbook is loaded
            const studentFormContainer = document.getElementById('studentFormContainer');
            if (studentFormContainer) studentFormContainer.style.display = 'block';
            loadDataIntoForm(result.data);
            showNotification('✅ Data loaded successfully!', 'success');
        } else {
            console.error('API returned no data:', result);
            showNotification('❌ No data found for register number: ' + rgno, 'error');
        }
    } catch (error) {
        console.error('Fetch error:', error);
        handleFetchError(error, 'Load by Register Number');
    }
}

// View all log books
function viewAllLogBooks() {
    window.location.href = 'logbook-viewer.html';
}

// Clear all form data
function clearAllFormData() {
    const form = document.getElementById('logbookForm');
    if (!form) return;
    
    // Clear text inputs and textareas
    const inputs = form.querySelectorAll('input[type="text"], input[type="number"], textarea');
    inputs.forEach(input => {
        input.value = '';
    });
    
    // Clear all checkboxes
    const checkboxes = form.querySelectorAll('input[type="checkbox"]');
    checkboxes.forEach(checkbox => {
        checkbox.checked = false;
    });
}

// Load data into form
function loadDataIntoForm(logBookData) {
    console.log('Loading data into form:', logBookData);
    console.log('Current user role:', currentUser?.role);
    
    // Clear all existing experiment data first
    clearAllFormData();
    
    // Student info
    const nameField = document.querySelector('[name="name"]');
    const rollField = document.querySelector('[name="rollno"]');
    const regField = document.querySelector('[name="rgno"]');
    const subjectField = document.querySelector('[name="subject"]');
    const codeField = document.querySelector('[name="code"]');
    
    if (nameField) nameField.value = logBookData.name || '';
    if (rollField) rollField.value = logBookData.rollno || '';
    if (regField) regField.value = logBookData.rgno || '';
    if (subjectField) subjectField.value = logBookData.subject || '';
    if (codeField) codeField.value = logBookData.code || '';
    
    // Load experiments
    if (logBookData.experiments && logBookData.experiments.length > 0) {
        // First, ensure we have enough rows in the form
        const table = document.getElementById('t1');
        if (table) {
            // Count existing data rows (excluding header rows and button row)
            const existingRows = table.querySelectorAll('input[name^="date"]').length;
            const neededRows = logBookData.experiments.length;
            
            console.log(`Table found. Need ${neededRows} experiment rows, currently have ${existingRows}`);
            
            // Remove extra rows if we have too many
            if (existingRows > neededRows) {
                console.log(`Removing ${existingRows - neededRows} extra rows...`);
                // Remove only rows that contain date inputs beyond needed count
                const dateInputs = Array.from(table.querySelectorAll('input[name^="date"]'));
                for (let i = neededRows; i < dateInputs.length; i++) {
                    const row = dateInputs[i].closest('tr');
                    if (row) row.remove();
                }
            }
            // Add rows if we need more
            else if (neededRows > existingRows) {
                const rowsToAdd = neededRows - existingRows;
                console.log(`Adding ${rowsToAdd} more rows...`);
                
                for (let i = 0; i < rowsToAdd; i++) {
                    // Simulate clicking the "Add Row" button
                    const addBtn = document.getElementById('addrow');
                    if (addBtn) {
                        const fakeEvent = { preventDefault: () => {} };
                        addRow(fakeEvent);
                    }
                }
            }
        } else {
            console.error('Table t1 not found in DOM!');
        }
        
        // Populate all experiments (with a small delay if rows were added)
        const delay = logBookData.experiments.length > 7 ? 200 : 0;
        setTimeout(() => {
            populateExperiments(logBookData.experiments);
            // After experiments, load other sections
            setTimeout(() => {
                loadOpenEndedProject(logBookData.openEndedProject);
                loadLabExams(logBookData.labExams);
                loadFinalAssessment(logBookData.finalAssessment);
                // Apply permissions after data is loaded
                if (currentUser) {
                    setFormPermissions(currentUser.role);
                }
                // Add verification listeners for students
                if (currentUser && currentUser.role === 'student') {
                    attachVerificationListeners();
                }
                // Scroll to show the form
                console.log('Scrolling to form...');
                const form = document.getElementById('logbookForm');
                const table = document.getElementById('t1');
                if (form) {
                    form.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    console.log('Scrolled to form');
                } else if (table) {
                    table.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    console.log('Scrolled to table');
                }
            }, 50);
        }, delay);
    } else {
        // No experiments, load other sections directly
        loadOpenEndedProject(logBookData.openEndedProject);
        loadLabExams(logBookData.labExams);
        loadFinalAssessment(logBookData.finalAssessment);
        // Apply permissions after data is loaded
        if (currentUser) {
            setFormPermissions(currentUser.role);
        }
        // Add verification listeners for students
        if (currentUser && currentUser.role === 'student') {
            attachVerificationListeners();
        }
        // Scroll to show the form
        console.log('Scrolling to form (no experiments)...');
        const form = document.getElementById('logbookForm');
        if (form) {
            form.scrollIntoView({ behavior: 'smooth', block: 'start' });
            console.log('Scrolled to form');
        }
    }
}

// Attach verification listeners for student checkboxes
function attachVerificationListeners() {
    const form = document.getElementById('logbookForm');
    if (!form) return;
    
    // Experiments verification checkboxes: names student1, student2, ...
    const expCheckboxes = form.querySelectorAll('input[name^="student"][type="checkbox"]');
    expCheckboxes.forEach((checkbox, idx) => {
        checkbox.addEventListener('change', () => {
            const num = idx + 1;
            const dateField = form.querySelector(`input[name="date${num}"]`);
            const date = dateField ? dateField.value : new Date().toISOString().split('T')[0];
            updateVerification('experiment', idx, date);
        });
    });
    
    // Project verification checkbox: t2student1
    const projectCheckbox = form.querySelector('input[name="t2student1"]');
    if (projectCheckbox) {
        projectCheckbox.addEventListener('change', () => {
            const dateField = form.querySelector('input[name="t2date1"]');
            const date = dateField ? dateField.value : new Date().toISOString().split('T')[0];
            updateVerification('project', 0, date);
        });
    }
    
    // Exam verification checkboxes: t3student1, t3student2, t3student3
    const examCheckboxes = form.querySelectorAll('input[name^="t3student"]');
    examCheckboxes.forEach((checkbox, idx) => {
        checkbox.addEventListener('change', () => {
            const num = idx + 1;
            const dateField = form.querySelector(`input[name="t3date${num}"]`);
            const date = dateField ? dateField.value : new Date().toISOString().split('T')[0];
            updateVerification('exam', idx, date);
        });
    });
}

function populateExperiments(experiments) {
    console.log('Populating experiments:', experiments);
    console.log('Total experiments to populate:', experiments.length);
    
    if (!experiments || experiments.length === 0) {
        console.log('No experiments to populate');
        return;
    }
    
    experiments.forEach((exp, index) => {
        const num = exp.slNo || (index + 1);
        console.log(`\n=== Loading Experiment ${num} ===`);
        console.log('Exp data:', exp);
        
        // Find fields by name pattern - matching actual form field names
        const dateField = document.querySelector(`[name="date${num}"]`);
        const expField = document.querySelector(`[name="experiment${num}"]`);
        const coField = document.querySelector(`[name="co${num}"]`);
        const r1Field = document.querySelector(`[name="rubric${num}-1"]`);
        const r2Field = document.querySelector(`[name="rubric${num}-2"]`);
        const r3Field = document.querySelector(`[name="rubric${num}-3"]`);
        const r4Field = document.querySelector(`[name="rubric${num}-4"]`);
        const r5Field = document.querySelector(`[name="rubric${num}-5"]`);
        const totalField = document.querySelector(`[name="total${num}"]`);
        const studentField = document.querySelector(`[name="student${num}"]`);
        const facultyField = document.querySelector(`[name="faculty${num}"]`);
        
        console.log('Field search results:', {
            dateField: !!dateField,
            expField: !!expField,
            coField: !!coField,
            r1Field: !!r1Field,
            totalField: !!totalField,
            studentField: !!studentField,
            facultyField: !!facultyField
        });
        
        if (dateField) { 
            dateField.value = exp.date || ''; 
            console.log(`Set date${num} to: "${dateField.value}"`);
            dateField.dispatchEvent(new Event('input', { bubbles: true })); 
        }
        if (expField) { 
            expField.value = exp.experimentName || ''; 
            console.log(`Set experiment${num} to: "${expField.value}"`);
            expField.dispatchEvent(new Event('input', { bubbles: true })); 
        }
        if (coField) {
            // Keep original CO text (e.g., "CO1") instead of forcing numeric
            const coValue = exp.co ?? '';
            coField.value = coValue;
            console.log(`Set co${num} to: "${coField.value}"`);
            coField.dispatchEvent(new Event('input', { bubbles: true }));
        }
        if (r1Field) { r1Field.value = (exp.rubric1 ?? 0); console.log(`Set rubric${num}-1 to: "${r1Field.value}"`); r1Field.dispatchEvent(new Event('input', { bubbles: true })); }
        if (r2Field) { r2Field.value = (exp.rubric2 ?? 0); console.log(`Set rubric${num}-2 to: "${r2Field.value}"`); r2Field.dispatchEvent(new Event('input', { bubbles: true })); }
        if (r3Field) { r3Field.value = (exp.rubric3 ?? 0); console.log(`Set rubric${num}-3 to: "${r3Field.value}"`); r3Field.dispatchEvent(new Event('input', { bubbles: true })); }
        if (r4Field) { r4Field.value = (exp.rubric4 ?? 0); console.log(`Set rubric${num}-4 to: "${r4Field.value}"`); r4Field.dispatchEvent(new Event('input', { bubbles: true })); }
        if (r5Field) { r5Field.value = (exp.rubric5 ?? 0); console.log(`Set rubric${num}-5 to: "${r5Field.value}"`); r5Field.dispatchEvent(new Event('input', { bubbles: true })); }
        if (totalField) { totalField.value = exp.total ?? ''; totalField.dispatchEvent(new Event('input', { bubbles: true })); }
        if (studentField) { studentField.checked = !!exp.studentSignature; studentField.dispatchEvent(new Event('change', { bubbles: true })); }
        if (facultyField) { facultyField.checked = !!exp.facultySignature; facultyField.dispatchEvent(new Event('change', { bubbles: true })); }
    });
}

function loadOpenEndedProject(proj) {
    if (!proj) return;
    
    const projDateField = document.querySelector('[name="t2date1"]');
    const projNameField = document.querySelector('[name="t2experiment1"]');
    const projCoField = document.querySelector('[name="t2co1"]');
    
    if (projDateField) projDateField.value = proj.date || '';
    if (projNameField) projNameField.value = proj.projectName || '';
    if (projCoField) projCoField.value = proj.co || '';
    
    for (let i = 1; i <= 5; i++) {
        const rubricField = document.querySelector(`[name="t2rubric1-${i}"]`);
        if (rubricField) rubricField.value = proj[`rubric${i}`] || '';
    }
    
    const projTotalField = document.querySelector('[name="t2total1"]');
    const projStudentField = document.querySelector('[name="t2student1"]');
    const projFacultyField = document.querySelector('[name="t2faculty1"]');
    
    if (projTotalField) projTotalField.value = proj.total || '';
    if (projStudentField) projStudentField.checked = proj.studentSignature || false;
    if (projFacultyField) projFacultyField.checked = proj.facultySignature || false;
}

function loadLabExams(labExams) {
    if (!labExams || !labExams.length) return;
    
    labExams.forEach((exam, index) => {
        const num = exam.slNo || (index + 1);
        const examDateField = document.querySelector(`[name="t3date${num}"]`);
        const examNameField = document.querySelector(`[name="exam${num}"]`);
        const examCoField = document.querySelector(`[name="t3co${num}"]`);
        
        if (examDateField) examDateField.value = exam.date || '';
        if (examNameField) examNameField.value = exam.examName || '';
        if (examCoField) examCoField.value = exam.co || '';
        
        for (let i = 1; i <= 5; i++) {
            const rubricField = document.querySelector(`[name="t3rubric${num}-${i}"]`);
            if (rubricField) rubricField.value = exam[`rubric${i}`] || '';
        }
        
        const examTotalField = document.querySelector(`[name="t3total${num}"]`);
        const examStudentField = document.querySelector(`[name="t3student${num}"]`);
        const examFacultyField = document.querySelector(`[name="t3faculty${num}"]`);
        
        if (examTotalField) examTotalField.value = exam.total || '';
        if (examStudentField) examStudentField.checked = exam.studentSignature || false;
        if (examFacultyField) examFacultyField.checked = exam.facultySignature || false;
    });
}

function loadFinalAssessment(finalAssessment) {
    if (!finalAssessment) return;
    
    const finalFields = ['final1', 'final2', 'final3', 'final4', 'final5'];
    const finalValues = ['attendance', 'labWork', 'openEndedProject', 'labExam', 'totalMarks'];
    
    finalValues.forEach((key, index) => {
        const field = document.querySelector(`[name="${finalFields[index]}"]`);
        if (field) field.value = finalAssessment[key] || '';
    });
}


// Show notification with SweetAlert2 (if available) or fallback to custom notification
function showNotification(message, type = 'info') {
    // Check if SweetAlert2 is available
    if (typeof Swal !== 'undefined') {
        const icon = type === 'success' ? 'success' : type === 'error' ? 'error' : 'info';
        const title = type === 'success' ? 'Success!' : type === 'error' ? 'Error!' : 'Info';
        
        Swal.fire({
            title: title,
            text: message.replace(/[❌✅]/g, ''),
            icon: icon,
            toast: true,
            position: 'top-end',
            showConfirmButton: false,
            timer: 3000,
            timerProgressBar: true,
            didOpen: (toast) => {
                toast.addEventListener('mouseenter', Swal.stopTimer);
                toast.addEventListener('mouseleave', Swal.resumeTimer);
            }
        });
    } else {
        // Fallback to original notification
        const existing = document.querySelector('.db-notification');
        if (existing) existing.remove();
        
        const notification = document.createElement('div');
        notification.className = `db-notification ${type}`;
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 25px;
            background: ${type === 'success' ? '#4CAF50' : type === 'error' ? '#f44336' : '#2196F3'};
            color: white;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            z-index: 10000;
            font-weight: 600;
            animation: slideIn 0.3s ease-out;
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease-in';
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }
}

// Add CSS animation
if (!document.getElementById('notificationStyles')) {
    const style = document.createElement('style');
    style.id = 'notificationStyles';
    style.textContent = `
        @keyframes slideIn {
            from { transform: translateX(400px); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOut {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(400px); opacity: 0; }
        }
    `;
    document.head.appendChild(style);
}
