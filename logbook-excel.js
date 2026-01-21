/**
 * Logbook Excel Export/Import with Integrity Protection
 * 
 * This module provides functionality to:
 * 1. Export logbook tables to Excel (.xlsx) with SHA-256 hash for integrity
 * 2. Import Excel files and verify data integrity before loading
 * 
 * Security: Uses SHA-256 hash stored in a hidden sheet to detect tampering.
 * The hash is calculated from all table data and verified on import.
 * 
 * Dependencies: SheetJS (xlsx) library - loaded via CDN
 */

// ============================================
// CONFIGURATION
// ============================================

const LogbookExcel = {
    // Table IDs and their corresponding sheet names
    TABLES: {
        'studentInfo': { selector: '.ftab', name: 'Student Info' },
        'labWork': { selector: '#t1', name: 'Lab Work' },
        'openEnded': { selector: 'table:has(.open-ended-project)', name: 'Open Ended Project' },
        'labExam': { selector: 'table:has(.lab-exam-header)', name: 'Lab Exam' },
        'finalAssessment': { selector: 'table:has(.final-assessment-header)', name: 'Final Assessment' }
    },

    // Hidden sheet name for storing hash (non-obvious name)
    HASH_SHEET_NAME: '._sys_meta',
    
    // Salt for hash (adds extra security layer)
    HASH_SALT: 'LOGI_INTEGRITY_2024',

    // ============================================
    // SHA-256 HASH FUNCTIONS
    // ============================================

    /**
     * Generate SHA-256 hash of data using Web Crypto API
     * @param {string} data - Data to hash
     * @returns {Promise<string>} - Hex string of hash
     */
    async generateHash(data) {
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data + this.HASH_SALT);
        const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    },

    /**
     * Create a canonical string representation of table data for hashing
     * @param {Object} tablesData - Object containing all table data
     * @returns {string} - Canonical string for hashing
     */
    createCanonicalString(tablesData) {
        // Sort keys and create consistent JSON representation
        const sortedData = {};
        Object.keys(tablesData).sort().forEach(key => {
            if (key !== this.HASH_SHEET_NAME) {
                sortedData[key] = tablesData[key];
            }
        });
        return JSON.stringify(sortedData);
    },

    // ============================================
    // TABLE DATA EXTRACTION
    // ============================================

    /**
     * Extract data from an HTML table including input values
     * @param {HTMLTableElement} table - Table element
     * @returns {Array<Array>} - 2D array of cell values
     */
    extractTableData(table) {
        const data = [];
        const rows = table.querySelectorAll('tr');
        
        rows.forEach(row => {
            const rowData = [];
            const cells = row.querySelectorAll('td, th');
            
            cells.forEach(cell => {
                // Check for input elements
                const input = cell.querySelector('input');
                if (input) {
                    if (input.type === 'checkbox') {
                        rowData.push(input.checked ? 'YES' : 'NO');
                    } else {
                        rowData.push(input.value || '');
                    }
                } else {
                    // Get text content, removing extra whitespace
                    rowData.push(cell.textContent.trim());
                }
            });
            
            if (rowData.length > 0) {
                data.push(rowData);
            }
        });
        
        return data;
    },

    /**
     * Find table by selector with fallback methods
     * @param {Object} tableConfig - Table configuration object
     * @returns {HTMLTableElement|null} - Found table or null
     */
    findTable(tableConfig) {
        try {
            // Try the primary selector
            let table = document.querySelector(tableConfig.selector);
            if (table) return table;
            
            // Fallback: search by header text
            const tables = document.querySelectorAll('table');
            for (const t of tables) {
                if (t.textContent.includes(tableConfig.name)) {
                    return t;
                }
            }
        } catch (e) {
            console.warn(`Could not find table: ${tableConfig.name}`, e);
        }
        return null;
    },

    /**
     * Extract all logbook data from the page with proper table structure
     * @returns {Object} - Object with sheet names as keys and data arrays as values
     */
    extractAllData() {
        const allData = {};
        
        // Extract student info in a clean format
        const studentInfo = this.extractStudentInfo();
        if (studentInfo.length > 0) {
            allData['Student Info'] = studentInfo;
        }
        
        // Extract Lab Work table with proper headers
        const labWorkData = this.extractLabWorkTable();
        if (labWorkData.length > 0) {
            allData['Lab Work'] = labWorkData;
        }
        
        // Extract Open Ended Project table
        const openEndedData = this.extractOpenEndedProject();
        if (openEndedData.length > 0) {
            allData['Open Ended Project'] = openEndedData;
        }
        
        // Extract Lab Exam table
        const labExamData = this.extractLabExam();
        if (labExamData.length > 0) {
            allData['Lab Exam'] = labExamData;
        }
        
        // Extract Final Assessment table
        const finalData = this.extractFinalAssessment();
        if (finalData.length > 0) {
            allData['Final Assessment'] = finalData;
        }
        
        return allData;
    },

    /**
     * Extract student information in a clean format
     */
    extractStudentInfo() {
        const data = [];
        data.push(['Student Information']);
        data.push(['']);
        data.push(['Field', 'Value']);
        
        const name = document.getElementById('name')?.value || '';
        const rollno = document.getElementById('detail1')?.value || '';
        const rgno = document.getElementById('detail')?.value || '';
        const subject = document.getElementById('subject')?.value || '';
        const code = document.getElementById('code')?.value || '';
        
        data.push(['Name of Student', name]);
        data.push(['Roll No', rollno]);
        data.push(['Register Number', rgno]);
        data.push(['Subject/Course Name', subject]);
        data.push(['Subject Code', code]);
        
        return data;
    },

    /**
     * Extract Lab Work table with exact logbook structure
     */
    extractLabWorkTable() {
        const data = [];
        
        // Header row 1 - matching the exact logbook structure
        data.push([
            'Sl No', 'Date of Experiment', 'Name of Experiment', 'CO',
            'Marks Awarded for Lab Work', '', '', '', '', '',
            'Signature', ''
        ]);
        
        // Header row 2 - Rubrics sub-header
        data.push([
            '', '', '', '',
            'Rubrics', '', '', '', '', 'TOTAL',
            'Student', 'Faculty'
        ]);
        
        // Header row 3 - Rubric numbers
        data.push([
            '', '', '', '',
            '1', '2', '3', '4', '5', '',
            '', ''
        ]);
        
        // Data rows - only include rows with data
        for (let i = 1; i <= 7; i++) {
            const date = document.querySelector(`[name="date${i}"]`)?.value || '';
            const experiment = document.querySelector(`[name="experiment${i}"]`)?.value || '';
            const co = document.querySelector(`[name="co${i}"]`)?.value || '';
            const r1 = document.querySelector(`[name="rubric${i}-1"]`)?.value || '';
            const r2 = document.querySelector(`[name="rubric${i}-2"]`)?.value || '';
            const r3 = document.querySelector(`[name="rubric${i}-3"]`)?.value || '';
            const r4 = document.querySelector(`[name="rubric${i}-4"]`)?.value || '';
            const r5 = document.querySelector(`[name="rubric${i}-5"]`)?.value || '';
            const total = document.querySelector(`[name="total${i}"]`)?.value || '';
            const student = document.querySelector(`[name="student${i}"]`)?.checked ? 'YES' : 'NO';
            const faculty = document.querySelector(`[name="faculty${i}"]`)?.checked ? 'YES' : 'NO';
            
            // Only export rows that have data (date or experiment filled)
            if (date.trim() !== '' || experiment.trim() !== '') {
                data.push([i, date, experiment, co, r1, r2, r3, r4, r5, total, student, faculty]);
            }
        }
        
        return data;
    },

    /**
     * Extract Open Ended Project with exact logbook structure
     */
    extractOpenEndedProject() {
        const data = [];
        
        // Title row
        data.push(['Open Ended Project', '', '', '', '', '', '', '', '', '', '', '']);
        
        // Header row 1
        data.push([
            'Sl No', 'Date of Project', 'Project', 'CO',
            'Marks Awarded for Lab Work', '', '', '', '', '',
            'Signature', ''
        ]);
        
        // Header row 2
        data.push([
            '', '', '', '',
            'Rubrics', '', '', '', '', 'TOTAL',
            'Student', 'Faculty'
        ]);
        
        // Header row 3
        data.push([
            '', '', '', '',
            '1', '2', '3', '4', '5', '',
            '', ''
        ]);
        
        // Data row - only include if it has data
        const date = document.querySelector('[name="t2date1"]')?.value || '';
        const project = document.querySelector('[name="t2experiment1"]')?.value || '';
        const co = document.querySelector('[name="t2co1"]')?.value || '';
        const r1 = document.querySelector('[name="t2rubric1-1"]')?.value || '';
        const r2 = document.querySelector('[name="t2rubric1-2"]')?.value || '';
        const r3 = document.querySelector('[name="t2rubric1-3"]')?.value || '';
        const r4 = document.querySelector('[name="t2rubric1-4"]')?.value || '';
        const r5 = document.querySelector('[name="t2rubric1-5"]')?.value || '';
        const total = document.querySelector('[name="t2total1"]')?.value || '';
        const student = document.querySelector('[name="t2student1"]')?.checked ? 'YES' : 'NO';
        const faculty = document.querySelector('[name="t2faculty1"]')?.checked ? 'YES' : 'NO';
        
        // Only include data row if it has data
        if (date.trim() !== '' || project.trim() !== '') {
            data.push([1, date, project, co, r1, r2, r3, r4, r5, total, student, faculty]);
        }
        
        return data;
    },

    /**
     * Extract Lab Exam with exact logbook structure
     */
    extractLabExam() {
        const data = [];
        
        // Title row
        data.push(['Lab Exam', '', '', '', '', '', '', '', '', '', '', '']);
        
        // Header row 1
        data.push([
            'Sl No', 'Date of Exam', 'Exam', 'CO',
            'Marks Awarded for Lab Work', '', '', '', '', '',
            'Signature', ''
        ]);
        
        // Header row 2
        data.push([
            '', '', '', '',
            'Rubrics', '', '', '', '', 'TOTAL',
            'Student', 'Faculty'
        ]);
        
        // Header row 3
        data.push([
            '', '', '', '',
            '1', '2', '3', '4', '5', '',
            '', ''
        ]);
        
        // Data rows - only include rows with data
        for (let i = 1; i <= 3; i++) {
            const date = document.querySelector(`[name="t3date${i}"]`)?.value || '';
            const exam = document.querySelector(`[name="exam${i}"]`)?.value || '';
            const co = document.querySelector(`[name="t3co${i}"]`)?.value || '';
            const r1 = document.querySelector(`[name="t3rubric${i}-1"]`)?.value || '';
            const r2 = document.querySelector(`[name="t3rubric${i}-2"]`)?.value || '';
            const r3 = document.querySelector(`[name="t3rubric${i}-3"]`)?.value || '';
            const r4 = document.querySelector(`[name="t3rubric${i}-4"]`)?.value || '';
            const r5 = document.querySelector(`[name="t3rubric${i}-5"]`)?.value || '';
            const total = document.querySelector(`[name="t3total${i}"]`)?.value || '';
            const student = document.querySelector(`[name="t3student${i}"]`)?.checked ? 'YES' : 'NO';
            const faculty = document.querySelector(`[name="t3faculty${i}"]`)?.checked ? 'YES' : 'NO';
            
            // Only export rows that have data (date or exam filled)
            if (date.trim() !== '' || exam.trim() !== '') {
                data.push([i, date, exam, co, r1, r2, r3, r4, r5, total, student, faculty]);
            }
        }
        
        return data;
    },

    /**
     * Extract Final Assessment with exact logbook structure
     */
    extractFinalAssessment() {
        const data = [];
        
        // Title row
        data.push(['Final Assessment', '', '', '']);
        
        // Header
        data.push(['', '', 'Maximum Marks', 'Marks Awarded']);
        
        // Data rows
        const f1 = document.querySelector('[name="final1"]')?.value || '';
        const f2 = document.querySelector('[name="final2"]')?.value || '';
        const f3 = document.querySelector('[name="final3"]')?.value || '';
        const f4 = document.querySelector('[name="final4"]')?.value || '';
        const f5 = document.querySelector('[name="final5"]')?.value || '';
        
        // Verification signatures
        const studentSig = document.querySelector('[name="finalStudentSignature"]')?.checked ? 'YES' : 'NO';
        const facultySig = document.querySelector('[name="finalFacultySignature"]')?.checked ? 'YES' : 'NO';
        
        data.push(['Attendance', '', '15', f1]);
        data.push(['Formative Assessment', 'Lab Work', '37.5', f2]);
        data.push(['', 'Open Ended Project', '7.5', f3]);
        data.push(['Summative Assessment', 'Lab Exam', '15', f4]);
        data.push(['Total Marks', '', '75', f5]);
        data.push(['Verification Signature', 'Student', studentSig, '']);
        data.push(['', 'Faculty', facultySig, '']);
        
        return data;
    },

    // ============================================
    // EXPORT FUNCTIONALITY
    // ============================================

    /**
     * Export all logbook tables to Excel with integrity hash
     */
    async exportToExcel() {
        try {
            // Show loading indicator
            this.showLoading('Preparing export...');
            
            // Check if XLSX library is loaded
            if (typeof XLSX === 'undefined') {
                throw new Error('Excel library not loaded. Please refresh the page and try again.');
            }
            
            // Extract all table data
            const allData = this.extractAllData();
            
            if (Object.keys(allData).length === 0) {
                throw new Error('No table data found to export.');
            }
            
            // Generate hash of the data
            const canonicalString = this.createCanonicalString(allData);
            const hash = await this.generateHash(canonicalString);
            
            // Create workbook
            const wb = XLSX.utils.book_new();
            
            // Add each table as a worksheet
            Object.entries(allData).forEach(([sheetName, data]) => {
                const ws = XLSX.utils.aoa_to_sheet(data);
                
                // Auto-size columns
                const colWidths = data[0]?.map((_, colIndex) => {
                    const maxLen = Math.max(...data.map(row => 
                        String(row[colIndex] || '').length
                    ));
                    return { wch: Math.min(Math.max(maxLen, 10), 50) };
                }) || [];
                ws['!cols'] = colWidths;
                
                XLSX.utils.book_append_sheet(wb, ws, sheetName.substring(0, 31)); // Excel limit: 31 chars
            });
            
            // Add hidden metadata sheet with hash
            const metaData = [
                ['LOGI Logbook Export'],
                ['Export Date', new Date().toISOString()],
                ['Integrity Hash', hash],
                ['Version', '1.0'],
                ['WARNING', 'Do not modify this sheet - file will be rejected on import']
            ];
            const metaWs = XLSX.utils.aoa_to_sheet(metaData);
            XLSX.utils.book_append_sheet(wb, metaWs, this.HASH_SHEET_NAME);
            
            // Generate consistent filename (no date to allow overwriting)
            const studentName = document.getElementById('name')?.value || 'Logbook';
            const rollNo = document.getElementById('detail1')?.value || '';
            const subjectCode = document.getElementById('code')?.value || '';
            const cleanName = studentName.replace(/[^a-zA-Z0-9]/g, '_');
            const filename = `${cleanName}_${rollNo}_${subjectCode}_Logbook.xlsx`;
            
            // Try to use File System Access API for overwriting same file
            if ('showSaveFilePicker' in window) {
                try {
                    const handle = await window.showSaveFilePicker({
                        suggestedName: filename,
                        types: [{
                            description: 'Excel Workbook',
                            accept: { 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'] }
                        }]
                    });
                    
                    const writable = await handle.createWritable();
                    const wbout = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });
                    await writable.write(new Blob([wbout], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }));
                    await writable.close();
                    
                    this.hideLoading();
                    this.showSuccess(`Logbook exported successfully!\n\nFile saved to your chosen location.\n\nKeep this file safe - it contains your verified logbook data.`);
                    return;
                } catch (fsError) {
                    // User cancelled or API not fully supported, fall back to regular download
                    console.log('File System Access API not available or cancelled, using fallback');
                }
            }
            
            // Fallback: Regular download
            XLSX.writeFile(wb, filename);
            
            this.hideLoading();
            this.showSuccess(`Logbook exported successfully!\n\nFile: ${filename}\n\n💡 Tip: Save to the same location and overwrite the old file to keep only one copy.`);
            
        } catch (error) {
            this.hideLoading();
            this.showError('Export Failed', error.message);
            console.error('Export error:', error);
        }
    },

    // ============================================
    // IMPORT FUNCTIONALITY
    // ============================================

    /**
     * Trigger file input for import
     */
    triggerImport() {
        // Create hidden file input
        const fileInput = document.createElement('input');
        fileInput.type = 'file';
        fileInput.accept = '.xlsx,.xls';
        fileInput.style.display = 'none';
        
        fileInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) {
                this.importFromExcel(file);
            }
            fileInput.remove();
        });
        
        document.body.appendChild(fileInput);
        fileInput.click();
    },

    /**
     * Import and verify Excel file
     * @param {File} file - Excel file to import
     */
    async importFromExcel(file) {
        try {
            this.showLoading('Verifying file integrity...');
            
            // Check if XLSX library is loaded
            if (typeof XLSX === 'undefined') {
                throw new Error('Excel library not loaded. Please refresh the page and try again.');
            }
            
            // Read file
            const arrayBuffer = await file.arrayBuffer();
            const wb = XLSX.read(arrayBuffer, { type: 'array' });
            
            // Check for metadata sheet
            if (!wb.SheetNames.includes(this.HASH_SHEET_NAME)) {
                throw new Error('Invalid file format: This file was not exported from LOGI or the integrity data is missing.');
            }
            
            // Extract stored hash
            const metaSheet = wb.Sheets[this.HASH_SHEET_NAME];
            const metaData = XLSX.utils.sheet_to_json(metaSheet, { header: 1 });
            
            let storedHash = null;
            metaData.forEach(row => {
                if (row[0] === 'Integrity Hash') {
                    storedHash = row[1];
                }
            });
            
            if (!storedHash) {
                throw new Error('Integrity hash not found in file. The file may be corrupted or tampered with.');
            }
            
            // Extract data from all sheets (except metadata)
            const importedData = {};
            wb.SheetNames.forEach(sheetName => {
                if (sheetName !== this.HASH_SHEET_NAME) {
                    const sheet = wb.Sheets[sheetName];
                    importedData[sheetName] = XLSX.utils.sheet_to_json(sheet, { header: 1 });
                }
            });
            
            // Recalculate hash
            const canonicalString = this.createCanonicalString(importedData);
            const calculatedHash = await this.generateHash(canonicalString);
            
            // Compare hashes
            if (storedHash !== calculatedHash) {
                this.hideLoading();
                this.showError(
                    'File Tampered!',
                    'The file has been modified since it was exported.\n\n' +
                    'This could mean:\n' +
                    '• Someone edited the Excel file\n' +
                    '• The file was corrupted during transfer\n\n' +
                    'Import rejected for security reasons. Please use the original exported file.'
                );
                return;
            }
            
            // Hash matches - populate form with imported data
            await this.populateFormFromData(importedData);
            
            this.hideLoading();
            this.showSuccess(
                'Import Successful!\n\n' +
                'File verified - data integrity confirmed.\n' +
                'The logbook data has been loaded into the form.'
            );
            
        } catch (error) {
            this.hideLoading();
            this.showError('Import Failed', error.message);
            console.error('Import error:', error);
        }
    },

    /**
     * Populate form inputs from imported data
     * @param {Object} data - Imported data object
     */
    async populateFormFromData(data) {
        // Populate Student Info
        if (data['Student Info']) {
            const studentData = data['Student Info'];
            studentData.forEach(row => {
                if (row[0] && row[1] !== undefined) {
                    const label = row[0].toLowerCase();
                    const value = row[1];
                    
                    if (label.includes('name')) {
                        const nameInput = document.getElementById('name');
                        if (nameInput) nameInput.value = value;
                    } else if (label.includes('roll')) {
                        const rollInput = document.getElementById('detail1');
                        if (rollInput) rollInput.value = value;
                    } else if (label.includes('register')) {
                        const regInput = document.getElementById('detail');
                        if (regInput) regInput.value = value;
                    } else if (label.includes('subject') || label.includes('course')) {
                        const subjectInput = document.getElementById('subject');
                        if (subjectInput) subjectInput.value = value;
                    } else if (label.includes('code')) {
                        const codeInput = document.getElementById('code');
                        if (codeInput) codeInput.value = value;
                    }
                }
            });
        }
        
        // Populate Lab Work table (skip header rows - first 3)
        if (data['Lab Work']) {
            const labData = data['Lab Work'];
            for (let i = 3; i < labData.length; i++) {
                const row = labData[i];
                const rowNum = i - 2; // Row 1 starts at index 3
                
                if (rowNum > 0 && rowNum <= 7) {
                    this.setInputValue(`date${rowNum}`, row[1]);
                    this.setInputValue(`experiment${rowNum}`, row[2]);
                    this.setInputValue(`co${rowNum}`, row[3]);
                    this.setInputValue(`rubric${rowNum}-1`, row[4]);
                    this.setInputValue(`rubric${rowNum}-2`, row[5]);
                    this.setInputValue(`rubric${rowNum}-3`, row[6]);
                    this.setInputValue(`rubric${rowNum}-4`, row[7]);
                    this.setInputValue(`rubric${rowNum}-5`, row[8]);
                    this.setInputValue(`total${rowNum}`, row[9]);
                    this.setCheckboxValue(`student${rowNum}`, row[10]);
                    this.setCheckboxValue(`faculty${rowNum}`, row[11]);
                }
            }
        }
        
        // Populate Open Ended Project (skip header rows - first 4)
        if (data['Open Ended Project']) {
            const projectData = data['Open Ended Project'];
            for (let i = 4; i < projectData.length; i++) {
                const row = projectData[i];
                const rowNum = i - 3;
                
                if (rowNum === 1) {
                    this.setInputValue('t2date1', row[1]);
                    this.setInputValue('t2experiment1', row[2]);
                    this.setInputValue('t2co1', row[3]);
                    this.setInputValue('t2rubric1-1', row[4]);
                    this.setInputValue('t2rubric1-2', row[5]);
                    this.setInputValue('t2rubric1-3', row[6]);
                    this.setInputValue('t2rubric1-4', row[7]);
                    this.setInputValue('t2rubric1-5', row[8]);
                    this.setInputValue('t2total1', row[9]);
                    this.setCheckboxValue('t2student1', row[10]);
                    this.setCheckboxValue('t2faculty1', row[11]);
                }
            }
        }
        
        // Populate Lab Exam (skip header rows - first 4)
        if (data['Lab Exam']) {
            const examData = data['Lab Exam'];
            for (let i = 4; i < examData.length; i++) {
                const row = examData[i];
                const rowNum = i - 3;
                
                if (rowNum >= 1 && rowNum <= 3) {
                    this.setInputValue(`t3date${rowNum}`, row[1]);
                    this.setInputValue(`exam${rowNum}`, row[2]);
                    this.setInputValue(`t3co${rowNum}`, row[3]);
                    this.setInputValue(`t3rubric${rowNum}-1`, row[4]);
                    this.setInputValue(`t3rubric${rowNum}-2`, row[5]);
                    this.setInputValue(`t3rubric${rowNum}-3`, row[6]);
                    this.setInputValue(`t3rubric${rowNum}-4`, row[7]);
                    this.setInputValue(`t3rubric${rowNum}-5`, row[8]);
                    this.setInputValue(`t3total${rowNum}`, row[9]);
                    this.setCheckboxValue(`t3student${rowNum}`, row[10]);
                    this.setCheckboxValue(`t3faculty${rowNum}`, row[11]);
                }
            }
        }
        
        // Populate Final Assessment
        if (data['Final Assessment']) {
            const finalData = data['Final Assessment'];
            // The structure is different, find values by position
            finalData.forEach((row, index) => {
                if (row[3] !== undefined && row[3] !== 'Marks Awarded') {
                    // Map based on row content
                    const label = (row[0] || '') + (row[1] || '');
                    if (label.includes('Attendance') || index === 2) {
                        this.setInputValue('final1', row[3]);
                    } else if (label.includes('Lab Work') || index === 4) {
                        this.setInputValue('final2', row[3]);
                    } else if (label.includes('Open Ended') || index === 5) {
                        this.setInputValue('final3', row[3]);
                    } else if (label.includes('Lab Exam') || index === 7) {
                        this.setInputValue('final4', row[3]);
                    } else if (label.includes('Total') || index === 8) {
                        this.setInputValue('final5', row[3]);
                    }
                }
                
                // Handle verification signatures
                if (row[0] && row[0].toString().includes('Verification')) {
                    if (row[1] === 'Student') {
                        this.setCheckboxValue('finalStudentSignature', row[2]);
                    }
                }
                if (row[1] === 'Faculty' && row[0] === '') {
                    this.setCheckboxValue('finalFacultySignature', row[2]);
                }
            });
        }
    },

    /**
     * Helper to set input value by name
     */
    setInputValue(name, value) {
        const input = document.querySelector(`[name="${name}"]`);
        if (input && value !== undefined && value !== '') {
            input.value = value;
        }
    },

    /**
     * Helper to set checkbox value
     */
    setCheckboxValue(name, value) {
        const checkbox = document.querySelector(`[name="${name}"]`);
        if (checkbox) {
            checkbox.checked = (value === 'YES' || value === true || value === 'true');
        }
    },

    // ============================================
    // UI HELPERS
    // ============================================

    /**
     * Show loading overlay
     */
    showLoading(message = 'Processing...') {
        // Remove existing overlay if any
        this.hideLoading();
        
        const overlay = document.createElement('div');
        overlay.id = 'excel-loading-overlay';
        overlay.innerHTML = `
            <div style="
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(0,0,0,0.5);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 10000;
            ">
                <div style="
                    background: white;
                    padding: 30px 50px;
                    border-radius: 12px;
                    text-align: center;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.3);
                ">
                    <div style="
                        width: 50px;
                        height: 50px;
                        border: 4px solid #e0e0e0;
                        border-top-color: #36ba86;
                        border-radius: 50%;
                        animation: excel-spin 0.8s linear infinite;
                        margin: 0 auto 20px;
                    "></div>
                    <p style="margin: 0; font-size: 16px; color: #333;">${message}</p>
                </div>
            </div>
            <style>
                @keyframes excel-spin {
                    to { transform: rotate(360deg); }
                }
            </style>
        `;
        document.body.appendChild(overlay);
    },

    /**
     * Hide loading overlay
     */
    hideLoading() {
        const overlay = document.getElementById('excel-loading-overlay');
        if (overlay) {
            overlay.remove();
        }
    },

    /**
     * Show success message using SweetAlert if available, otherwise alert
     */
    showSuccess(message) {
        if (typeof Swal !== 'undefined') {
            Swal.fire({
                title: 'Success!',
                text: message,
                icon: 'success',
                confirmButtonColor: '#36ba86'
            });
        } else {
            alert('✅ ' + message);
        }
    },

    /**
     * Show error message using SweetAlert if available, otherwise alert
     */
    showError(title, message) {
        if (typeof Swal !== 'undefined') {
            Swal.fire({
                title: title,
                text: message,
                icon: 'error',
                confirmButtonColor: '#dc3545'
            });
        } else {
            alert('❌ ' + title + '\n\n' + message);
        }
    }
};

// ============================================
// GLOBAL FUNCTIONS (for onclick handlers)
// ============================================

/**
 * Export logbook to Excel - called from button
 */
function exportLogbookToExcel() {
    LogbookExcel.exportToExcel();
}

/**
 * Import logbook from Excel - called from button
 */
function importLogbookFromExcel() {
    LogbookExcel.triggerImport();
}

// Log initialization
console.log('📊 Logbook Excel Export/Import module loaded');
