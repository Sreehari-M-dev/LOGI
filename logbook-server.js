// Load environment variables from .env for local development
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const crypto = require('crypto');
const app = express();

const JWT_SECRET = process.env.JWT_SECRET; // Same as auth-server
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/LOGI';
const PORT = process.env.PORT || process.env.LOGBOOK_SERVICE_PORT || 3005;

if (!JWT_SECRET) {
    console.error('JWT_SECRET is not set. Please define it in the environment.');
    process.exit(1);
}

// Security Enhancement: Simple rate limiting middleware
const requestCounts = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const MAX_REQUESTS = 100; // Max requests per window

function simpleRateLimit(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    
    if (!requestCounts.has(ip)) {
        requestCounts.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    } else {
        const data = requestCounts.get(ip);
        if (now > data.resetTime) {
            data.count = 1;
            data.resetTime = now + RATE_LIMIT_WINDOW;
        } else {
            data.count++;
            if (data.count > MAX_REQUESTS) {
                return res.status(429).json({ 
                    success: false, 
                    error: 'Too many requests. Please try again later.' 
                });
            }
        }
    }
    next();
}

// Security Enhancement: Input sanitization middleware
function sanitizeInput(obj) {
    if (typeof obj === 'string') {
        return obj.replace(/[<>]/g, '').trim();
    }
    if (typeof obj === 'object' && obj !== null) {
        for (let key in obj) {
            obj[key] = sanitizeInput(obj[key]);
        }
    }
    return obj;
}

// Authentication middleware: delegate verification to Auth Service to enforce session idle timeout
async function authenticateToken(req, res, next) {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ success: false, error: 'No token provided' });
        }

        const authServiceUrl = process.env.AUTH_SERVICE_URL || 'http://localhost:3002';
        const response = await fetch(`${authServiceUrl}/api/auth/verify`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            const err = await response.json().catch(() => ({ error: 'Authentication failed' }));
            return res.status(401).json({ success: false, error: err.error || 'Authentication failed' });
        }

        const data = await response.json();
        req.user = data.user; // decoded payload from auth-server
        next();
    } catch (error) {
        console.error('Auth verification error:', error);
        res.status(401).json({ success: false, error: 'Authentication failed' });
    }
}

// Middleware - Environment-aware CORS origins
const isProduction = process.env.NODE_ENV === 'production';
const allowedOrigins = isProduction
    ? ['https://sreehari-m-dev.github.io'] // Production: only GitHub Pages
    : [
        'http://localhost',
        'http://localhost:3000',
        'http://localhost:8080',
        'http://127.0.0.1',
        'http://127.0.0.1:3000',
        'http://127.0.0.1:3003',
        'http://10.154.126.1:5000'
        
    ];

// Log all incoming requests and headers
app.use((req, res, next) => {
    console.log(`[REQUEST] ${req.method} ${req.path}`);
    console.log(`[HEADERS] Origin: ${req.headers.origin}, Referer: ${req.headers.referer}`);
    console.log(`[HEADERS] Host: ${req.headers.host}`);
    next();
});

app.use(cors({
    origin: function(origin, callback) {
        console.log(`[CORS] Origin received: ${origin}`);
        if (!origin) {
            console.log('[CORS] No origin (non-browser request) - allowing');
            return callback(null, true);
        }
        if (allowedOrigins.includes(origin)) {
            console.log(`[CORS] Origin ${origin} is allowed`);
            return callback(null, true);
        }
        console.log(`[CORS] Origin ${origin} is NOT allowed`);
        return callback(new Error('Not allowed by CORS'));
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: false,
    maxAge: 86400
}));

// Security headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
});

app.use(simpleRateLimit);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// MongoDB Connection
mongoose.connect(MONGODB_URI)
.then(() => console.log('Connected to MongoDB - Database: LOGI'))
.catch((err) => console.error('MongoDB connection error:', err));

// Log Book Schema - updated to support multiple subjects per student
const logBookSchema = new mongoose.Schema({
    name: { type: String, required: true },
    rollno: { type: Number, required: true },
    rgno: { type: Number, required: true },
    subject: { type: String, required: true }, // Subject/Course name
    code: { type: String }, // Subject code
    semester: { type: Number },
    experiments: [{
        slNo: Number,
        date: String,
        experimentName: String,
        co: Number,
        rubric1: Number,
        rubric2: Number,
        rubric3: Number,
        rubric4: Number,
        rubric5: Number,
        total: Number,
        studentSignature: Boolean,
        facultySignature: Boolean
    }],
    openEndedProject: {
        date: String,
        projectName: String,
        co: Number,
        rubric1: Number,
        rubric2: Number,
        rubric3: Number,
        rubric4: Number,
        rubric5: Number,
        total: Number,
        studentSignature: Boolean,
        facultySignature: Boolean
    },
    labExams: [{
        slNo: Number,
        date: String,
        examName: String,
        co: Number,
        rubric1: Number,
        rubric2: Number,
        rubric3: Number,
        rubric4: Number,
        rubric5: Number,
        total: Number,
        studentSignature: Boolean,
        facultySignature: Boolean
    }],
    finalAssessment: {
        attendance: Number,
        labWork: Number,
        openEndedProject: Number,
        labExam: Number,
        totalMarks: Number
    },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const LogBook = mongoose.model('LogBook', logBookSchema);

// Master Logbook Schema - Template created by teachers
const masterLogbookSchema = new mongoose.Schema({
    subject: { type: String, required: true },
    code: { type: String },
    department: { type: String, required: true },
    semester: { type: Number, required: true },
    batch: { type: String, required: true },
    college: { type: String, required: true }, // College scoping
    teacherRgno: { type: Number, required: true },
    teacherName: { type: String },
    experiments: [{
        slNo: Number,
        experimentName: String,
        co: String,
        maxMarks: Number
    }],
    openEndedProject: {
        projectName: String,
        co: String,
        maxMarks: Number
    },
    labExams: [{
        examName: String,
        co: String,
        maxMarks: Number
    }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// Add college-based indexes for performance
masterLogbookSchema.index({ college: 1, teacherRgno: 1 });
masterLogbookSchema.index({ college: 1, department: 1, semester: 1 });

// Student Logbook Schema - Individual instances linked to master
const studentLogbookSchema = new mongoose.Schema({
    masterLogbookId: { type: mongoose.Schema.Types.ObjectId, ref: 'MasterLogbook', required: true },
    name: { type: String, required: true },
    rollno: { type: Number, required: true },
    rgno: { type: Number, required: true },
    subject: { type: String, required: true },
    code: { type: String },
    department: { type: String },
    semester: { type: Number },
    batch: { type: String },
    college: { type: String }, // College scoping
    experiments: [{
        slNo: Number,
        date: String,
        experimentName: String,
        co: String,
        rubric1: Number,
        rubric2: Number,
        rubric3: Number,
        rubric4: Number,
        rubric5: Number,
        total: Number,
        studentSignature: Boolean,
        facultySignature: Boolean
    }],
    openEndedProject: {
        date: String,
        projectName: String,
        co: String,
        rubric1: Number,
        rubric2: Number,
        rubric3: Number,
        rubric4: Number,
        rubric5: Number,
        total: Number,
        studentSignature: Boolean,
        facultySignature: Boolean
    },
    labExams: [{
        slNo: Number,
        date: String,
        examName: String,
        co: String,
        rubric1: Number,
        rubric2: Number,
        rubric3: Number,
        rubric4: Number,
        rubric5: Number,
        total: Number,
        studentSignature: Boolean,
        facultySignature: Boolean
    }],
    finalAssessment: {
        attendance: Number,
        labWork: Number,
        openEndedProject: Number,
        labExam: Number,
        totalMarks: Number
    },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// Add college-based indexes
studentLogbookSchema.index({ college: 1, rgno: 1 });
studentLogbookSchema.index({ college: 1, department: 1, semester: 1 });

const MasterLogbook = mongoose.model('MasterLogbook', masterLogbookSchema);
const StudentLogbook = mongoose.model('StudentLogbook', studentLogbookSchema);

// ==================== MASTER LOGBOOK ENDPOINTS ====================

// Create Master Logbook (Teachers only)
app.post('/api/logbook/master/create', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'faculty' && req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                error: 'Only teachers can create master logbooks'
            });
        }

        const sanitizedBody = sanitizeInput(req.body);
        const { subject, code, department, semester, batch, experiments, openEndedProject, labExams } = sanitizedBody;

        if (!subject || !department || !semester || !batch) {
            return res.status(400).json({
                success: false,
                error: 'Subject, department, semester, and batch are required'
            });
        }

        // Get teacher's college from their profile
        const authServiceUrl = process.env.AUTH_SERVICE_URL || 'http://localhost:3002';
        const teacherResponse = await fetch(`${authServiceUrl}/api/auth/profile`, {
            headers: { 'Authorization': req.headers.authorization }
        });
        const teacherData = await teacherResponse.json();
        
        if (!teacherData.success || !teacherData.user.college) {
            return res.status(400).json({
                success: false,
                error: 'Teacher college information not found'
            });
        }

        const teacherCollege = teacherData.user.college;

        // Check if this faculty already has a master template with same subject AND code in their college
        const existingTemplate = await MasterLogbook.findOne({
            teacherRgno: req.user.rgno,
            subject: subject,
            code: code,
            college: teacherCollege
        });

        if (existingTemplate) {
            return res.status(400).json({
                success: false,
                error: `You already have a master template for "${subject}" (${code}). Please edit the existing template instead.`
            });
        }

        const masterLogbook = new MasterLogbook({
            subject,
            code,
            department,
            semester,
            batch,
            college: teacherCollege, // College scoping
            teacherRgno: req.user.rgno,
            teacherName: teacherData.user.name,
            experiments: experiments || [],
            openEndedProject: openEndedProject || {},
            labExams: labExams || []
        });

        const result = await masterLogbook.save();
        
        res.json({
            success: true,
            message: 'Master logbook created successfully',
            masterId: result._id,
            data: result
        });
    } catch (error) {
        console.error('Error creating master logbook:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get Master Logbook by ID
app.get('/api/logbook/master/:id', authenticateToken, async (req, res) => {
    try {
        const masterId = req.params.id;
        const masterLogbook = await MasterLogbook.findById(masterId);

        if (!masterLogbook) {
            return res.status(404).json({
                success: false,
                error: 'Master logbook not found'
            });
        }

        // Authorization: Only the creator can access
        if (masterLogbook.teacherRgno !== req.user.rgno && req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                error: 'You can only access templates you created'
            });
        }

        res.json({
            success: true,
            data: masterLogbook
        });
    } catch (error) {
        console.error('Error fetching master logbook:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get assigned students for a Master Template
app.get('/api/logbook/master/:id/students', authenticateToken, async (req, res) => {
    try {
        const masterId = req.params.id;
        
        // Check if template exists
        const masterLogbook = await MasterLogbook.findById(masterId);
        if (!masterLogbook) {
            return res.status(404).json({
                success: false,
                error: 'Master logbook not found'
            });
        }

        // Authorization: Only the creator or admin can view assigned students
        if (masterLogbook.teacherRgno !== req.user.rgno && req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                error: 'You can only view students for templates you created'
            });
        }

        // Find all student logbooks created from this master template
        const studentLogbooks = await StudentLogbook.find({ masterLogbookId: masterId }).select('name email rollno rgno studentRgno createdAt');
        
        // Map to a cleaner format
        const students = studentLogbooks.map(sl => ({
            name: sl.name || 'N/A',
            email: sl.email || 'N/A',
            rollNo: sl.rollno || 'N/A',
            rgno: sl.rgno || sl.studentRgno || 'N/A',
            assignedAt: sl.createdAt
        }));

        res.json({
            success: true,
            students: students,
            count: students.length
        });
    } catch (error) {
        console.error('Error fetching assigned students:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Update Master Logbook (syncs to all student instances)
app.put('/api/logbook/master/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'faculty' && req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                error: 'Only teachers can update master logbooks'
            });
        }

        const masterId = req.params.id;
        const sanitizedBody = sanitizeInput(req.body);
        
        // Check if template exists and belongs to this teacher
        const existingMaster = await MasterLogbook.findById(masterId);
        if (!existingMaster) {
            return res.status(404).json({
                success: false,
                error: 'Master template not found'
            });
        }

        if (existingMaster.teacherRgno !== req.user.rgno && req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                error: 'You can only edit templates you created'
            });
        }
        
        const updatedMaster = await MasterLogbook.findByIdAndUpdate(
            masterId,
            { ...sanitizedBody, updatedAt: Date.now() },
            { new: true }
        );

        if (!updatedMaster) {
            return res.status(404).json({
                success: false,
                error: 'Master logbook not found'
            });
        }

        // Sync master changes to all student instances
        const studentLogbooks = await StudentLogbook.find({ masterLogbookId: masterId });
        
        for (const studentLogbook of studentLogbooks) {
            // Keep subject/code in sync
            if (sanitizedBody.subject) studentLogbook.subject = sanitizedBody.subject;
            if (sanitizedBody.code) studentLogbook.code = sanitizedBody.code;
            if (sanitizedBody.department) studentLogbook.department = sanitizedBody.department;
            if (sanitizedBody.semester) studentLogbook.semester = sanitizedBody.semester;
            if (sanitizedBody.batch) studentLogbook.batch = sanitizedBody.batch;

            // Experiments: update existing and append missing rows
            if (sanitizedBody.experiments) {
                sanitizedBody.experiments.forEach((mExp, idx) => {
                    if (studentLogbook.experiments[idx]) {
                        studentLogbook.experiments[idx].experimentName = mExp.experimentName;
                        studentLogbook.experiments[idx].co = mExp.co;
                    } else {
                        studentLogbook.experiments.push({
                            slNo: mExp.slNo || idx + 1,
                            experimentName: mExp.experimentName,
                            co: mExp.co,
                            date: '',
                            rubric1: 0,
                            rubric2: 0,
                            rubric3: 0,
                            rubric4: 0,
                            rubric5: 0,
                            total: 0,
                            studentSignature: false,
                            facultySignature: false
                        });
                    }
                });
            }
            
            // Lab exams: update and append
            if (sanitizedBody.labExams) {
                sanitizedBody.labExams.forEach((mExam, idx) => {
                    if (studentLogbook.labExams[idx]) {
                        studentLogbook.labExams[idx].examName = mExam.examName;
                        studentLogbook.labExams[idx].co = mExam.co;
                    } else {
                        studentLogbook.labExams.push({
                            slNo: mExam.slNo || idx + 1,
                            examName: mExam.examName,
                            co: mExam.co,
                            date: '',
                            rubric1: 0,
                            rubric2: 0,
                            rubric3: 0,
                            rubric4: 0,
                            rubric5: 0,
                            total: 0,
                            studentSignature: false,
                            facultySignature: false
                        });
                    }
                });
            }
            
            // Open-ended project (if present in student logbook)
            if (sanitizedBody.openEndedProject && studentLogbook.openEndedProject) {
                studentLogbook.openEndedProject.projectName = sanitizedBody.openEndedProject.projectName;
                studentLogbook.openEndedProject.co = sanitizedBody.openEndedProject.co;
            }
            
            studentLogbook.updatedAt = Date.now();
            await studentLogbook.save();
        }

        res.json({
            success: true,
            message: `Master updated and synced to ${studentLogbooks.length} student(s)`,
            data: updatedMaster
        });
    } catch (error) {
        console.error('Error updating master logbook:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Fetch registered students by department and semester
app.get('/api/logbook/students/by-dept-sem', authenticateToken, async (req, res) => {
    try {
        const { department, semester } = req.query;

        if (!department || !semester) {
            return res.status(400).json({
                success: false,
                error: 'Department and semester are required'
            });
        }

        // Fetch students from auth database
        const authServiceUrl = process.env.AUTH_SERVICE_URL || 'http://localhost:3002';
        const authResponse = await fetch(`${authServiceUrl}/api/auth/students/filter`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': req.headers.authorization
            },
            body: JSON.stringify({ department, semester: parseInt(semester) })
        });

        const data = await authResponse.json();

        if (data.success) {
            res.json({
                success: true,
                students: data.students || []
            });
        } else {
            res.status(500).json({
                success: false,
                error: 'Failed to fetch students'
            });
        }
    } catch (error) {
        console.error('Error fetching students by dept/sem:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Fetch all master templates for the logged-in teacher
app.get('/api/logbook/teacher/templates', authenticateToken, async (req, res) => {
    try {
        console.log('GET /teacher/templates - User:', req.user);
        
        if (req.user.role !== 'faculty' && req.user.role !== 'admin') {
            console.log('403 - Role check failed. User role:', req.user.role);
            return res.status(403).json({
                success: false,
                error: 'Only teachers can fetch master templates'
            });
        }

        // Fetch all master logbooks created by this teacher
        const templates = await MasterLogbook.find({ teacherRgno: req.user.rgno }).sort({ createdAt: -1 });

        res.json({
            success: true,
            data: templates,
            count: templates.length
        });
    } catch (error) {
        console.error('Error fetching teacher templates:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Assign Students to Master Logbook
app.post('/api/logbook/master/:id/assign-students', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'faculty' && req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                error: 'Only teachers can assign students'
            });
        }

        const masterId = req.params.id;
        const { students } = sanitizeInput(req.body);

        const masterLogbook = await MasterLogbook.findById(masterId);
        if (!masterLogbook) {
            return res.status(404).json({
                success: false,
                error: 'Master logbook not found'
            });
        }

        // Ensure faculty can only assign to templates they own
        if (masterLogbook.teacherRgno !== req.user.rgno && req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                error: 'You can only assign students to your own templates'
            });
        }

        const studentLogbooks = [];
        const skippedStudents = [];
        
        for (const student of students) {
            // Check if student already has a logbook for same subject + code in same college
            const existingLogbook = await StudentLogbook.findOne({
                rgno: student.rgno,
                subject: masterLogbook.subject,
                code: masterLogbook.code,
                college: masterLogbook.college
            });

            if (existingLogbook) {
                skippedStudents.push({
                    name: student.name,
                    rollno: student.rollno,
                    reason: `Already assigned to "${masterLogbook.subject}" (${masterLogbook.code})`
                });
                continue; // Skip this student
            }
            
            const studentLogbook = new StudentLogbook({
                masterLogbookId: masterId,
                name: student.name,
                rollno: student.rollno,
                rgno: student.rgno,
                subject: masterLogbook.subject,
                code: masterLogbook.code,
                department: masterLogbook.department,
                semester: masterLogbook.semester,
                batch: masterLogbook.batch,
                college: masterLogbook.college, // College scoping from master
                experiments: masterLogbook.experiments.map(exp => ({
                    slNo: exp.slNo,
                    experimentName: exp.experimentName,
                    co: exp.co,
                    date: '',
                    rubric1: 0,
                    rubric2: 0,
                    rubric3: 0,
                    rubric4: 0,
                    rubric5: 0,
                    total: 0,
                    studentSignature: false,
                    facultySignature: false
                })),
                openEndedProject: masterLogbook.openEndedProject ? {
                    projectName: masterLogbook.openEndedProject.projectName,
                    co: masterLogbook.openEndedProject.co,
                    date: '',
                    rubric1: 0,
                    rubric2: 0,
                    rubric3: 0,
                    rubric4: 0,
                    rubric5: 0,
                    total: 0,
                    studentSignature: false,
                    facultySignature: false
                } : {},
                labExams: masterLogbook.labExams.map((exam, index) => ({
                    slNo: index + 1,
                    examName: exam.examName,
                    co: exam.co,
                    date: '',
                    rubric1: 0,
                    rubric2: 0,
                    rubric3: 0,
                    rubric4: 0,
                    rubric5: 0,
                    total: 0,
                    studentSignature: false,
                    facultySignature: false
                })),
                finalAssessment: {
                    attendance: 0,
                    labWork: 0,
                    openEndedProject: 0,
                    labExam: 0,
                    totalMarks: 0
                }
            });

            studentLogbooks.push(studentLogbook);
        }

        if (studentLogbooks.length > 0) {
            await StudentLogbook.insertMany(studentLogbooks);
        }

        res.json({
            success: true,
            message: `Assigned ${studentLogbooks.length} students to master logbook`,
            count: studentLogbooks.length,
            skipped: skippedStudents,
            skippedCount: skippedStudents.length
        });
    } catch (error) {
        console.error('Error assigning students:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==================== STUDENT LOGBOOK ENDPOINTS ====================

// Get Student Logbook by Roll Number
app.get('/api/logbook/student/roll/:rollno', authenticateToken, async (req, res) => {
    try {
        const rollno = parseInt(req.params.rollno);
        
        let studentLogbooks;
        if (req.user.role === 'faculty') {
            // Faculty can only see logbooks from their master templates
            const masterLogbooks = await MasterLogbook.find({ teacherRgno: req.user.rgno }).select('_id');
            const masterIds = masterLogbooks.map(m => m._id);
            studentLogbooks = await StudentLogbook.find({ rollno, masterLogbookId: { $in: masterIds } });
        } else {
            // Admin or student can see all
            studentLogbooks = await StudentLogbook.find({ rollno });
        }

        if (!studentLogbooks || studentLogbooks.length === 0) {
            return res.status(404).json({
                success: false,
                error: 'Student logbook not found'
            });
        }

        res.json({
            success: true,
            data: studentLogbooks.length === 1 ? studentLogbooks[0] : studentLogbooks
        });
    } catch (error) {
        console.error('Error fetching student logbook:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get Student Logbook by Register Number
app.get('/api/logbook/student/register/:rgno', authenticateToken, async (req, res) => {
    try {
        const rgno = parseInt(req.params.rgno);
        
        let studentLogbooks;
        if (req.user.role === 'faculty') {
            // Faculty can only see logbooks from their master templates
            const masterLogbooks = await MasterLogbook.find({ teacherRgno: req.user.rgno }).select('_id');
            const masterIds = masterLogbooks.map(m => m._id);
            studentLogbooks = await StudentLogbook.find({ rgno, masterLogbookId: { $in: masterIds } });
        } else {
            // Admin or student can see all
            studentLogbooks = await StudentLogbook.find({ rgno });
        }

        if (!studentLogbooks || studentLogbooks.length === 0) {
            return res.status(404).json({
                success: false,
                error: 'Student logbook not found'
            });
        }

        res.json({
            success: true,
            data: studentLogbooks.length === 1 ? studentLogbooks[0] : studentLogbooks
        });
    } catch (error) {
        console.error('Error fetching student logbook:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get My Logbooks (Students) - MUST come before /:id route
app.get('/api/logbook/student/my-logbooks', authenticateToken, async (req, res) => {
    try {
        console.log('Fetching logbooks for user:', req.user);
        
        if (!req.user || !req.user.rgno) {
            return res.status(400).json({
                success: false,
                error: 'User register number not found'
            });
        }

        const studentLogbooks = await StudentLogbook.find({ rgno: req.user.rgno }).sort({ createdAt: -1 });
        
        console.log(`Found ${studentLogbooks.length} logbooks for rgno ${req.user.rgno}`);

        res.json({
            success: true,
            count: studentLogbooks.length,
            data: studentLogbooks
        });
    } catch (error) {
        console.error('Error fetching student logbooks:', error);
        console.error('Stack trace:', error.stack);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get Single Student Logbook by ID
app.get('/api/logbook/student/:id', authenticateToken, async (req, res) => {
    try {
        let studentLogbook = await StudentLogbook.findById(req.params.id);

        if (!studentLogbook) {
            return res.status(404).json({
                success: false,
                error: 'Student logbook not found'
            });
        }

        // Authorization check
        console.log('Authorization check:', {
            userRole: req.user.role,
            userRgno: req.user.rgno,
            logbookRgno: studentLogbook.rgno
        });
        
        if (req.user.role === 'student' && req.user.rgno !== studentLogbook.rgno) {
            console.log('403 Forbidden: Student trying to access another student logbook');
            return res.status(403).json({
                success: false,
                error: 'You can only access your own logbook'
            });
        }

        // If student logbook has no experiments, try to sync from master
        if (!studentLogbook.experiments || studentLogbook.experiments.length === 0) {
            const masterLogbook = await MasterLogbook.findById(studentLogbook.masterLogbookId);
            if (masterLogbook && masterLogbook.experiments) {
                console.log(`Syncing ${masterLogbook.experiments.length} experiments from master to student`);
                studentLogbook.experiments = masterLogbook.experiments.map(exp => ({
                    slNo: exp.slNo,
                    experimentName: exp.experimentName,
                    co: exp.co,
                    date: '',
                    rubric1: 0,
                    rubric2: 0,
                    rubric3: 0,
                    rubric4: 0,
                    rubric5: 0,
                    total: 0,
                    studentSignature: false,
                    facultySignature: false
                }));
                await studentLogbook.save();
                console.log('Experiments synced and saved');
            }
        }

        res.json({
            success: true,
            data: studentLogbook
        });
    } catch (error) {
        console.error('Error fetching student logbook:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Update Student Logbook Marks (Teachers only)
app.put('/api/logbook/student/:id/marks', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'faculty' && req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                error: 'Only teachers can update marks'
            });
        }

        const sanitizedBody = sanitizeInput(req.body);
        const updatedLogbook = await StudentLogbook.findByIdAndUpdate(
            req.params.id,
            { ...sanitizedBody, updatedAt: Date.now() },
            { new: true }
        );

        if (!updatedLogbook) {
            return res.status(404).json({
                success: false,
                error: 'Student logbook not found'
            });
        }

        res.json({
            success: true,
            message: 'Marks updated successfully',
            data: updatedLogbook
        });
    } catch (error) {
        console.error('Error updating marks:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Update Verification (Students only)
app.put('/api/logbook/student/:id/verify', authenticateToken, async (req, res) => {
    try {
        const { type, index, date, verified } = sanitizeInput(req.body);
        const studentLogbook = await StudentLogbook.findById(req.params.id);

        if (!studentLogbook) {
            return res.status(404).json({
                success: false,
                error: 'Student logbook not found'
            });
        }

        if (req.user.role === 'student' && req.user.rgno !== studentLogbook.rgno) {
            return res.status(403).json({
                success: false,
                error: 'You can only verify your own logbook'
            });
        }

        // Update verification based on type
        if (type === 'experiment' && studentLogbook.experiments[index]) {
            studentLogbook.experiments[index].studentSignature = !!verified;
            if (date) studentLogbook.experiments[index].date = date;
        } else if (type === 'project' && studentLogbook.openEndedProject) {
            studentLogbook.openEndedProject.studentSignature = !!verified;
            if (date) studentLogbook.openEndedProject.date = date;
        } else if (type === 'exam' && studentLogbook.labExams[index]) {
            studentLogbook.labExams[index].studentSignature = !!verified;
            if (date) studentLogbook.labExams[index].date = date;
        }

        studentLogbook.updatedAt = Date.now();
        await studentLogbook.save();

        res.json({
            success: true,
            message: 'Verification updated',
            data: studentLogbook
        });
    } catch (error) {
        console.error('Error updating verification:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==================== OLD ENDPOINTS (Backward Compatibility) ====================

// Create or update log book entry
app.post('/api/logbook/create', authenticateToken, async (req, res) => {
    try {
        // Only students can create logbooks
        if (req.user.role !== 'student') {
            return res.status(403).json({
                success: false,
                error: 'Only students can create logbooks. Faculty can view and manage student logbooks.'
            });
        }
        
        // Sanitize input data
        const sanitizedBody = sanitizeInput(req.body);
        console.log('Received data from user:', req.user.rgno);
        
        // Validate required fields
        if (!sanitizedBody.name || !sanitizedBody.rollno || !sanitizedBody.rgno || !sanitizedBody.subject) {
            return res.status(400).json({
                success: false,
                error: 'Name, Roll Number, Register Number, and Subject are required'
            });
        }

        // Students can only create/update their own logbook
        if (parseInt(sanitizedBody.rgno) !== req.user.rgno) {
            return res.status(403).json({
                success: false,
                error: 'You can only edit your own logbook'
            });
        }
        
        // Parse experiments from form data
        const experiments = [];
        let expIndex = 1;
        while (sanitizedBody[`date${expIndex}`] || sanitizedBody[`experiment${expIndex}`]) {
            const rubricKey1 = `rubric${expIndex}-1`;
            const rubricVal1 = sanitizedBody[rubricKey1];
            console.log(`Parsing exp ${expIndex}: key="${rubricKey1}" value="${rubricVal1}"`);
            
            experiments.push({
                slNo: expIndex,
                date: sanitizedBody[`date${expIndex}`] || '',
                experimentName: sanitizedBody[`experiment${expIndex}`] || '',
                co: parseInt(sanitizedBody[`co${expIndex}`]) || 0,
                rubric1: parseInt(sanitizedBody[`rubric${expIndex}-1`]) || 0,
                rubric2: parseInt(sanitizedBody[`rubric${expIndex}-2`]) || 0,
                rubric3: parseInt(sanitizedBody[`rubric${expIndex}-3`]) || 0,
                rubric4: parseInt(sanitizedBody[`rubric${expIndex}-4`]) || 0,
                rubric5: parseInt(sanitizedBody[`rubric${expIndex}-5`]) || 0,
                total: parseInt(sanitizedBody[`total${expIndex}`]) || 0,
                studentSignature: sanitizedBody[`student${expIndex}`] === 'on',
                facultySignature: sanitizedBody[`faculty${expIndex}`] === 'on'
            });
            expIndex++;
        }
        
        // Parse lab exams
        const labExams = [];
        for (let i = 1; i <= 3; i++) {
            if (sanitizedBody[`t3date${i}`] || sanitizedBody[`exam${i}`]) {
                labExams.push({
                    slNo: i,
                    date: sanitizedBody[`t3date${i}`] || '',
                    examName: sanitizedBody[`exam${i}`] || `Lab Exam ${i}`,
                    co: parseInt(sanitizedBody[`t3co${i}`]) || 0,
                    rubric1: parseInt(sanitizedBody[`t3rubric${i}-1`]) || 0,
                    rubric2: parseInt(sanitizedBody[`t3rubric${i}-2`]) || 0,
                    rubric3: parseInt(sanitizedBody[`t3rubric${i}-3`]) || 0,
                    rubric4: parseInt(sanitizedBody[`t3rubric${i}-4`]) || 0,
                    rubric5: parseInt(sanitizedBody[`t3rubric${i}-5`]) || 0,
                    total: parseInt(sanitizedBody[`t3total${i}`]) || 0,
                    studentSignature: sanitizedBody[`t3student${i}`] === 'on',
                    facultySignature: sanitizedBody[`t3faculty${i}`] === 'on'
                });
            }
        }
        
        const newData = {
            name: sanitizedBody.name,
            rollno: parseInt(sanitizedBody.rollno),
            rgno: parseInt(sanitizedBody.rgno),
            subject: sanitizedBody.subject,
            code: sanitizedBody.code || '',
            semester: sanitizedBody.semester ? parseInt(sanitizedBody.semester) : null,
            experiments: experiments,
            openEndedProject: {
                date: sanitizedBody.t2date1 || '',
                projectName: sanitizedBody.t2experiment1 || '',
                co: parseInt(sanitizedBody.t2co1) || 0,
                rubric1: parseInt(sanitizedBody['t2rubric1-1']) || 0,
                rubric2: parseInt(sanitizedBody['t2rubric1-2']) || 0,
                rubric3: parseInt(sanitizedBody['t2rubric1-3']) || 0,
                rubric4: parseInt(sanitizedBody['t2rubric1-4']) || 0,
                rubric5: parseInt(sanitizedBody['t2rubric1-5']) || 0,
                total: parseInt(sanitizedBody.t2total1) || 0,
                studentSignature: sanitizedBody.t2student1 === 'on',
                facultySignature: sanitizedBody.t2faculty1 === 'on'
            },
            labExams: labExams,
            finalAssessment: {
                attendance: parseFloat(req.body.final1) || 0,
                labWork: parseFloat(req.body.final2) || 0,
                openEndedProject: parseFloat(req.body.final3) || 0,
                labExam: parseFloat(req.body.final4) || 0,
                totalMarks: parseFloat(req.body.final5) || 0
            },
            updatedAt: new Date()
        };
        
        // Check if logbook exists for this student and subject
        const existing = await LogBook.findOne({ 
            rollno: newData.rollno,
            rgno: newData.rgno,
            subject: newData.subject
        });
        
        let result;
        if (existing) {
            // Smart merge: only update fields with actual values
            
            // Update name if provided
            if (newData.name) existing.name = newData.name;
            
            // Merge experiments - keep existing, add/update only filled ones
            const existingExps = existing.experiments || [];
            newData.experiments.forEach(newExp => {
                const existingExp = existingExps.find(e => e.slNo === newExp.slNo);
                if (existingExp) {
                    // Update existing experiment only if new fields have values
                    if (newExp.date) existingExp.date = newExp.date;
                    if (newExp.experimentName) existingExp.experimentName = newExp.experimentName;
                    if (newExp.co) existingExp.co = newExp.co;
                    if (newExp.rubric1) existingExp.rubric1 = newExp.rubric1;
                    if (newExp.rubric2) existingExp.rubric2 = newExp.rubric2;
                    if (newExp.rubric3) existingExp.rubric3 = newExp.rubric3;
                    if (newExp.rubric4) existingExp.rubric4 = newExp.rubric4;
                    if (newExp.rubric5) existingExp.rubric5 = newExp.rubric5;
                    if (newExp.total) existingExp.total = newExp.total;
                    if (newExp.studentSignature !== undefined) existingExp.studentSignature = newExp.studentSignature;
                    if (newExp.facultySignature !== undefined) existingExp.facultySignature = newExp.facultySignature;
                } else if (newExp.date || newExp.experimentName) {
                    // Add new experiment only if it has some data
                    existingExps.push(newExp);
                }
            });
            existing.experiments = existingExps;
            
            // Merge open-ended project
            if (!existing.openEndedProject) existing.openEndedProject = {};
            if (newData.openEndedProject.date) existing.openEndedProject.date = newData.openEndedProject.date;
            if (newData.openEndedProject.projectName) existing.openEndedProject.projectName = newData.openEndedProject.projectName;
            if (newData.openEndedProject.co) existing.openEndedProject.co = newData.openEndedProject.co;
            if (newData.openEndedProject.rubric1) existing.openEndedProject.rubric1 = newData.openEndedProject.rubric1;
            if (newData.openEndedProject.rubric2) existing.openEndedProject.rubric2 = newData.openEndedProject.rubric2;
            if (newData.openEndedProject.rubric3) existing.openEndedProject.rubric3 = newData.openEndedProject.rubric3;
            if (newData.openEndedProject.rubric4) existing.openEndedProject.rubric4 = newData.openEndedProject.rubric4;
            if (newData.openEndedProject.rubric5) existing.openEndedProject.rubric5 = newData.openEndedProject.rubric5;
            if (newData.openEndedProject.total) existing.openEndedProject.total = newData.openEndedProject.total;
            
            // Merge lab exams
            const existingExams = existing.labExams || [];
            newData.labExams.forEach(newExam => {
                const existingExam = existingExams.find(e => e.slNo === newExam.slNo);
                if (existingExam) {
                    if (newExam.date) existingExam.date = newExam.date;
                    if (newExam.examName) existingExam.examName = newExam.examName;
                    if (newExam.co) existingExam.co = newExam.co;
                    if (newExam.rubric1) existingExam.rubric1 = newExam.rubric1;
                    if (newExam.rubric2) existingExam.rubric2 = newExam.rubric2;
                    if (newExam.rubric3) existingExam.rubric3 = newExam.rubric3;
                    if (newExam.rubric4) existingExam.rubric4 = newExam.rubric4;
                    if (newExam.rubric5) existingExam.rubric5 = newExam.rubric5;
                    if (newExam.total) existingExam.total = newExam.total;
                } else if (newExam.date || newExam.examName) {
                    existingExams.push(newExam);
                }
            });
            existing.labExams = existingExams;
            
            // Merge final assessment
            if (!existing.finalAssessment) existing.finalAssessment = {};
            if (newData.finalAssessment.attendance) existing.finalAssessment.attendance = newData.finalAssessment.attendance;
            if (newData.finalAssessment.labWork) existing.finalAssessment.labWork = newData.finalAssessment.labWork;
            if (newData.finalAssessment.openEndedProject) existing.finalAssessment.openEndedProject = newData.finalAssessment.openEndedProject;
            if (newData.finalAssessment.labExam) existing.finalAssessment.labExam = newData.finalAssessment.labExam;
            if (newData.finalAssessment.totalMarks) existing.finalAssessment.totalMarks = newData.finalAssessment.totalMarks;
            
            existing.updatedAt = new Date();
            result = await existing.save();
            console.log('Updated log book (smart merge):', result._id);
            res.json({ success: true, message: 'Log book updated successfully', id: result._id, isUpdate: true });
        } else {
            // Create new record
            const logBook = new LogBook(newData);
            result = await logBook.save();
            console.log('Created new log book:', result._id);
            res.json({ success: true, message: 'Log book saved successfully', id: result._id, isUpdate: false });
        }
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get all log books (Faculty/Admin only)
app.get('/api/logbook/all', authenticateToken, async (req, res) => {
    try {
        // Only faculty and admin can view logbooks
        if (req.user.role === 'student') {
            return res.status(403).json({ 
                success: false, 
                error: 'Students can only view their own logbook' 
            });
        }

        let studentLogbooks = [];
        let oldLogBooks = [];

        if (req.user.role === 'faculty') {
            // Faculty can only see logbooks from master templates they created
            const masterLogbooks = await MasterLogbook.find({ teacherRgno: req.user.rgno }).select('_id');
            const masterIds = masterLogbooks.map(m => m._id);
            
            studentLogbooks = await StudentLogbook.find({ masterLogbookId: { $in: masterIds } }).sort({ createdAt: -1 });
            oldLogBooks = await LogBook.find({ teacherRgno: req.user.rgno }).sort({ createdAt: -1 });
        } else {
            // Admin can see all logbooks
            studentLogbooks = await StudentLogbook.find().sort({ createdAt: -1 });
            oldLogBooks = await LogBook.find().sort({ createdAt: -1 });
        }

        const allBooks = [...studentLogbooks, ...oldLogBooks];
        
        res.json({ success: true, count: allBooks.length, data: allBooks });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get logbooks for authenticated student (must be before :id route)
app.get('/api/logbook/my-logbooks', authenticateToken, async (req, res) => {
    try {
        // Get all logbooks for the authenticated student
        const logBooks = await LogBook.find({ rgno: req.user.rgno }).sort({ createdAt: -1 });
        console.log(`Student ${req.user.rgno} has ${logBooks.length} logbooks`);
        res.json({ 
            success: true, 
            count: logBooks.length, 
            data: logBooks
        });
    } catch (error) {
        console.error('Error fetching logbooks:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get by ID (Faculty/Admin only or own student logbook)
app.get('/api/logbook/:id', authenticateToken, async (req, res) => {
    try {
        const logBook = await LogBook.findById(req.params.id);
        if (!logBook) return res.status(404).json({ success: false, error: 'Not found' });
        
        // Students can only view their own logbook
        if (req.user.role === 'student' && logBook.rgno !== req.user.rgno) {
            return res.status(403).json({ 
                success: false, 
                error: 'You can only view your own logbook' 
            });
        }
        
        res.json({ success: true, data: logBook });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get by roll number (Faculty/Admin only or own student)
app.get('/api/logbook/roll/:rollno', authenticateToken, async (req, res) => {
    try {
        // Faculty and Admin can view any roll number
        // Students can only view their own
        if (req.user.role === 'student') {
            return res.status(403).json({ 
                success: false, 
                error: 'Students can only view their own logbook' 
            });
        }

        const rollno = parseInt(req.params.rollno);
        
        let logBooks;
        if (req.user.role === 'faculty') {
            logBooks = await LogBook.find({ rollno: rollno, teacherRgno: req.user.rgno }).sort({ createdAt: -1 });
        } else {
            logBooks = await LogBook.find({ rollno: rollno }).sort({ createdAt: -1 });
        }
        
        console.log(`Finding by roll ${rollno}: found ${logBooks.length} records`);
        res.json({ success: true, count: logBooks.length, data: logBooks });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get by register number (Faculty/Admin only or own student)
app.get('/api/logbook/register/:rgno', authenticateToken, async (req, res) => {
    try {
        const rgno = parseInt(req.params.rgno);
        
        // Students can only view their own logbooks
        if (req.user.role === 'student' && rgno !== req.user.rgno) {
            return res.status(403).json({ 
                success: false, 
                error: 'You can only view your own logbooks' 
            });
        }

        // Get all logbooks for this student (multiple subjects)
        let logBooks;
        if (req.user.role === 'faculty') {
            logBooks = await LogBook.find({ rgno: rgno, teacherRgno: req.user.rgno }).sort({ createdAt: -1 });
        } else {
            logBooks = await LogBook.find({ rgno: rgno }).sort({ createdAt: -1 });
        }
        
        console.log(`Finding logbooks for register ${rgno}: found ${logBooks.length} records (user role: ${req.user.role})`);
        res.json({ success: true, count: logBooks.length, data: logBooks });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Delete by ID
app.delete('/api/logbook/master/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'faculty' && req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                error: 'Only teachers can delete master templates'
            });
        }

        const masterId = req.params.id;
        const masterLogbook = await MasterLogbook.findById(masterId);

        if (!masterLogbook) {
            return res.status(404).json({
                success: false,
                error: 'Master template not found'
            });
        }

        // Verify that the teacher owns this template
        if (masterLogbook.teacherRgno !== req.user.rgno) {
            return res.status(403).json({
                success: false,
                error: 'You can only delete your own templates'
            });
        }

        // Delete the master logbook and all associated student logbooks
        await MasterLogbook.findByIdAndDelete(masterId);
        await StudentLogbook.deleteMany({ masterLogbookId: masterId });

        res.json({
            success: true,
            message: 'Template and all associated student logbooks deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting master template:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.delete('/api/logbook/:id', async (req, res) => {
    try {
        const logBook = await LogBook.findByIdAndDelete(req.params.id);
        if (!logBook) return res.status(404).json({ success: false, error: 'Not found' });
        res.json({ success: true, message: 'Deleted successfully' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Cascade delete all templates and student logbooks created by a teacher
// Called when a faculty account is deleted
app.delete('/api/logbook/cascade-delete-by-teacher', authenticateToken, async (req, res) => {
    try {
        const { teacherRgno } = req.body;
        
        if (!teacherRgno) {
            return res.status(400).json({ success: false, error: 'Teacher register number required' });
        }
        
        // Find all master templates created by this teacher
        const masterTemplates = await MasterLogbook.find({ teacherRgno: teacherRgno });
        const masterIds = masterTemplates.map(m => m._id);
        
        // Delete all student logbooks associated with these templates
        const studentLogbooksDeleted = await StudentLogbook.deleteMany({ 
            masterLogbookId: { $in: masterIds } 
        });
        
        // Delete all master templates
        const templatesDeleted = await MasterLogbook.deleteMany({ teacherRgno: teacherRgno });
        
        console.log(`[CASCADE DELETE] Teacher ${teacherRgno}: Deleted ${templatesDeleted.deletedCount} templates, ${studentLogbooksDeleted.deletedCount} student logbooks`);
        
        res.json({
            success: true,
            message: 'All templates and student logbooks deleted',
            templatesDeleted: templatesDeleted.deletedCount,
            studentLogbooksDeleted: studentLogbooksDeleted.deletedCount
        });
    } catch (error) {
        console.error('[CASCADE DELETE] Error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Delete all logbooks for a specific student (when student account is deleted)
app.delete('/api/logbook/delete-by-student', authenticateToken, async (req, res) => {
    try {
        const { studentRgno } = req.body;
        
        if (!studentRgno) {
            return res.status(400).json({ success: false, error: 'Student register number required' });
        }
        
        // Delete all student logbooks for this student
        const result = await StudentLogbook.deleteMany({ rgno: studentRgno });
        
        console.log(`[DELETE STUDENT LOGBOOKS] Student ${studentRgno}: Deleted ${result.deletedCount} logbooks`);
        
        res.json({
            success: true,
            message: 'All student logbooks deleted',
            deletedCount: result.deletedCount
        });
    } catch (error) {
        console.error('[DELETE STUDENT LOGBOOKS] Error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Health check for Render/uptime monitors
app.get('/health', (req, res) => {
    res.json({ status: 'Logbook Server OK', port: PORT });
});

app.listen(PORT, () => console.log(`Log Book Server running on port ${PORT}\nDatabase: LOGI`));
