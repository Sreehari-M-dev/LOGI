// Load environment variables from .env for local development
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const cors = require('cors');
const nodemailer = require('nodemailer');

// Bcrypt configuration
const BCRYPT_SALT_ROUNDS = 12;

const app = express();
const PORT = process.env.PORT || process.env.AUTH_SERVICE_PORT || 3002;
const JWT_SECRET = process.env.JWT_SECRET;

// Multi-cluster MongoDB URIs (2 clusters: AUTH + LOGBOOK)
const MONGODB_URI_AUTH = process.env.MONGODB_URI_AUTH || process.env.MONGODB_URI || 'mongodb://localhost:27017/logi_auth';

// Debug: Log environment variable status at startup
console.log('🔧 Environment Check:');
console.log('   MONGODB_URI_AUTH:', process.env.MONGODB_URI_AUTH ? '✅ SET' : '❌ NOT SET (using fallback)');
console.log('   MONGODB_URI:', process.env.MONGODB_URI ? '✅ SET' : '❌ NOT SET');
console.log('   JWT_SECRET:', process.env.JWT_SECRET ? '✅ SET' : '❌ NOT SET');
console.log('   NODE_ENV:', process.env.NODE_ENV || 'not set');
console.log('   Using URI:', MONGODB_URI_AUTH.includes('localhost') ? 'localhost (DEFAULT - CHECK ENV!)' : MONGODB_URI_AUTH.replace(/\/\/[^:]+:[^@]+@/, '//<credentials>@'));

const JWT_EXPIRY = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds
const IDLE_TIMEOUT_MS = parseInt(process.env.IDLE_TIMEOUT_MS || '600000'); // 10 minutes default (600,000 ms)
const TOUCH_INTERVAL_MS = 60000; // update lastActivity at most once per minute

// Log the actual timeout being used
console.log(`⏱️ Session idle timeout: ${IDLE_TIMEOUT_MS / 1000 / 60} minutes (${IDLE_TIMEOUT_MS}ms)`);

// Require a secret before starting
if (!JWT_SECRET) {
    console.error('JWT_SECRET is not set. Please define it in the environment.');
    process.exit(1);
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
        'http://10.196.162.19',
        'http://10.154.126.1:5000'

    ];

// Log requests - skip health checks and preflight to reduce noise in production
app.use((req, res, next) => {
    // Skip logging for health checks and OPTIONS preflight (too noisy)
    if (req.path === '/health' || req.method === 'OPTIONS') {
        return next();
    }
    console.log(`[REQUEST] ${req.method} ${req.path}`);
    // Only log headers in development for debugging
    if (process.env.NODE_ENV !== 'production') {
        console.log(`[HEADERS] Origin: ${req.headers.origin}, Host: ${req.headers.host}`);
    }
    next();
});

app.use(cors({
    origin: function(origin, callback) {
        // Skip logging for allowed origins in production (too noisy)
        if (!origin) {
            return callback(null, true);
        }
        if (allowedOrigins.includes(origin)) {
            return callback(null, true);
        }
        // Only log rejected origins
        console.log(`[CORS] Origin ${origin} is NOT allowed`);
        return callback(new Error('Not allowed by CORS'));
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: false,
    maxAge: 86400
}));
app.use(express.json());

// ==================== MULTI-CLUSTER MONGODB CONNECTIONS ====================

// Create separate connections for AUTH and META clusters
// Note: useNewUrlParser and useUnifiedTopology are deprecated in MongoDB Driver 4.0+ (removed)
const authConnection = mongoose.createConnection(MONGODB_URI_AUTH);

authConnection.on('connected', () => {
    console.log('✅ Connected to MongoDB AUTH cluster');
});

authConnection.on('error', (err) => {
    console.error('❌ MongoDB AUTH cluster error:', err.message);
});

// User Schema - using Register Number (rgno) as unique identifier with college scoping
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true }, // Unique email for password reset flow
    rollno: { type: Number }, // For students only - not stored for other roles
    rgno: { type: Number, required: true, unique: true }, // Unique identifier (Register Number)
    password: { type: String, required: true }, // Hashed
    role: { type: String, enum: ['student', 'faculty', 'hod', 'principal', 'super-admin'], default: 'student' },
    department: String,
    semester: Number, // For students only
    college: { type: String, required: true }, // College name - required for all users
    createdAt: { type: Date, default: Date.now },
    isActive: { type: Boolean, default: true },
    // Approval workflow fields
    approvalStatus: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    approvedAt: { type: Date },
    rejectionReason: { type: String },
    // Password reset fields - only set when password reset is requested
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date },
    // Super-admin 2FA fields - ONLY set for super-admin users (not created for others)
    twoFactorSecret: { type: String },
    twoFactorEnabled: { type: Boolean },
    twoFactorBackupCodes: [{ code: String, used: { type: Boolean, default: false } }],
    // Navbar customization - ONLY set for principal/super-admin when they customize
    navbarPreferences: {
        type: {
            home: { type: Boolean },
            logbook: { type: Boolean },
            resources: { type: Boolean },
            about: { type: Boolean },
            profile: { type: Boolean },
            masterTemplates: { type: Boolean },
            viewLogbooks: { type: Boolean },
            admin: { type: Boolean }
        }
    },
    lastLoginAt: { type: Date },
    lastLoginIP: { type: String },
    failedLoginAttempts: { type: Number, default: 0 },
    lockoutUntil: { type: Date },
    // Account freeze (requires admin to unfreeze)
    accountFrozen: { type: Boolean },
    frozenAt: { type: Date },
    frozenReason: { type: String },
    unfrozenBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    unfrozenAt: { type: Date },
    // Super-admin succession invitation fields (invitation-based transfer)
    superAdminInviteToken: { type: String }, // Secure token for invitation
    superAdminInviteExpires: { type: Date }, // 24-hour expiry
    superAdminInviteAccepted: { type: Boolean }, // User accepted the invitation
    superAdminInviteAcceptedAt: { type: Date },
    superAdminInvitedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Who invited this user
    // Transfer completion fields
    superAdminTransferPendingCompletion: { type: Boolean }, // Waiting for super-admin to complete
    superAdminTransferGracePeriodEnds: { type: Date }, // 24-hour grace period after completion
    previousRole: { type: String }, // Store previous role before becoming super-admin
    previousCollege: { type: String }, // Store previous college before becoming super-admin
    previousDepartment: { type: String }, // Store previous department before becoming super-admin
    demotedFromSuperAdmin: { type: Boolean }, // Flag to track if user was demoted from super-admin
    demotedAt: { type: Date },
    // Email verification fields
    emailVerified: { type: Boolean, default: false }, // Whether email is verified
    emailVerificationToken: { type: String }, // Token for verification link
    emailVerificationExpires: { type: Date }, // Token expiry (24 hours)
    emailVerificationSentAt: { type: Date }, // When verification email was last sent
    // Admin password reset - forces user to change password on next login
    mustChangePassword: { type: Boolean, default: false }, // Set by admin reset
    passwordResetByAdmin: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Who reset it
    passwordResetByAdminAt: { type: Date } // When admin reset it
}, {
    // Mongoose options to minimize storage
    minimize: true, // Remove empty objects
    versionKey: false // Remove __v field (saves ~10 bytes per doc)
});

// Index for college-scoped queries
userSchema.index({ college: 1, role: 1 });
userSchema.index({ college: 1, department: 1 });
userSchema.index({ approvalStatus: 1, college: 1 });

// Register User model on AUTH connection
const User = authConnection.model('User', userSchema);

// Audit Log Schema for super-admin actions (stored in META cluster)
const auditLogSchema = new mongoose.Schema({
    action: { type: String, required: true }, // e.g., 'USER_APPROVED', 'USER_DELETED', 'SESSION_REVOKED'
    performedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    performedByRgno: { type: Number, required: true },
    performedByRole: { type: String, required: true },
    targetUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    targetUserRgno: { type: Number },
    details: { type: mongoose.Schema.Types.Mixed }, // Additional details
    ipAddress: { type: String },
    userAgent: { type: String },
    timestamp: { type: Date, default: Date.now }
});

auditLogSchema.index({ timestamp: -1 });
auditLogSchema.index({ performedBy: 1, timestamp: -1 });
auditLogSchema.index({ action: 1, timestamp: -1 });

// Register AuditLog model on AUTH connection (same cluster as Users)
const AuditLog = authConnection.model('AuditLog', auditLogSchema);

// Helper function to create audit log
async function createAuditLog(action, performedBy, targetUser, details, req) {
    try {
        await new AuditLog({
            action,
            performedBy: performedBy._id || performedBy,
            performedByRgno: performedBy.rgno || performedBy,
            performedByRole: performedBy.role || 'unknown',
            targetUser: targetUser?._id || targetUser,
            targetUserRgno: targetUser?.rgno,
            details,
            ipAddress: req?.ip || req?.headers?.['x-forwarded-for'] || 'unknown',
            userAgent: req?.headers?.['user-agent'] || 'unknown'
        }).save();
    } catch (error) {
        console.error('[AUDIT LOG] Error creating audit log:', error);
    }
}

// List of valid colleges (for validation) - organized by district
const VALID_COLLEGES = [
    // SYSTEM (for super-admin)
    "SYSTEM",
    // THIRUVANANTHAPURAM DISTRICT
    "Central Polytechnic College, Thiruvananthapuram",
    "Government Women's Polytechnic College, Thiruvananthapuram",
    "Government Polytechnic College, Neyyattinkara",
    "Government Polytechnic College, Nedumangad",
    "Government Polytechnic College, Attingal",
    // KOLLAM DISTRICT
    "Government Polytechnic College, Punalur",
    "Government Polytechnic College, Ezhukone",
    "Sree Narayana Polytechnic College, Kottiyam",
    // PATHANAMTHITTA DISTRICT
    "MVGM Government Polytechnic College, Vennikulam",
    "Government Polytechnic College, Vechoochira",
    "Government Polytechnic College, Manakala (Adoor)",
    "N S S Polytechnic College, Pandalam",
    // ALAPPUZHA DISTRICT
    "Government Polytechnic College, Cherthala",
    "Government Women's Polytechnic College, Kayamkulam",
    "Carmel Polytechnic College, Alappuzha",
    // KOTTAYAM DISTRICT
    "Government Polytechnic College, Kottayam",
    "Government Polytechnic College, Pala",
    "Government Polytechnic College, Kaduthuruthy",
    "Thiagarajar Polytechnic College, Alagappanagar",
    // IDUKKI DISTRICT
    "Government Polytechnic College, Muttom Idukki",
    "Government Polytechnic College, Vandiperiyar",
    "Government Polytechnic College, Nedumkandam",
    "Government Polytechnic College, Purappuzha",
    // ERNAKULAM DISTRICT
    "Government Polytechnic College, Kalamassery",
    "Women's Polytechnic College, Ernakulam",
    "Government Polytechnic College, Kothamangalam",
    "Government Polytechnic College, Perumbavoor",
    // THRISSUR DISTRICT
    "Maharaja's Technological Institute, Thrissur",
    "Government Women's Polytechnic College, Thrissur",
    "Government Polytechnic College, Chelakkara",
    "Government Polytechnic College, Kunnamkulam",
    "Government Polytechnic College, Koratty",
    "Sree Rama Government Polytechnic College, Thriprayar",
    // PALAKKAD DISTRICT
    "Government Polytechnic College, Palakkad",
    "Institute of Printing Technology and Government Polytechnic College, Shoranur",
    // MALAPPURAM DISTRICT
    "Government Polytechnic College, Perinthalmanna",
    "AKNM Government Polytechnic College, Thirurangadi",
    "Government Women's Polytechnic College, Kottakkal",
    "Government Polytechnic College, Manjeri",
    "Seethi Sahib Memorial Polytechnic College, Tirur",
    // KOZHIKODE DISTRICT
    "Kerala Government Polytechnic College, Kozhikode",
    "Government Women's Polytechnic College, Kozhikode",
    // WAYANAD DISTRICT
    "Government Polytechnic College, Meenangadi",
    "Government Polytechnic College, Meppadi",
    "Government Polytechnic College, Mananthavady",
    // KANNUR DISTRICT
    "Government Polytechnic College, Kannur (Thottada)",
    "Government Polytechnic College, Mattannur",
    "Government Residential Women's Polytechnic College, Payyannur",
    "Government Technical High School, Naduvil",
    // KASARAGOD DISTRICT
    "Government Polytechnic College, Kasaragod",
    "EKNM Government Polytechnic College, Trikaripur",
    "Swami Nithyananda Polytechnic, Kanhangad"
];

// Session Schema for idle timeout and server-side session tracking
const sessionSchema = new mongoose.Schema({
    sid: { type: String, required: true, unique: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    rgno: { type: Number, required: true },
    role: { type: String, required: true },
    lastActivity: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now },
    expiredAt: { type: Date },
    isExpired: { type: Boolean, default: false },
    stayLoggedIn: { type: Boolean, default: false }, // If true, skip idle timeout but still expire after 7 days
    stayLoggedInExpiry: { type: Date } // Expiry date for stay logged in sessions (7 days from creation)
});

// Register Session model on AUTH connection
const Session = authConnection.model('Session', sessionSchema);

// Constants for session management
const STAY_LOGGED_IN_DURATION_MS = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds

// Secure password hashing using bcrypt
async function hashPassword(password) {
    return await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
}

// Verify password using bcrypt
async function verifyPassword(password, hash) {
    // Handle legacy SHA-256 hashes (64 hex chars) vs bcrypt hashes (start with $2)
    if (hash && !hash.startsWith('$2')) {
        // Legacy SHA-256 hash - compare using old method for migration
        const legacyHash = crypto.createHash('sha256').update(password + JWT_SECRET).digest('hex');
        return legacyHash === hash;
    }
    return await bcrypt.compare(password, hash);
}

// Simple JWT token generation (without external library)
function generateToken(userId, rgno, role, sid) {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64');
    const now = Math.floor(Date.now() / 1000);
    const payload = {
        userId: userId.toString(),
        rgno: rgno,
        role: role,
        sid: sid,
        iat: now,
        exp: now + (7 * 24 * 60 * 60) // 7 days
    };
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64');
    const signature = crypto
        .createHmac('sha256', JWT_SECRET)
        .update(`${header}.${encodedPayload}`)
        .digest('base64');
    
    return `${header}.${encodedPayload}.${signature}`;
}
// Shared session lookup helper
async function findActiveSession(token) {
    if (!token) return { error: 'No token provided' };
    const decoded = verifyToken(token);
    if (!decoded || !decoded.sid) return { error: 'Invalid token' };

    const session = await Session.findOne({ sid: decoded.sid });
    if (!session || session.isExpired) return { error: 'Session expired. Please login again.' };

    return { session, decoded };
}

// Middleware to authenticate and enforce idle timeout using sessions (touches lastActivity)
async function authenticateAndTouchSession(req, res, next) {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const result = await findActiveSession(token);
        if (result.error) return res.status(401).json({ success: false, error: result.error });
        const { session, decoded } = result;

        // Super-admin is exempt from idle timeout
        const isSuperAdmin = session.role === 'super-admin';
        
        const now = Date.now();
        const last = session.lastActivity ? session.lastActivity.getTime() : session.createdAt.getTime();
        
        // Check 7-day expiry for "stay logged in" sessions (not for super-admin)
        if (!isSuperAdmin && session.stayLoggedIn && session.stayLoggedInExpiry) {
            if (now > session.stayLoggedInExpiry.getTime()) {
                session.isExpired = true;
                session.expiredAt = new Date(now);
                await session.save();
                return res.status(401).json({ success: false, error: 'Your session has expired after 7 days. Please login again.' });
            }
        }
        
        // Skip idle timeout check for super-admin OR if "stay logged in" is enabled
        const skipIdleTimeout = isSuperAdmin || session.stayLoggedIn;
        if (!skipIdleTimeout && now - last > IDLE_TIMEOUT_MS) {
            session.isExpired = true;
            session.expiredAt = new Date(now);
            await session.save();
            return res.status(401).json({ success: false, error: 'Session expired due to inactivity. Please login again.' });
        }

        // Update last activity (sliding window) with throttling to reduce writes
        if (now - last > TOUCH_INTERVAL_MS) {
            session.lastActivity = new Date(now);
            await session.save();
        }

        req.auth = { decoded, session };
        next();
    } catch (error) {
        console.error('Session auth error:', error);
        return res.status(401).json({ success: false, error: 'Authentication failed' });
    }
}

// Middleware to authenticate session without updating lastActivity (for read-only remaining time)
async function authenticateSessionNoTouch(req, res, next) {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const result = await findActiveSession(token);
        if (result.error) return res.status(401).json({ success: false, error: result.error });

        const { session, decoded } = result;
        
        // Super-admin OR "stay logged in" is exempt from idle timeout
        const skipIdleTimeout = session.role === 'super-admin' || session.stayLoggedIn;
        
        const now = Date.now();
        const last = session.lastActivity ? session.lastActivity.getTime() : session.createdAt.getTime();

        // If already expired by idle window (skip for super-admin or stay logged in)
        if (!skipIdleTimeout && now - last > IDLE_TIMEOUT_MS) {
            session.isExpired = true;
            session.expiredAt = new Date(now);
            await session.save();
            return res.status(401).json({ success: false, error: 'Session expired due to inactivity. Please login again.' });
        }

        req.auth = { decoded, session };
        next();
    } catch (error) {
        console.error('Session auth error (no touch):', error);
        return res.status(401).json({ success: false, error: 'Authentication failed' });
    }
}


// Verify JWT token
function verifyToken(token) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;
        
        const [header, payload, signature] = parts;
        const expectedSignature = crypto
            .createHmac('sha256', JWT_SECRET)
            .update(`${header}.${payload}`)
            .digest('base64');
        
        if (signature !== expectedSignature) return null;
        
        const decodedPayload = JSON.parse(Buffer.from(payload, 'base64').toString());
        const now = Math.floor(Date.now() / 1000);
        
        if (decodedPayload.exp < now) return null; // Token expired
        
        return decodedPayload;
    } catch (error) {
        return null;
    }
}

// Register Route - using Register Number with college scoping and approval workflow
app.post('/api/auth/register', async (req, res) => {
    try {
        // Normalize and trim incoming fields
        const name = req.body.name?.trim();
        const email = req.body.email?.trim().toLowerCase();
        const password = req.body.password?.trim();
        const rgnoRaw = req.body.rgno;
        const rollnoRaw = req.body.rollno;
        const role = req.body.role?.trim();
        const department = req.body.department?.trim();
        const semesterRaw = req.body.semester;
        const college = req.body.college?.trim();

        const rgno = rgnoRaw !== undefined && rgnoRaw !== null && rgnoRaw !== '' ? parseInt(rgnoRaw, 10) : null;
        const rollno = rollnoRaw !== undefined && rollnoRaw !== null && rollnoRaw !== '' ? parseInt(rollnoRaw, 10) : null;
        const semester = semesterRaw !== undefined && semesterRaw !== null && semesterRaw !== '' ? parseInt(semesterRaw, 10) : null;

        // Validation - rgno and college are required
        if (!name || !rgno || !password) {
            return res.status(400).json({ 
                success: false, 
                error: 'Name, register number, and password are required' 
            });
        }
        
        // Email is REQUIRED for all registrations
        if (!email) {
            return res.status(400).json({ 
                success: false, 
                error: 'Email address is required for registration' 
            });
        }
        
        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ 
                success: false, 
                error: 'Please enter a valid email address' 
            });
        }
        
        // College is required
        if (!college) {
            return res.status(400).json({ 
                success: false, 
                error: 'College selection is required' 
            });
        }
        
        // Validate college is in the allowed list
        if (!VALID_COLLEGES.includes(college)) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid college selected' 
            });
        }
        
        // Validate role
        const validRoles = ['student', 'faculty', 'hod', 'principal'];
        if (role && !validRoles.includes(role)) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid role selected' 
            });
        }
        
        // Validate department - "Office Administration" is only for principals
        if (department && department.toLowerCase() === 'office administration' && role !== 'principal') {
            return res.status(400).json({ 
                success: false, 
                error: 'Office Administration department is only available for principals.' 
            });
        }
        
        // HOD must select a department (not Office Administration)
        if (role === 'hod') {
            if (!department || department.toLowerCase() === 'office administration') {
                return res.status(400).json({ 
                    success: false, 
                    error: 'HOD must select a valid department (not Office Administration).' 
                });
            }
        }
        
        // Strong password validation
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).json({ 
                success: false, 
                error: 'Password must be at least 8 characters and include: uppercase letter, lowercase letter, number, and special symbol (!@#$%^&*...)' 
            });
        }
        
        // For students: Check if there's an approved faculty in the same college/department
        if (role === 'student') {
            const approvedFaculty = await User.findOne({
                college: college,
                role: 'faculty',
                approvalStatus: 'approved',
                isActive: true,
                ...(department ? { department: department } : {})
            });
            
            if (!approvedFaculty) {
                return res.status(400).json({ 
                    success: false, 
                    error: 'No approved faculty found for your college/department. A faculty member must be registered and approved first.' 
                });
            }
        }
        
        // For faculty: Check if there's an approved HOD in the same college/department
        if (role === 'faculty') {
            const approvedHOD = await User.findOne({
                college: college,
                role: 'hod',
                department: department,
                approvalStatus: 'approved',
                isActive: true
            });
            
            if (!approvedHOD) {
                return res.status(400).json({ 
                    success: false, 
                    error: 'No approved HOD found for your department. An HOD must be registered and approved first.' 
                });
            }
        }
        
        // For HOD: Check if there's an approved principal in the same college
        if (role === 'hod') {
            const approvedPrincipal = await User.findOne({
                college: college,
                role: 'principal',
                approvalStatus: 'approved',
                isActive: true
            });
            
            if (!approvedPrincipal) {
                return res.status(400).json({ 
                    success: false, 
                    error: 'No approved principal found for your college. A principal must be registered and approved first.' 
                });
            }
        }
        
        // For HOD: Check if there's already an HOD for this department in this college (only one allowed)
        if (role === 'hod') {
            const existingHOD = await User.findOne({
                college: college,
                role: 'hod',
                department: department,
                approvalStatus: { $in: ['pending', 'approved'] },
                isActive: true
            });
            
            if (existingHOD) {
                const statusMsg = existingHOD.approvalStatus === 'approved' 
                    ? 'An HOD is already registered and approved for this department.'
                    : 'An HOD registration is already pending for this department.';
                return res.status(409).json({ 
                    success: false, 
                    error: `${statusMsg} Only one HOD is allowed per department per college.`
                });
            }
        }
        
        // For principal: Check if there's already a principal for this college (only one allowed)
        if (role === 'principal') {
            const existingPrincipal = await User.findOne({
                college: college,
                role: 'principal',
                approvalStatus: { $in: ['pending', 'approved'] },
                isActive: true
            });
            
            if (existingPrincipal) {
                const statusMsg = existingPrincipal.approvalStatus === 'approved' 
                    ? 'A principal is already registered and approved for this college.'
                    : 'A principal registration is already pending for this college.';
                return res.status(409).json({ 
                    success: false, 
                    error: `${statusMsg} Only one principal is allowed per college. If the previous principal has transferred, please contact them to transfer the account credentials or ask the super-admin to remove the old account.`
                });
            }
        }

        // Check if user already exists by register number
        const existingUser = await User.findOne({ rgno });
        if (existingUser) {
            // If the existing user was rejected, allow re-registration by deleting the old account
            if (existingUser.approvalStatus === 'rejected') {
                console.log(`Deleting rejected account for rgno ${rgno} to allow re-registration`);
                await User.deleteOne({ _id: existingUser._id });
                // Also delete any sessions for this user
                await Session.deleteMany({ userId: existingUser._id });
            } else {
                return res.status(409).json({ 
                    success: false, 
                    error: existingUser.approvalStatus === 'pending' 
                        ? 'This register number has a pending registration. Please wait for approval.'
                        : 'This register number is already registered.' 
                });
            }
        }
        
        // Check if email already exists
        if (email) {
            const existingEmail = await User.findOne({ email: email });
            if (existingEmail) {
                // If the existing email belongs to a rejected user, allow re-registration
                if (existingEmail.approvalStatus === 'rejected') {
                    console.log(`Deleting rejected account for email ${email} to allow re-registration`);
                    await User.deleteOne({ _id: existingEmail._id });
                    await Session.deleteMany({ userId: existingEmail._id });
                } else {
                    return res.status(409).json({ 
                        success: false, 
                        error: existingEmail.approvalStatus === 'pending'
                            ? 'This email has a pending registration. Please wait for approval.'
                            : 'This email is already registered.' 
                    });
                }
            }
        }

        // Hash password with bcrypt
        const hashedPassword = await hashPassword(password);

        // Determine approval status based on role
        // Super-admin approved users or principals approved by super-admin
        let approvalStatus = 'pending';
        
        // Generate email verification token
        const emailVerificationToken = crypto.randomBytes(32).toString('hex');
        const emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
        
        // Create new user
        const newUser = new User({
            name,
            email: email,
            password: hashedPassword,
            rollno: rollno || null,
            rgno,
            role: role || 'student',
            department: department || null,
            semester: semester || null,
            college: college,
            approvalStatus: approvalStatus,
            emailVerified: false,
            emailVerificationToken: emailVerificationToken,
            emailVerificationExpires: emailVerificationExpires,
            emailVerificationSentAt: new Date()
        });

        await newUser.save();
        
        /* ============================================================
         * EMAIL VERIFICATION (Commented - Enable when SMTP is available)
         * ============================================================
        // Send verification email
        try {
            const verificationUrl = `${process.env.FRONTEND_URL || 'https://sreehari-m-dev.github.io/LOGI'}/verify-email.html?token=${emailVerificationToken}`;
            
            await sendEmail({
                from: `"LOGI System" <${EMAIL_FROM}>`,
                to: email,
                subject: '📧 Verify Your Email - LOGI Registration',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0;">
                            <h1 style="margin: 0;">📧 Verify Your Email</h1>
                            <p style="margin: 10px 0 0; opacity: 0.9;">Welcome to LOGI - Digital Lab Logbook System</p>
                        </div>
                        
                        <div style="padding: 30px; border: 1px solid #ddd; border-top: none;">
                            <p>Hello <strong>${name}</strong>,</p>
                            <p>Thank you for registering with LOGI. Please verify your email address to complete your registration.</p>
                            
                            <div style="text-align: center; margin: 30px 0;">
                                <a href="${verificationUrl}" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 40px; text-decoration: none; border-radius: 8px; font-weight: bold; display: inline-block;">
                                    ✓ Verify Email Address
                                </a>
                            </div>
                            
                            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 20px 0;">
                                <p style="margin: 0; font-size: 14px; color: #666;">
                                    <strong>Registration Details:</strong><br>
                                    Name: ${name}<br>
                                    RGNO: ${rgno}<br>
                                    Role: ${role || 'student'}<br>
                                    College: ${college}
                                </p>
                            </div>
                            
                            <p style="color: #d32f2f; font-size: 14px;">⏰ This link expires in 24 hours.</p>
                            
                            <p style="font-size: 13px; color: #666;">If you didn't create this account, please ignore this email.</p>
                            
                            <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                            <p style="font-size: 12px; color: #999;">If the button doesn't work, copy and paste this link into your browser:<br>
                            <span style="color: #667eea; word-break: break-all;">${verificationUrl}</span></p>
                        </div>
                        
                        <div style="background: #f5f5f5; padding: 15px; text-align: center; border-radius: 0 0 8px 8px; border: 1px solid #ddd; border-top: none;">
                            <p style="margin: 0; color: #666; font-size: 12px;">LOGI - Digital Lab Logbook Management System</p>
                        </div>
                    </div>
                `
            });
            console.log('[REGISTRATION] ✅ Verification email sent to:', email);
        } catch (emailError) {
            console.error('[REGISTRATION] ❌ Failed to send verification email:', emailError.message);
            // Don't fail registration if email fails - admin can verify manually
        }
        * END EMAIL VERIFICATION COMMENT */
        
        // NOTE: Email verification is disabled. Admin must manually verify users.
        console.log('[REGISTRATION] ℹ️ Email verification disabled - Admin must verify user:', email);

        // Create server-side session and generate token with session id (sid)
        const sid = crypto.randomBytes(16).toString('hex');
        await new Session({ sid, userId: newUser._id, rgno: newUser.rgno, role: newUser.role }).save();

        // Generate token using rgno + sid
        const token = generateToken(newUser._id, newUser.rgno, newUser.role, sid);

        // For principals, include super-admin contact info
        let additionalMessage = '';
        if (role === 'principal') {
            additionalMessage = '\n\nTo get your account approved, please contact the Super Admin:\n📧 Email: your.personal.email@gmail.com\n📞 Phone: +91 XXXXXXXXXX\n\nPlease provide your college name and registration details for verification.';
        }
        
        res.status(201).json({
            success: true,
            message: 'Registration successful! Your account is pending approval by an administrator.' + additionalMessage,
            // Email verification disabled - admin will manually verify if needed
            requiresEmailVerification: false,
            token,
            user: {
                id: newUser._id,
                name: newUser.name,
                rgno: newUser.rgno,
                role: newUser.role,
                rollno: newUser.rollno,
                college: newUser.college,
                department: newUser.department,
                approvalStatus: newUser.approvalStatus,
                emailVerified: false
            },
            showSuperAdminContact: role === 'principal'
        });

    } catch (error) {
        console.error('Registration error:', error);
        
        // Handle duplicate key errors (E11000)
        if (error.code === 11000) {
            const field = Object.keys(error.keyPattern)[0]; // Get which field caused the duplicate
            let message = 'This information is already registered.';
            if (field === 'email') {
                message = 'This email is already registered. Please use a different email.';
            } else if (field === 'rgno') {
                message = 'This register number is already registered.';
            }
            return res.status(409).json({ success: false, error: message });
        }
        
        res.status(500).json({ success: false, error: error.message });
    }
});

// Login Route - using Register Number with approval check
app.post('/api/auth/login', async (req, res) => {
    try {
        const { rgno, password, twoFactorCode, stayLoggedIn } = req.body;

        // Validation
        if (!rgno || !password) {
            return res.status(400).json({ 
                success: false, 
                error: 'Register number and password are required' 
            });
        }

        // Find user by register number
        const user = await User.findOne({ rgno: parseInt(rgno) });
        if (!user) {
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid register number or password' 
            });
        }

        // Check if user is active
        if (!user.isActive) {
            return res.status(403).json({ 
                success: false, 
                error: 'Account is inactive' 
            });
        }
        
        // Check if account is frozen (requires admin verification)
        if (user.accountFrozen) {
            let contactMsg = '';
            if (user.role === 'student') {
                contactMsg = 'Please contact your faculty or HOD to unfreeze your account.';
            } else if (user.role === 'faculty') {
                contactMsg = 'Please contact your HOD or principal to unfreeze your account.';
            } else if (user.role === 'hod') {
                contactMsg = 'Please contact your principal or super-admin to unfreeze your account.';
            } else {
                contactMsg = 'Please contact the super-admin to unfreeze your account.';
            }
            return res.status(403).json({ 
                success: false, 
                error: `Your account has been frozen due to too many failed login attempts. ${contactMsg}`,
                accountFrozen: true
            });
        }
        
        // Check temporary lockout (if any)
        if (user.lockoutUntil && user.lockoutUntil > new Date()) {
            const remainingMinutes = Math.ceil((user.lockoutUntil - new Date()) / 60000);
            return res.status(403).json({ 
                success: false, 
                error: `Account is temporarily locked. Try again in ${remainingMinutes} minutes.` 
            });
        }

        // Verify password with bcrypt
        const isPasswordValid = await verifyPassword(password, user.password);
        if (!isPasswordValid) {
            // Increment failed login attempts
            user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
            const remainingAttempts = 5 - user.failedLoginAttempts;
            
            // Create security alert for principals (notify super-admin)
            if (user.role === 'principal' && user.failedLoginAttempts >= 3) {
                await createSecurityAlert(user, 'failed_login', 
                    user.failedLoginAttempts >= 5 ? 'critical' : 'high', 
                    { 
                        attempts: user.failedLoginAttempts, 
                        message: `${user.failedLoginAttempts} failed login attempts on principal account` 
                    }, 
                    req
                );
            }
            
            if (user.failedLoginAttempts >= 5) {
                // FREEZE the account - requires admin to unfreeze
                user.accountFrozen = true;
                user.frozenAt = new Date();
                user.frozenReason = 'Too many failed login attempts';
                await user.save();
                
                let contactMsg = '';
                if (user.role === 'student') {
                    contactMsg = 'Please contact your faculty or HOD to unfreeze your account.';
                } else if (user.role === 'faculty') {
                    contactMsg = 'Please contact your HOD or principal to unfreeze your account.';
                } else if (user.role === 'hod') {
                    contactMsg = 'Please contact your principal or super-admin to unfreeze your account.';
                } else {
                    contactMsg = 'Please contact the super-admin to unfreeze your account.';
                }
                
                return res.status(403).json({ 
                    success: false, 
                    error: `Your account has been frozen due to too many failed login attempts. ${contactMsg}`,
                    accountFrozen: true,
                    remainingAttempts: 0
                });
            }
            await user.save();
            return res.status(401).json({ 
                success: false, 
                error: `Invalid register number or password. ${remainingAttempts} attempt${remainingAttempts !== 1 ? 's' : ''} remaining before account freeze.`,
                remainingAttempts: remainingAttempts
            });
        }
        
        // Upgrade legacy SHA-256 password to bcrypt on successful login
        if (user.password && !user.password.startsWith('$2')) {
            const newBcryptHash = await hashPassword(password);
            user.password = newBcryptHash;
            console.log(`✅ Upgraded password to bcrypt for user: ${user.rgno}`);
        }
        
        // Check email verification (only for users who registered after email verification was implemented)
        // Existing users (who don't have emailVerified field set at all) are grandfathered in
        // Only block users who explicitly have emailVerified === false (meaning they registered with this feature)
        // ============================================================
        // EMAIL VERIFICATION CHECK - Currently using admin manual verification
        // ============================================================
        if (user.role !== 'super-admin' && user.email && user.emailVerified === false) {
            const maskedEmail = user.email ? user.email.replace(/(.{2})(.*)(@.*)/, '$1***$3') : 'your email';
            return res.status(403).json({ 
                success: false, 
                // Updated message since email service is disabled
                error: 'Your email is not yet verified. Please contact your administrator (Faculty/Principal) to verify your email.',
                emailNotVerified: true,
                email: maskedEmail
            });
        }
        
        // Check approval status (except for super-admin)
        if (user.role !== 'super-admin' && user.approvalStatus !== 'approved') {
            if (user.approvalStatus === 'pending') {
                return res.status(403).json({ 
                    success: false,
                    error: 'Your account is pending approval. Please wait for approval from your administrator.',
                    approvalStatus: 'pending'
                });
            } else if (user.approvalStatus === 'rejected') {
                return res.status(403).json({ 
                    success: false, 
                    error: `Your account registration was rejected. ${user.rejectionReason ? 'Reason: ' + user.rejectionReason : ''}`,
                    approvalStatus: 'rejected'
                });
            }
        }
        
        // Variables for backup code tracking (need to be outside 2FA block for response)
        let usedBackupCode = false;
        let remainingBackupCodes = 0;
        
        // Check 2FA for super-admin
        if (user.role === 'super-admin' && user.twoFactorEnabled) {
            if (!twoFactorCode) {
                return res.status(200).json({ 
                    success: false, 
                    requiresTwoFactor: true,
                    hasBackupCodes: user.twoFactorBackupCodes && user.twoFactorBackupCodes.some(bc => !bc.used),
                    error: 'Two-factor authentication code required' 
                });
            }
            
            // Check if it's a backup code (8 characters) or TOTP code (6 digits)
            const isBackupCode = twoFactorCode.length === 8;
            let verified = false;
            
            if (isBackupCode) {
                // Check backup codes
                const backupCodeIndex = user.twoFactorBackupCodes.findIndex(
                    bc => bc.code === twoFactorCode.toUpperCase() && !bc.used
                );
                if (backupCodeIndex !== -1) {
                    // Mark backup code as used
                    user.twoFactorBackupCodes[backupCodeIndex].used = true;
                    const usedCode = user.twoFactorBackupCodes[backupCodeIndex].code;
                    remainingBackupCodes = user.twoFactorBackupCodes.filter(bc => !bc.used).length;
                    usedBackupCode = true;
                    await user.save();
                    verified = true;
                    
                    // Create audit log for backup code usage
                    await createAuditLog('2FA_BACKUP_CODE_USED', user, null, { 
                        codeIndex: backupCodeIndex,
                        remainingCodes: remainingBackupCodes 
                    }, req);
                    
                    // 🔔 SECURITY ALERT: Email notification about backup code usage
                    // ============================================================
                    // COMMENTED - Enable when SMTP is available
                    // ============================================================
                    // try {
                    //     const loginIP = req.ip || req.headers['x-forwarded-for'] || 'unknown';
                    //     const userAgent = req.headers['user-agent'] || 'Unknown device';
                    //     const loginTime = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });
                    //     const maskedCode = usedCode.substring(0, 2) + '****' + usedCode.substring(6);
                    //     if (user.email) {
                    //         await transporter.sendMail({ ... backup code alert email ... });
                    //     }
                    // } catch (emailError) {
                    //     console.error('[BACKUP CODE ALERT] Failed:', emailError.message);
                    // }
                    // ============================================================
                    console.log(`[BACKUP CODE ALERT] User ${user.username} used a backup code. ${remainingBackupCodes} codes remaining. (Email alert disabled)`);
                    // END BACKUP CODE EMAIL COMMENT
                }
            } else {
                // Verify 2FA code (using TOTP)
                const speakeasy = require('speakeasy');
                verified = speakeasy.totp.verify({
                    secret: user.twoFactorSecret,
                    encoding: 'base32',
                    token: twoFactorCode,
                    window: 1
                });
            }
            
            if (!verified) {
                return res.status(401).json({ 
                    success: false, 
                    error: isBackupCode ? 'Invalid or already used backup code' : 'Invalid two-factor authentication code' 
                });
            }
        }
        
        // Reset failed login attempts on successful login
        user.failedLoginAttempts = 0;
        user.lockoutUntil = null;
        user.lastLoginAt = new Date();
        user.lastLoginIP = req.ip || req.headers['x-forwarded-for'] || 'unknown';
        await user.save();

        // Create server-side session and generate token with session id (sid)
        const sid = crypto.randomBytes(16).toString('hex');
        const sessionData = { 
            sid, 
            userId: user._id, 
            rgno: user.rgno, 
            role: user.role,
            stayLoggedIn: !!stayLoggedIn // Store "stay logged in" preference
        };
        
        // Set 7-day expiry if stay logged in is enabled
        if (stayLoggedIn) {
            sessionData.stayLoggedInExpiry = new Date(Date.now() + STAY_LOGGED_IN_DURATION_MS);
        }
        
        await new Session(sessionData).save();

        // Generate token using rgno + sid
        const token = generateToken(user._id, user.rgno, user.role, sid);
        
        // Create audit log for super-admin login
        if (user.role === 'super-admin') {
            await createAuditLog('SUPER_ADMIN_LOGIN', user, null, { ip: user.lastLoginIP, stayLoggedIn: !!stayLoggedIn }, req);
        }

        // Check if user must change password (admin-reset password)
        if (user.mustChangePassword) {
            return res.json({
                success: true,
                message: 'Password change required',
                mustChangePassword: true,
                token, // Give token so they can call the change password endpoint
                user: {
                    id: user._id,
                    name: user.name,
                    rgno: user.rgno,
                    role: user.role,
                    email: user.email
                }
            });
        }

        res.json({
            success: true,
            message: 'Login successful',
            token,
            stayLoggedIn: !!stayLoggedIn, // Return this so client knows
            usedBackupCode: usedBackupCode, // Flag if backup code was used
            remainingBackupCodes: usedBackupCode ? remainingBackupCodes : undefined, // Only include if backup code was used
            user: {
                id: user._id,
                name: user.name,
                rgno: user.rgno,
                role: user.role,
                rollno: user.rollno,
                email: user.email,
                college: user.college,
                department: user.department,
                approvalStatus: user.approvalStatus
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Verify Token Route (does NOT extend session - just checking validity)
app.post('/api/auth/verify', authenticateSessionNoTouch, (req, res) => {
    try {
        // If middleware passed, session is valid
        res.json({ success: true, user: req.auth.decoded });
    } catch (error) {
        res.status(401).json({ success: false, error: 'Invalid token' });
    }
});

// Get User Profile (does NOT extend session - read-only operation)
app.get('/api/auth/profile', authenticateSessionNoTouch, async (req, res) => {
    try {
        const user = await User.findById(req.auth.decoded.userId).select('-password');
        
        res.json({ 
            success: true, 
            user 
        });

    } catch (error) {
        res.status(401).json({ success: false, error: 'Invalid token' });
    }
});

// Get remaining session time without extending the session
app.get('/api/auth/session-remaining', authenticateSessionNoTouch, async (req, res) => {
    try {
        const session = req.auth.session;
        const now = Date.now();
        const last = session.lastActivity ? session.lastActivity.getTime() : session.createdAt.getTime();
        const remainingMs = Math.max(0, IDLE_TIMEOUT_MS - (now - last));
        res.json({ success: true, remainingMs });
    } catch (error) {
        console.error('Session remaining error:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch session time' });
    }
});

// Update Profile Route
app.put('/api/auth/profile', authenticateAndTouchSession, async (req, res) => {
    try {
        const { name, email, rollno, department, semester } = req.body;
        const userId = req.auth.decoded.userId;

        // Validation
        if (!name || !email) {
            return res.status(400).json({ 
                success: false, 
                error: 'Name and email are required' 
            });
        }

        // Check if new email is already taken by another user
        if (email) {
            const existingUser = await User.findOne({ email: email, _id: { $ne: userId } });
            if (existingUser) {
                return res.status(409).json({ 
                    success: false, 
                    error: 'This email is already registered. Please use a different email.' 
                });
            }
        }

        // Update user
        const user = await User.findByIdAndUpdate(
            userId,
            {
                name,
                email,
                rollno: rollno ? parseInt(rollno) : null,
                department,
                semester: semester ? parseInt(semester) : null
            },
            { new: true, runValidators: true }
        ).select('-password');

        res.json({
            success: true,
            message: 'Profile updated successfully',
            user
        });

    } catch (error) {
        console.error('Profile update error:', error);

        // Handle duplicate key errors (E11000)
        if (error.code === 11000) {
            const field = Object.keys(error.keyPattern)[0];
            let message = 'This information is already in use.';
            if (field === 'email') {
                message = 'This email is already registered. Please use a different email.';
            }
            return res.status(409).json({ success: false, error: message });
        }

        res.status(500).json({ success: false, error: error.message });
    }
});

// Get Navbar Preferences (for principals and super-admins)
app.get('/api/auth/navbar-preferences', authenticateSessionNoTouch, async (req, res) => {
    try {
        const user = await User.findById(req.auth.decoded.userId);
        
        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        // Default preferences if not set
        const defaultPrefs = {
            home: true,
            logbook: true,
            resources: true,
            about: true,
            profile: true,
            masterTemplates: true,
            viewLogbooks: true,
            admin: true
        };
        
        // Merge defaults with user's saved preferences
        const prefs = user.navbarPreferences || defaultPrefs;
        
        res.json({
            success: true,
            navbarPreferences: prefs,
            canCustomize: ['principal', 'super-admin'].includes(user.role)
        });
    } catch (error) {
        console.error('Get navbar preferences error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Update Navbar Preferences (for principals and super-admins only)
app.put('/api/auth/navbar-preferences', authenticateAndTouchSession, async (req, res) => {
    try {
        const user = await User.findById(req.auth.decoded.userId);
        
        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        // Only principals and super-admins can customize navbar
        if (!['principal', 'super-admin'].includes(user.role)) {
            return res.status(403).json({ 
                success: false, 
                error: 'Only principals and super-admins can customize navbar preferences' 
            });
        }
        
        const { navbarPreferences } = req.body;
        
        // Validate preferences structure
        const validKeys = ['home', 'logbook', 'resources', 'about', 'profile', 'masterTemplates', 'viewLogbooks', 'admin'];
        const sanitizedPrefs = {};
        
        for (const key of validKeys) {
            if (typeof navbarPreferences[key] === 'boolean') {
                sanitizedPrefs[key] = navbarPreferences[key];
            } else {
                sanitizedPrefs[key] = true; // Default to visible
            }
        }
        
        // Principals should NOT be able to see super-admin-specific items
        // (Currently 'admin' is the only one, but we keep it accessible for both)
        
        user.navbarPreferences = sanitizedPrefs;
        await user.save();
        
        res.json({
            success: true,
            message: 'Navbar preferences updated',
            navbarPreferences: sanitizedPrefs
        });
    } catch (error) {
        console.error('Update navbar preferences error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Change Password Route
app.post('/api/auth/change-password', authenticateAndTouchSession, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const user = await User.findById(req.auth.decoded.userId);

        // Verify current password with bcrypt
        const isValid = await verifyPassword(currentPassword, user.password);
        if (!isValid) {
            return res.status(401).json({ success: false, error: 'Current password is incorrect' });
        }

        // Hash new password with bcrypt
        const hashedPassword = await hashPassword(newPassword);

        // Update password
        user.password = hashedPassword;
        await user.save();

        res.json({ success: true, message: 'Password changed successfully' });

    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Logout Route (client-side)
app.post('/api/auth/logout', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (token) {
            const decoded = verifyToken(token);
            if (decoded && decoded.sid) {
                const session = await Session.findOne({ sid: decoded.sid });
                if (session && !session.isExpired) {
                    session.isExpired = true;
                    session.expiredAt = new Date();
                    await session.save();
                }
            }
        }
    } catch (e) {
        // ignore and return success
    }
    res.json({ success: true, message: 'Logout successful' });
});

// Delete Account Route - Cascades to delete all templates and logbooks
app.delete('/api/auth/delete-account', authenticateAndTouchSession, async (req, res) => {
    try {
        const { password, twoFactorCode } = req.body;
        const userId = req.auth.decoded.userId;
        
        // Verify user exists
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        // Super-admin cannot delete account - must transfer first
        if (user.role === 'super-admin') {
            return res.status(403).json({ 
                success: false, 
                error: 'Super-admin cannot delete their account. You must first transfer super-admin privileges to another user using the succession system.',
                requiresSuccessor: true
            });
        }
        
        // Verify password
        if (!password) {
            return res.status(400).json({ success: false, error: 'Password is required to delete account' });
        }
        
        const isValid = await verifyPassword(password, user.password);
        if (!isValid) {
            return res.status(401).json({ success: false, error: 'Incorrect password' });
        }
        
        // If user is faculty/admin, cascade delete their templates and associated student logbooks
        if (user.role === 'faculty' || user.role === 'admin') {
            try {
                // Call logbook service to delete all templates and logbooks created by this user
                const logbookServiceUrl = process.env.LOGBOOK_SERVICE_URL || 'http://localhost:3005';
                const cascadeResponse = await fetch(`${logbookServiceUrl}/api/logbook/cascade-delete-by-teacher`, {
                    method: 'DELETE',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': req.headers.authorization
                    },
                    body: JSON.stringify({ teacherRgno: user.rgno })
                });
                
                const cascadeResult = await cascadeResponse.json();
                console.log('[DELETE ACCOUNT] Cascade delete result:', cascadeResult);
            } catch (cascadeError) {
                console.error('[DELETE ACCOUNT] Cascade delete error:', cascadeError.message);
                // Continue with account deletion even if cascade fails
            }
        }
        
        // If user is student, delete their logbooks
        if (user.role === 'student') {
            try {
                const logbookServiceUrl = process.env.LOGBOOK_SERVICE_URL || 'http://localhost:3005';
                const deleteResponse = await fetch(`${logbookServiceUrl}/api/logbook/delete-by-student`, {
                    method: 'DELETE',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': req.headers.authorization
                    },
                    body: JSON.stringify({ studentRgno: user.rgno })
                });
                
                const deleteResult = await deleteResponse.json();
                console.log('[DELETE ACCOUNT] Student logbooks delete result:', deleteResult);
            } catch (deleteError) {
                console.error('[DELETE ACCOUNT] Student logbooks delete error:', deleteError.message);
            }
        }
        
        // Invalidate all sessions for this user
        await Session.updateMany(
            { userId: userId },
            { isExpired: true, expiredAt: new Date() }
        );
        
        // Delete the user
        await User.findByIdAndDelete(userId);
        
        console.log('[DELETE ACCOUNT] Account deleted successfully:', user.rgno);
        res.json({ success: true, message: 'Account and all associated data deleted successfully' });
        
    } catch (error) {
        console.error('[DELETE ACCOUNT] Error:', error);
        res.status(500).json({ success: false, error: 'Failed to delete account. Please try again.' });
    }
});

// Filter students by department and semester
app.post('/api/auth/students/filter', async (req, res) => {
    try {
        const { department, semester } = req.body;

        if (!department || !semester) {
            return res.status(400).json({
                success: false,
                error: 'Department and semester are required'
            });
        }

        // Use regex to handle trailing/leading spaces in department names
        const students = await User.find({
            role: 'student',
            department: { $regex: `^${department.trim()}\\s*$`, $options: 'i' },
            semester: parseInt(semester)
        }).select('name rgno rollno department semester -_id').sort({ rollno: 1 });

        res.json({
            success: true,
            students: students,
            count: students.length
        });
    } catch (error) {
        console.error('Error filtering students:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get all users (Admin only)
app.get('/api/auth/users', authenticateAndTouchSession, async (req, res) => {
    try {
        // Check if user is admin
        if (req.auth.decoded.role !== 'admin') {
            return res.status(403).json({ success: false, error: 'Access denied' });
        }

        const users = await User.find().select('-password');
        res.json({ success: true, users });

    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// --- Password Reset: Forgot Password Endpoint ---

// ==================== EMAIL CONFIGURATION ====================
// Supports: Elastic Email (recommended), Brevo, Gmail, Mailgun, SendGrid, etc.
//
// === ELASTIC EMAIL SETUP (Recommended - Free 100 emails/day, no domain required) ===
// 1. Sign up at https://elasticemail.com
// 2. Go to Settings → SMTP → Create new SMTP credentials
// 3. Set these in your .env:
//    EMAIL_HOST=smtp.elasticemail.com
//    EMAIL_PORT=2525
//    EMAIL_USER=your-elasticemail-api-key (or your account email)
//    EMAIL_PASS=your-elasticemail-smtp-password
//    EMAIL_FROM=your-verified-sender@email.com
//
// === BREVO SETUP (Requires domain verification) ===
//    EMAIL_HOST=smtp-relay.brevo.com
//    EMAIL_PORT=587
//    EMAIL_USER=your-brevo-login-email
//    EMAIL_PASS=your-brevo-smtp-key
//
// === GMAIL SETUP (May be blocked by some hosts) ===
//    EMAIL_HOST=smtp.gmail.com
//    EMAIL_PORT=587
//    EMAIL_USER=your-gmail@gmail.com
//    EMAIL_PASS=your-app-password (16-char app password, not regular password)
//
// FRONTEND_URL=https://sreehari-m-dev.github.io/LOGI

const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;
const EMAIL_FROM = process.env.EMAIL_FROM || process.env.EMAIL_USER; // Separate "from" address
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://sreehari-m-dev.github.io/LOGI';

// Check if using Resend API (recommended - works without domain verification)
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const useResend = !!RESEND_API_KEY;

// Validate email credentials
if (!useResend && (!EMAIL_USER || !EMAIL_PASS)) {
    console.warn('⚠️ Email not configured - Set RESEND_API_KEY (recommended) or EMAIL_USER/EMAIL_PASS');
}

// ==================== EMAIL SENDING FUNCTION ====================
// Unified email sending that supports both Resend API and SMTP

let transporter = null; // Will be initialized for SMTP providers

async function sendEmail(mailOptions) {
    // Use Resend API if configured (RECOMMENDED - free, works without domain)
    if (useResend) {
        try {
            const response = await fetch('https://api.resend.com/emails', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${RESEND_API_KEY}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    from: mailOptions.from || `LOGI <onboarding@resend.dev>`, // Resend's free sender
                    to: Array.isArray(mailOptions.to) ? mailOptions.to : [mailOptions.to],
                    subject: mailOptions.subject,
                    html: mailOptions.html || mailOptions.text
                })
            });

            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || `Resend API error: ${response.status}`);
            }
            
            console.log('✅ Email sent via Resend:', data.id);
            return { messageId: data.id };
        } catch (error) {
            console.error('❌ Resend email error:', error.message);
            throw error;
        }
    }
    
    // Fall back to SMTP (Brevo, Gmail, etc.)
    if (!transporter) {
        throw new Error('Email not configured. Set RESEND_API_KEY or SMTP credentials.');
    }
    
    return transporter.sendMail(mailOptions);
}

// SMTP Configuration (for Brevo, Gmail, Elastic Email if preferred)
if (!useResend && EMAIL_USER && EMAIL_PASS) {
    const EMAIL_HOST = process.env.EMAIL_HOST || 'smtp.gmail.com';
    const EMAIL_PORT = parseInt(process.env.EMAIL_PORT || '587');
    
    const isBrevo = EMAIL_HOST.includes('brevo') || EMAIL_HOST.includes('sendinblue');
    const isGmail = EMAIL_HOST.includes('gmail');
    const isElasticEmail = EMAIL_HOST.includes('elasticemail');
    
    console.log('📧 SMTP Email config:');
    console.log('   Provider:', isBrevo ? 'Brevo' : isGmail ? 'Gmail' : isElasticEmail ? 'Elastic Email' : 'Custom SMTP');
    console.log('   Host:', EMAIL_HOST, 'Port:', EMAIL_PORT);
    
    const transporterConfig = {
        host: EMAIL_HOST,
        port: EMAIL_PORT,
        secure: EMAIL_PORT === 465,
        auth: {
            user: EMAIL_USER,
            pass: EMAIL_PASS
        },
        connectionTimeout: 30000,
        greetingTimeout: 30000,
        socketTimeout: 60000
    };
    
    if (isBrevo || isElasticEmail) {
        transporterConfig.pool = true;
        transporterConfig.maxConnections = 5;
    }
    
    if (isGmail) {
        transporterConfig.requireTLS = true;
    }
    
    transporter = nodemailer.createTransport(transporterConfig);
    
    transporter.verify((error, success) => {
        if (error) {
            console.error('❌ SMTP transporter error:', error.message);
        } else {
            console.log('✅ SMTP transporter ready');
        }
    });
} else if (useResend) {
    console.log('📧 Email config: Using Resend API (recommended)');
    console.log('   Free tier: 100 emails/day, no domain required');
    console.log('   From address: onboarding@resend.dev (Resend free sender)');
} else {
    console.warn('⚠️ No email provider configured');
}

// ==================== EMAIL VERIFICATION ENDPOINTS ====================

// Verify Email - User clicks link in email
app.get('/api/auth/verify-email', async (req, res) => {
    try {
        const { token } = req.query;
        
        if (!token) {
            return res.status(400).json({ success: false, error: 'Verification token is required' });
        }
        
        const user = await User.findOne({
            emailVerificationToken: token,
            emailVerificationExpires: { $gt: new Date() }
        });
        
        if (!user) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid or expired verification link. Please request a new one.',
                expired: true
            });
        }
        
        // Check if already verified
        if (user.emailVerified) {
            return res.json({ 
                success: true, 
                message: 'Email is already verified. You can now log in.',
                alreadyVerified: true
            });
        }
        
        // Verify the email
        user.emailVerified = true;
        user.emailVerificationToken = null;
        user.emailVerificationExpires = null;
        await user.save();
        
        res.json({
            success: true,
            message: 'Email verified successfully! You can now log in.',
            user: {
                name: user.name,
                rgno: user.rgno,
                email: user.email
            }
        });
        
    } catch (error) {
        console.error('Email verification error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

/* ============================================================
 * RESEND VERIFICATION EMAIL (Commented - Enable when SMTP is available)
 * ============================================================

// Resend Verification Email
app.post('/api/auth/resend-verification', async (req, res) => {
    // ... email sending code ...
});

* END RESEND VERIFICATION EMAIL COMMENT */

// Resend verification email - currently unavailable
app.post('/api/auth/resend-verification', async (req, res) => {
    res.status(503).json({ 
        success: false, 
        error: 'Email service is currently unavailable. Please contact your administrator to verify your email.' 
    });
});

// Force verify email for existing users (admin endpoint)
app.post('/api/auth/admin/mark-email-verified/:userId', authenticateAndTouchSession, async (req, res) => {
    try {
        // Only super-admin can force verify
        const admin = await User.findById(req.auth.decoded.userId);
        if (!admin || admin.role !== 'super-admin') {
            return res.status(403).json({ success: false, error: 'Super-admin access required' });
        }
        
        const targetUser = await User.findById(req.params.userId);
        if (!targetUser) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        targetUser.emailVerified = true;
        targetUser.emailVerificationToken = null;
        targetUser.emailVerificationExpires = null;
        await targetUser.save();
        
        await createAuditLog('EMAIL_VERIFIED_BY_ADMIN', admin, targetUser, {
            verifiedBy: admin.name,
            reason: 'Manual verification by super-admin'
        }, req);
        
        res.json({ 
            success: true, 
            message: `Email verified for ${targetUser.name}` 
        });
        
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/* ============================================================
 * ADMIN SEND VERIFICATION EMAIL (Commented - Enable when SMTP is available)
 * Use "Manually Verify Email" button in admin dashboard instead
 * ============================================================

// Send verification email to a specific user (admin can trigger)
app.post('/api/auth/admin/send-verification-email/:userId', authenticateAndTouchSession, async (req, res) => {
    // ... email sending code ...
});

// Bulk send verification emails to all unverified users (super-admin only)
app.post('/api/auth/admin/send-bulk-verification-emails', authenticateAndTouchSession, async (req, res) => {
    // ... bulk email sending code ...
});

* END ADMIN SEND VERIFICATION EMAIL COMMENT */

// Admin send verification email - currently unavailable
app.post('/api/auth/admin/send-verification-email/:userId', authenticateAndTouchSession, async (req, res) => {
    res.status(503).json({ 
        success: false, 
        error: 'Email service is currently unavailable. Use "Manually Verify Email" button instead.' 
    });
});

// Bulk send verification emails - currently unavailable
app.post('/api/auth/admin/send-bulk-verification-emails', authenticateAndTouchSession, async (req, res) => {
    res.status(503).json({ 
        success: false, 
        error: 'Email service is currently unavailable. Please verify users manually from the admin dashboard.' 
    });
});

// Get email verification stats (super-admin)
app.get('/api/auth/admin/email-verification-stats', authenticateAndTouchSession, async (req, res) => {
    try {
        const admin = await User.findById(req.auth.decoded.userId);
        if (!admin || admin.role !== 'super-admin') {
            return res.status(403).json({ success: false, error: 'Super-admin access required' });
        }
        
        const totalUsers = await User.countDocuments({ role: { $ne: 'super-admin' } });
        const verifiedCount = await User.countDocuments({ 
            role: { $ne: 'super-admin' },
            emailVerified: true 
        });
        const unverifiedCount = await User.countDocuments({ 
            role: { $ne: 'super-admin' },
            $or: [
                { emailVerified: { $ne: true } },
                { emailVerified: { $exists: false } }
            ]
        });
        const noEmailCount = await User.countDocuments({ 
            role: { $ne: 'super-admin' },
            $or: [
                { email: { $exists: false } },
                { email: null }
            ]
        });
        
        res.json({
            success: true,
            stats: {
                total: totalUsers,
                verified: verifiedCount,
                unverified: unverifiedCount,
                noEmail: noEmailCount
            }
        });
        
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==================== END EMAIL VERIFICATION ====================

/* ============================================================
 * FORGOT PASSWORD VIA EMAIL (Commented - Enable when SMTP is available)
 * Users should contact admin for password reset instead
 * ============================================================

// Forgot Password Endpoint
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { rgno, email } = req.body;
        
        console.log('[FORGOT PASSWORD] Request received - rgno:', rgno, 'email:', email);
        
        // Validate email configuration first
        if (!EMAIL_USER || !EMAIL_PASS) {
            console.error('[FORGOT PASSWORD] Email not configured - EMAIL_USER or EMAIL_PASS missing in .env');
            return res.status(503).json({ 
                success: false, 
                error: 'Email service not configured. Please contact administrator.' 
            });
        }
        
        if (!rgno || !email) {
            return res.status(400).json({ success: false, error: 'Register number and email are required' });
        }
        
        // Find user by register number (trim email in DB and input for robustness)
        const user = await User.findOne({ rgno: parseInt(rgno) });
        if (!user) {
            console.log('[FORGOT PASSWORD] User not found - rgno:', rgno);
            return res.status(404).json({ success: false, error: 'No user found with that register number' });
        }
        
        console.log('[FORGOT PASSWORD] User found:', user.rgno, 'DB Email:', user.email);
        
        // Normalize and compare emails
        const dbEmail = user.email ? user.email.trim().toLowerCase() : '';
        const inputEmail = email ? email.trim().toLowerCase() : '';
        
        if (!dbEmail || dbEmail !== inputEmail) {
            console.log('[FORGOT PASSWORD] Email mismatch - DB:', dbEmail, 'Input:', inputEmail);
            return res.status(400).json({ success: false, error: 'Email does not match the register number' });
        }
        
        // Generate token
        const token = crypto.randomBytes(32).toString('hex');
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        await user.save();
        console.log('[FORGOT PASSWORD] Reset token generated and saved:', token.substring(0, 8) + '...');
        
        // Send email
        const resetUrl = `${FRONTEND_URL}/reset-password.html?token=${token}`;
        const mailOptions = {
            from: `LOGI <${EMAIL_FROM}>`,
            to: user.email,
            subject: 'LOGI Password Reset Request',
            html: `<p>Hello ${user.name},</p>
                   <p>You requested a password reset for your LOGI account.</p>
                   <p><b>Register Number:</b> ${user.rgno}</p>
                   <p>Click the link below to reset your password. This link is valid for 1 hour.</p>
                   <p><a href='${resetUrl}'>Reset Password</a></p>
                   <p>If you did not request this, please ignore this email.</p>`
        };
        
        console.log('[FORGOT PASSWORD] Sending email to:', user.email);
        await sendEmail(mailOptions);
        console.log('[FORGOT PASSWORD] Email sent successfully');
        
        res.json({ success: true, message: 'Password reset email sent' });
    } catch (error) {
        console.error('[FORGOT PASSWORD] Error:', error.message);
        res.status(500).json({ success: false, error: 'Failed to send reset email: ' + error.message });
    }
});

// --- Password Reset: Reset Password Endpoint (Email Token Based) ---
app.post('/api/auth/reset-password/:token', async (req, res) => {
    try {
        const { token } = req.params;
        const { password } = req.body;
        if (!token || !password) {
            return res.status(400).json({ success: false, error: 'Token and new password are required' });
        }

        console.log('[RESET PASSWORD] Token received:', token);

        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            console.log('[RESET PASSWORD] Invalid or expired token');
            return res.status(400).json({ success: false, error: 'Invalid or expired token' });
        }

        const hashedPassword = await hashPassword(password);
        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();
        console.log('[RESET PASSWORD] Password updated successfully for user:', user.rgno);

        res.json({ success: true, message: 'Password has been reset successfully' });
    } catch (error) {
        console.error('[RESET PASSWORD] Error:', error);
        res.status(500).json({ success: false, error: 'Failed to reset password' });
    }
});

* END FORGOT PASSWORD VIA EMAIL COMMENT */

// Forgot password - redirect to contact admin
app.post('/api/auth/forgot-password', async (req, res) => {
    res.status(503).json({ 
        success: false, 
        error: 'Email-based password reset is currently unavailable. Please contact your administrator (Faculty/Principal) to reset your password.' 
    });
});

// ==================== FORCED PASSWORD CHANGE (After Admin Reset) ====================

// Forced password change - for users who must change password after admin reset
app.post('/api/auth/force-change-password', authenticateSessionNoTouch, async (req, res) => {
    try {
        const { newPassword, confirmPassword } = req.body;
        
        // Validate input
        if (!newPassword || !confirmPassword) {
            return res.status(400).json({ 
                success: false, 
                error: 'New password and confirmation are required' 
            });
        }
        
        if (newPassword !== confirmPassword) {
            return res.status(400).json({ 
                success: false, 
                error: 'Passwords do not match' 
            });
        }
        
        if (newPassword.length < 8) {
            return res.status(400).json({ 
                success: false, 
                error: 'Password must be at least 8 characters long' 
            });
        }
        
        const user = await User.findById(req.auth.decoded.userId);
        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        if (!user.mustChangePassword) {
            return res.status(400).json({ 
                success: false, 
                error: 'Password change not required for this account' 
            });
        }
        
        // Hash and save new password
        user.password = await hashPassword(newPassword);
        user.mustChangePassword = false;
        user.passwordResetByAdmin = null;
        user.passwordResetByAdminAt = null;
        await user.save();
        
        console.log(`[FORCE-CHANGE-PASSWORD] ✅ User ${user.rgno} changed password after admin reset`);
        
        res.json({ 
            success: true, 
            message: 'Password changed successfully. You can now use all features.',
            user: {
                id: user._id,
                name: user.name,
                rgno: user.rgno,
                role: user.role,
                rollno: user.rollno,
                college: user.college,
                department: user.department,
                email: user.email,
                approvalStatus: user.approvalStatus,
                emailVerified: user.emailVerified,
                twoFactorEnabled: user.twoFactorEnabled || false,
                mustChangePassword: false
            }
        });
        
    } catch (error) {
        console.error('Force change password error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==================== ADMIN PASSWORD RESET (No Email Required) ====================

// Admin resets user password - sets a temporary password that user must change
app.post('/api/auth/admin/reset-password/:userId', authenticateAndTouchSession, async (req, res) => {
    try {
        const admin = await User.findById(req.auth.decoded.userId);
        if (!admin || !['super-admin', 'principal', 'hod', 'faculty'].includes(admin.role)) {
            return res.status(403).json({ success: false, error: 'Admin access required' });
        }
        
        const targetUser = await User.findById(req.params.userId);
        if (!targetUser) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        // Check authorization hierarchy
        if (admin.role === 'faculty') {
            // Faculty can only reset student passwords in their college/department
            if (targetUser.role !== 'student' || targetUser.college !== admin.college) {
                return res.status(403).json({ success: false, error: 'Not authorized to reset this user\'s password' });
            }
        } else if (admin.role === 'hod') {
            // HOD can reset faculty and student passwords in their department
            if (!['student', 'faculty'].includes(targetUser.role) || 
                targetUser.college !== admin.college || 
                targetUser.department !== admin.department) {
                return res.status(403).json({ success: false, error: 'Not authorized to reset this user\'s password' });
            }
        } else if (admin.role === 'principal') {
            // Principal can reset HOD, faculty and student passwords in their college
            if (!['student', 'faculty', 'hod'].includes(targetUser.role) || targetUser.college !== admin.college) {
                return res.status(403).json({ success: false, error: 'Not authorized to reset this user\'s password' });
            }
        }
        // Super-admin can reset anyone except other super-admins
        if (targetUser.role === 'super-admin' && admin.role !== 'super-admin') {
            return res.status(403).json({ success: false, error: 'Cannot reset super-admin password' });
        }
        
        // Generate a temporary password
        const tempPassword = crypto.randomBytes(4).toString('hex').toUpperCase(); // 8 char like "A1B2C3D4"
        
        // Hash and save
        targetUser.password = await hashPassword(tempPassword);
        targetUser.mustChangePassword = true;
        targetUser.passwordResetByAdmin = admin._id;
        targetUser.passwordResetByAdminAt = new Date();
        targetUser.failedLoginAttempts = 0; // Reset lockout
        targetUser.accountFrozen = false; // Unfreeze if frozen
        targetUser.lockoutUntil = null;
        await targetUser.save();
        
        // Create audit log
        await createAuditLog('ADMIN_PASSWORD_RESET', admin, targetUser, {
            adminRole: admin.role,
            userRole: targetUser.role
        }, req);
        
        console.log(`[ADMIN-RESET-PASSWORD] ✅ Admin ${admin.rgno} reset password for user ${targetUser.rgno}`);
        
        res.json({ 
            success: true, 
            message: `Password reset successful. Temporary password: ${tempPassword}`,
            tempPassword: tempPassword, // Return to admin so they can tell user
            note: 'User will be forced to change this password on next login.',
            user: {
                name: targetUser.name,
                rgno: targetUser.rgno,
                email: targetUser.email
            }
        });
        
    } catch (error) {
        console.error('Admin reset password error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'Auth Server running on port 3002' });
});

// ==================== APPROVAL WORKFLOW ENDPOINTS ====================

// Get pending approvals (for principals: faculty, for faculty: students, for super-admin: all)
app.get('/api/auth/pending-approvals', authenticateAndTouchSession, async (req, res) => {
    try {
        const user = await User.findById(req.auth.decoded.userId);
        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        let query = { approvalStatus: 'pending', isActive: true };
        
        if (user.role === 'super-admin') {
            // Super-admin can see all pending (primarily principals)
            query.role = { $in: ['principal', 'hod', 'faculty', 'student'] };
        } else if (user.role === 'principal') {
            // Principal can see pending HOD and faculty in their college
            query.role = { $in: ['hod', 'faculty'] };
            query.college = user.college;
        } else if (user.role === 'hod') {
            // HOD can see pending faculty and students in their department
            query.role = { $in: ['faculty', 'student'] };
            query.college = user.college;
            query.department = user.department;
        } else if (user.role === 'faculty') {
            // Faculty can only see pending students in their college/department
            query.role = 'student';
            query.college = user.college;
            if (user.department) {
                query.department = user.department;
            }
        } else {
            return res.status(403).json({ success: false, error: 'Not authorized to view pending approvals' });
        }
        
        const pendingUsers = await User.find(query)
            .select('-password -resetPasswordToken -resetPasswordExpires -twoFactorSecret')
            .sort({ createdAt: -1 });
        
        res.json({ success: true, pendingUsers, count: pendingUsers.length });
    } catch (error) {
        console.error('Get pending approvals error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Approve a user
app.post('/api/auth/approve-user/:userId', authenticateAndTouchSession, async (req, res) => {
    try {
        const approver = await User.findById(req.auth.decoded.userId);
        if (!approver) {
            return res.status(404).json({ success: false, error: 'Approver not found' });
        }
        
        const targetUser = await User.findById(req.params.userId);
        if (!targetUser) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        // Authorization checks
        let authorized = false;
        if (approver.role === 'super-admin') {
            authorized = true; // Super-admin can approve anyone
        } else if (approver.role === 'principal' && ['hod', 'faculty'].includes(targetUser.role)) {
            // Principal can approve HOD and faculty in their college
            authorized = approver.college === targetUser.college;
        } else if (approver.role === 'hod' && ['faculty', 'student'].includes(targetUser.role)) {
            // HOD can approve faculty and students in their department
            authorized = approver.college === targetUser.college && approver.department === targetUser.department;
        } else if (approver.role === 'faculty' && targetUser.role === 'student') {
            // Faculty can approve students in their college/department
            authorized = approver.college === targetUser.college;
            if (approver.department && targetUser.department) {
                authorized = authorized && approver.department === targetUser.department;
            }
        }
        
        if (!authorized) {
            return res.status(403).json({ success: false, error: 'Not authorized to approve this user' });
        }
        
        // Update approval status
        targetUser.approvalStatus = 'approved';
        targetUser.approvedBy = approver._id;
        targetUser.approvedAt = new Date();
        await targetUser.save();
        
        // Create audit log
        await createAuditLog('USER_APPROVED', approver, targetUser, {
            targetRole: targetUser.role,
            college: targetUser.college
        }, req);
        
        res.json({ 
            success: true, 
            message: `${targetUser.name} has been approved`,
            user: {
                id: targetUser._id,
                name: targetUser.name,
                rgno: targetUser.rgno,
                role: targetUser.role,
                college: targetUser.college,
                approvalStatus: targetUser.approvalStatus
            }
        });
    } catch (error) {
        console.error('Approve user error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Reject a user
app.post('/api/auth/reject-user/:userId', authenticateAndTouchSession, async (req, res) => {
    try {
        const { reason } = req.body;
        const approver = await User.findById(req.auth.decoded.userId);
        if (!approver) {
            return res.status(404).json({ success: false, error: 'Approver not found' });
        }
        
        const targetUser = await User.findById(req.params.userId);
        if (!targetUser) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        // Authorization checks (same as approve)
        let authorized = false;
        if (approver.role === 'super-admin') {
            authorized = true;
        } else if (approver.role === 'principal' && ['hod', 'faculty'].includes(targetUser.role)) {
            authorized = approver.college === targetUser.college;
        } else if (approver.role === 'hod' && ['faculty', 'student'].includes(targetUser.role)) {
            authorized = approver.college === targetUser.college && approver.department === targetUser.department;
        } else if (approver.role === 'faculty' && targetUser.role === 'student') {
            authorized = approver.college === targetUser.college;
        }
        
        if (!authorized) {
            return res.status(403).json({ success: false, error: 'Not authorized to reject this user' });
        }
        
        // Update rejection status
        targetUser.approvalStatus = 'rejected';
        targetUser.rejectionReason = reason || 'No reason provided';
        targetUser.approvedBy = approver._id;
        targetUser.approvedAt = new Date();
        await targetUser.save();
        
        // Create audit log
        await createAuditLog('USER_REJECTED', approver, targetUser, {
            targetRole: targetUser.role,
            reason: reason,
            college: targetUser.college
        }, req);
        
        res.json({ 
            success: true, 
            message: `${targetUser.name} has been rejected`,
            user: {
                id: targetUser._id,
                name: targetUser.name,
                rgno: targetUser.rgno,
                approvalStatus: targetUser.approvalStatus
            }
        });
    } catch (error) {
        console.error('Reject user error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Unfreeze a frozen account (admin action)
app.post('/api/auth/unfreeze-user/:userId', authenticateAndTouchSession, async (req, res) => {
    try {
        const admin = await User.findById(req.auth.decoded.userId);
        if (!admin) {
            return res.status(404).json({ success: false, error: 'Admin not found' });
        }
        
        // Only principal or super-admin can unfreeze accounts
        if (!['principal', 'super-admin'].includes(admin.role)) {
            return res.status(403).json({ success: false, error: 'Not authorized to unfreeze accounts' });
        }
        
        const targetUser = await User.findById(req.params.userId);
        if (!targetUser) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        // Check if the user is actually frozen
        if (!targetUser.accountFrozen) {
            return res.status(400).json({ success: false, error: 'This account is not frozen' });
        }
        
        // Principals can only unfreeze users in their college (not other principals)
        if (admin.role === 'principal') {
            if (targetUser.college !== admin.college) {
                return res.status(403).json({ success: false, error: 'You can only unfreeze users in your college' });
            }
            if (targetUser.role === 'principal') {
                return res.status(403).json({ success: false, error: 'Only super-admin can unfreeze principal accounts' });
            }
        }
        
        // Unfreeze the account
        targetUser.accountFrozen = false;
        targetUser.failedLoginAttempts = 0;
        targetUser.lockoutUntil = null;
        targetUser.unfrozenBy = admin._id;
        targetUser.unfrozenAt = new Date();
        await targetUser.save();
        
        // Create audit log
        await createAuditLog('USER_UNFROZEN', admin, targetUser, {
            targetRole: targetUser.role,
            frozenReason: targetUser.frozenReason,
            frozenAt: targetUser.frozenAt,
            college: targetUser.college
        }, req);
        
        res.json({ 
            success: true, 
            message: `${targetUser.name}'s account has been unfrozen. They can now log in again.`,
            user: {
                id: targetUser._id,
                name: targetUser.name,
                rgno: targetUser.rgno,
                accountFrozen: false
            }
        });
    } catch (error) {
        console.error('Unfreeze user error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get frozen users (for admins)
app.get('/api/auth/frozen-users', authenticateAndTouchSession, async (req, res) => {
    try {
        const admin = await User.findById(req.auth.decoded.userId);
        if (!admin) {
            return res.status(404).json({ success: false, error: 'Admin not found' });
        }
        
        // Only principal or super-admin can view frozen accounts
        if (!['principal', 'super-admin'].includes(admin.role)) {
            return res.status(403).json({ success: false, error: 'Not authorized' });
        }
        
        let query = { accountFrozen: true, isActive: true };
        
        if (admin.role === 'principal') {
            // Principals can only see frozen users in their college (excluding other principals)
            query.college = admin.college;
            query.role = { $ne: 'principal' };
        }
        // Super-admin can see all frozen users
        
        const frozenUsers = await User.find(query)
            .select('name email rgno role college department frozenAt frozenReason')
            .sort({ frozenAt: -1 });
        
        res.json({ 
            success: true, 
            frozenUsers: frozenUsers,
            count: frozenUsers.length
        });
    } catch (error) {
        console.error('Get frozen users error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get users in my college (college-scoped)
app.get('/api/auth/college-users', authenticateAndTouchSession, async (req, res) => {
    try {
        const user = await User.findById(req.auth.decoded.userId);
        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        // Only principal, hod, faculty, or super-admin can view college users
        if (!['principal', 'hod', 'faculty', 'super-admin'].includes(user.role)) {
            return res.status(403).json({ success: false, error: 'Not authorized' });
        }
        
        let query = { isActive: true };
        
        if (user.role === 'super-admin') {
            // Super-admin can see all users, optionally filter by college
            if (req.query.college) {
                query.college = req.query.college;
            }
        } else if (user.role === 'hod') {
            // HOD can only see users in their college AND department
            query.college = user.college;
            query.department = user.department;
        } else {
            // Principal/Faculty can only see users in their college
            query.college = user.college;
        }
        
        // Filter by role if specified
        if (req.query.role) {
            query.role = req.query.role;
        }
        
        // Filter by approval status if specified
        if (req.query.approvalStatus) {
            query.approvalStatus = req.query.approvalStatus;
        }
        
        // Filter by department if specified (for faculty viewing students)
        if (req.query.department) {
            query.department = req.query.department;
        }
        
        const users = await User.find(query)
            .select('-password -resetPasswordToken -resetPasswordExpires -twoFactorSecret')
            .sort({ role: 1, name: 1 });
        
        res.json({ success: true, users, count: users.length });
    } catch (error) {
        console.error('Get college users error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==================== SUPER-ADMIN ENDPOINTS ====================

// Super-admin: Get all users across all colleges
app.get('/api/auth/admin/all-users', authenticateAndTouchSession, async (req, res) => {
    try {
        const admin = await User.findById(req.auth.decoded.userId);
        if (!admin || admin.role !== 'super-admin') {
            return res.status(403).json({ success: false, error: 'Super-admin access required' });
        }
        
        const users = await User.find()
            .select('-password -resetPasswordToken -resetPasswordExpires -twoFactorSecret')
            .sort({ college: 1, role: 1, name: 1 });
        
        // Group by college
        const byCollege = {};
        users.forEach(u => {
            if (!byCollege[u.college]) {
                byCollege[u.college] = { principals: [], hods: [], faculty: [], students: [] };
            }
            if (u.role === 'principal') byCollege[u.college].principals.push(u);
            else if (u.role === 'hod') byCollege[u.college].hods.push(u);
            else if (u.role === 'faculty') byCollege[u.college].faculty.push(u);
            else if (u.role === 'student') byCollege[u.college].students.push(u);
        });
        
        res.json({ success: true, users, byCollege, totalCount: users.length });
    } catch (error) {
        console.error('Admin get all users error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Super-admin: Delete any user
app.delete('/api/auth/admin/delete-user/:userId', authenticateAndTouchSession, async (req, res) => {
    try {
        const admin = await User.findById(req.auth.decoded.userId);
        if (!admin || admin.role !== 'super-admin') {
            return res.status(403).json({ success: false, error: 'Super-admin access required' });
        }
        
        const targetUser = await User.findById(req.params.userId);
        if (!targetUser) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        // Prevent deleting self
        if (targetUser._id.toString() === admin._id.toString()) {
            return res.status(400).json({ success: false, error: 'Cannot delete your own account' });
        }
        
        // Create audit log before deletion
        await createAuditLog('USER_DELETED_BY_ADMIN', admin, targetUser, {
            deletedUserName: targetUser.name,
            deletedUserRole: targetUser.role,
            deletedUserCollege: targetUser.college
        }, req);
        
        // Invalidate all sessions
        await Session.updateMany(
            { userId: targetUser._id },
            { isExpired: true, expiredAt: new Date() }
        );
        
        // Delete user
        await User.findByIdAndDelete(req.params.userId);
        
        res.json({ success: true, message: `User ${targetUser.name} deleted successfully` });
    } catch (error) {
        console.error('Admin delete user error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Super-admin: Revoke all sessions for a user (emergency kick out)
app.post('/api/auth/admin/revoke-sessions/:userId', authenticateAndTouchSession, async (req, res) => {
    try {
        const admin = await User.findById(req.auth.decoded.userId);
        if (!admin || admin.role !== 'super-admin') {
            return res.status(403).json({ success: false, error: 'Super-admin access required' });
        }
        
        const targetUser = await User.findById(req.params.userId);
        if (!targetUser) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        // Revoke all sessions
        const result = await Session.updateMany(
            { userId: targetUser._id, isExpired: false },
            { isExpired: true, expiredAt: new Date() }
        );
        
        // Create audit log
        await createAuditLog('SESSIONS_REVOKED', admin, targetUser, {
            revokedCount: result.modifiedCount
        }, req);
        
        res.json({ 
            success: true, 
            message: `All sessions for ${targetUser.name} have been revoked`,
            revokedCount: result.modifiedCount
        });
    } catch (error) {
        console.error('Admin revoke sessions error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Super-admin: Revoke ALL sessions system-wide (emergency)
app.post('/api/auth/admin/revoke-all-sessions', authenticateAndTouchSession, async (req, res) => {
    try {
        const admin = await User.findById(req.auth.decoded.userId);
        if (!admin || admin.role !== 'super-admin') {
            return res.status(403).json({ success: false, error: 'Super-admin access required' });
        }
        
        const { excludeSelf } = req.body;
        
        let query = { isExpired: false };
        if (excludeSelf) {
            query.userId = { $ne: admin._id };
        }
        
        const result = await Session.updateMany(query, { 
            isExpired: true, 
            expiredAt: new Date() 
        });
        
        // Create audit log
        await createAuditLog('ALL_SESSIONS_REVOKED', admin, null, {
            revokedCount: result.modifiedCount,
            excludedSelf: excludeSelf
        }, req);
        
        res.json({ 
            success: true, 
            message: `${result.modifiedCount} sessions have been revoked`,
            revokedCount: result.modifiedCount
        });
    } catch (error) {
        console.error('Admin revoke all sessions error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Super-admin: Get audit logs
app.get('/api/auth/admin/audit-logs', authenticateAndTouchSession, async (req, res) => {
    try {
        const admin = await User.findById(req.auth.decoded.userId);
        if (!admin || admin.role !== 'super-admin') {
            return res.status(403).json({ success: false, error: 'Super-admin access required' });
        }
        
        const limit = parseInt(req.query.limit) || 100;
        const skip = parseInt(req.query.skip) || 0;
        
        let query = {};
        if (req.query.action) {
            query.action = req.query.action;
        }
        
        const logs = await AuditLog.find(query)
            .sort({ timestamp: -1 })
            .skip(skip)
            .limit(limit)
            .populate('performedBy', 'name rgno role')
            .populate('targetUser', 'name rgno role college');
        
        const total = await AuditLog.countDocuments(query);
        
        res.json({ success: true, logs, total, limit, skip });
    } catch (error) {
        console.error('Get audit logs error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Super-admin: Setup 2FA
app.post('/api/auth/admin/setup-2fa', authenticateAndTouchSession, async (req, res) => {
    try {
        const admin = await User.findById(req.auth.decoded.userId);
        if (!admin || admin.role !== 'super-admin') {
            return res.status(403).json({ success: false, error: 'Super-admin access required' });
        }
        
        const speakeasy = require('speakeasy');
        const qrcode = require('qrcode');
        
        // Generate secret
        const secret = speakeasy.generateSecret({
            name: `LOGI Super Admin (${admin.rgno})`,
            issuer: 'LOGI'
        });
        
        // Store secret temporarily (not enabled until verified)
        admin.twoFactorSecret = secret.base32;
        await admin.save();
        
        // Generate QR code
        const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);
        
        res.json({ 
            success: true, 
            secret: secret.base32,
            qrCode: qrCodeUrl,
            message: 'Scan the QR code with your authenticator app, then verify with a code'
        });
    } catch (error) {
        console.error('Setup 2FA error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Super-admin: Verify and enable 2FA
app.post('/api/auth/admin/verify-2fa', authenticateAndTouchSession, async (req, res) => {
    try {
        const { code } = req.body;
        const admin = await User.findById(req.auth.decoded.userId);
        if (!admin || admin.role !== 'super-admin') {
            return res.status(403).json({ success: false, error: 'Super-admin access required' });
        }
        
        if (!admin.twoFactorSecret) {
            return res.status(400).json({ success: false, error: '2FA setup not initiated' });
        }
        
        const speakeasy = require('speakeasy');
        const verified = speakeasy.totp.verify({
            secret: admin.twoFactorSecret,
            encoding: 'base32',
            token: code,
            window: 1
        });
        
        if (!verified) {
            return res.status(400).json({ success: false, error: 'Invalid verification code' });
        }
        
        admin.twoFactorEnabled = true;
        await admin.save();
        
        // Create audit log
        await createAuditLog('2FA_ENABLED', admin, null, {}, req);
        
        res.json({ success: true, message: 'Two-factor authentication enabled successfully' });
    } catch (error) {
        console.error('Verify 2FA error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Super-admin: Generate backup codes
app.post('/api/auth/admin/generate-backup-codes', authenticateAndTouchSession, async (req, res) => {
    try {
        const admin = await User.findById(req.auth.decoded.userId);
        if (!admin || admin.role !== 'super-admin') {
            return res.status(403).json({ success: false, error: 'Super-admin access required' });
        }
        
        if (!admin.twoFactorEnabled) {
            return res.status(400).json({ success: false, error: '2FA must be enabled first' });
        }
        
        // Generate 10 backup codes (8 characters each)
        const backupCodes = [];
        for (let i = 0; i < 10; i++) {
            const code = crypto.randomBytes(4).toString('hex').toUpperCase();
            backupCodes.push({ code, used: false });
        }
        
        admin.twoFactorBackupCodes = backupCodes;
        await admin.save();
        
        // Create audit log
        await createAuditLog('2FA_BACKUP_CODES_GENERATED', admin, null, { count: 10 }, req);
        
        res.json({ 
            success: true, 
            backupCodes: backupCodes.map(bc => bc.code),
            message: 'Backup codes generated. Save these codes in a safe place - they will only be shown once!'
        });
    } catch (error) {
        console.error('Generate backup codes error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Super-admin: Get backup codes status (how many remaining)
app.get('/api/auth/admin/backup-codes-status', authenticateAndTouchSession, async (req, res) => {
    try {
        const admin = await User.findById(req.auth.decoded.userId);
        if (!admin || admin.role !== 'super-admin') {
            return res.status(403).json({ success: false, error: 'Super-admin access required' });
        }
        
        const totalCodes = admin.twoFactorBackupCodes?.length || 0;
        const usedCodes = admin.twoFactorBackupCodes?.filter(bc => bc.used).length || 0;
        const remainingCodes = totalCodes - usedCodes;
        
        res.json({ 
            success: true, 
            totalCodes,
            usedCodes,
            remainingCodes,
            hasBackupCodes: totalCodes > 0
        });
    } catch (error) {
        console.error('Backup codes status error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Super-admin: View backup codes (requires password verification)
app.post('/api/auth/admin/view-backup-codes', authenticateAndTouchSession, async (req, res) => {
    try {
        const { password } = req.body;
        const admin = await User.findById(req.auth.decoded.userId);
        
        if (!admin || admin.role !== 'super-admin') {
            return res.status(403).json({ success: false, error: 'Super-admin access required' });
        }
        
        if (!admin.twoFactorEnabled) {
            return res.status(400).json({ success: false, error: '2FA is not enabled' });
        }
        
        // Password is required to view sensitive backup codes
        if (!password) {
            return res.status(400).json({ success: false, error: 'Password is required to view backup codes' });
        }
        
        const isPasswordValid = await verifyPassword(password, admin.password);
        if (!isPasswordValid) {
            return res.status(401).json({ success: false, error: 'Invalid password' });
        }
        
        // Return backup codes with their usage status
        const backupCodes = admin.twoFactorBackupCodes?.map(bc => ({
            code: bc.code,
            used: bc.used
        })) || [];
        
        res.json({ 
            success: true, 
            backupCodes,
            message: 'Backup codes retrieved successfully'
        });
    } catch (error) {
        console.error('View backup codes error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Super-admin: Disable 2FA
app.post('/api/auth/admin/disable-2fa', authenticateAndTouchSession, async (req, res) => {
    try {
        const { code, password } = req.body;
        const admin = await User.findById(req.auth.decoded.userId);
        if (!admin || admin.role !== 'super-admin') {
            return res.status(403).json({ success: false, error: 'Super-admin access required' });
        }
        
        // Verify password with bcrypt
        if (!await verifyPassword(password, admin.password)) {
            return res.status(401).json({ success: false, error: 'Invalid password' });
        }
        
        // Verify 2FA code if enabled
        if (admin.twoFactorEnabled && admin.twoFactorSecret) {
            const speakeasy = require('speakeasy');
            const verified = speakeasy.totp.verify({
                secret: admin.twoFactorSecret,
                encoding: 'base32',
                token: code,
                window: 1
            });
            if (!verified) {
                return res.status(400).json({ success: false, error: 'Invalid 2FA code' });
            }
        }
        
        admin.twoFactorEnabled = false;
        admin.twoFactorSecret = null;
        admin.twoFactorBackupCodes = []; // Clear backup codes when 2FA is disabled
        await admin.save();
        
        // Create audit log
        await createAuditLog('2FA_DISABLED', admin, null, {}, req);
        
        res.json({ success: true, message: 'Two-factor authentication disabled' });
    } catch (error) {
        console.error('Disable 2FA error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Super-admin: Reassign user to different college
app.post('/api/auth/admin/reassign-user/:userId', authenticateAndTouchSession, async (req, res) => {
    try {
        const { newCollege, newDepartment, newRole } = req.body;
        const admin = await User.findById(req.auth.decoded.userId);
        if (!admin || admin.role !== 'super-admin') {
            return res.status(403).json({ success: false, error: 'Super-admin access required' });
        }
        
        const targetUser = await User.findById(req.params.userId);
        if (!targetUser) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        // Validate new college
        if (newCollege && !VALID_COLLEGES.includes(newCollege)) {
            return res.status(400).json({ success: false, error: 'Invalid college' });
        }
        
        const oldValues = {
            college: targetUser.college,
            department: targetUser.department,
            role: targetUser.role
        };
        
        if (newCollege) targetUser.college = newCollege;
        if (newDepartment) targetUser.department = newDepartment;
        if (newRole && ['student', 'faculty', 'hod', 'principal'].includes(newRole)) {
            targetUser.role = newRole;
        }
        
        await targetUser.save();
        
        // Create audit log
        await createAuditLog('USER_REASSIGNED', admin, targetUser, {
            oldValues,
            newValues: { college: targetUser.college, department: targetUser.department, role: targetUser.role }
        }, req);
        
        res.json({ 
            success: true, 
            message: `User ${targetUser.name} has been reassigned`,
            user: {
                id: targetUser._id,
                name: targetUser.name,
                college: targetUser.college,
                department: targetUser.department,
                role: targetUser.role
            }
        });
    } catch (error) {
        console.error('Reassign user error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get list of valid colleges
app.get('/api/auth/colleges', (req, res) => {
    res.json({ success: true, colleges: VALID_COLLEGES });
});

// ==================== SUPER-ADMIN SUCCESSION SYSTEM (INVITATION-BASED) ====================
// Only ONE super-admin can exist at a time
// Flow: Super-admin invites → User accepts → Super-admin completes with password + 2FA

// Send invitation to become super-admin (super-admin only, principal/faculty only)
app.post('/api/auth/invite-super-admin-successor/:userId', authenticateAndTouchSession, async (req, res) => {
    try {
        const admin = await User.findById(req.auth.decoded.userId);
        if (!admin || admin.role !== 'super-admin') {
            return res.status(403).json({ success: false, error: 'Super-admin access required' });
        }
        
        // Check if there's already a pending invitation
        const existingInvitation = await User.findOne({
            superAdminInviteToken: { $exists: true, $ne: null },
            superAdminInviteExpires: { $gt: new Date() },
            superAdminInviteAccepted: { $ne: true }
        });
        
        if (existingInvitation) {
            return res.status(400).json({
                success: false,
                error: 'There is already a pending invitation. Cancel it first before inviting another user.',
                pendingUser: existingInvitation.name
            });
        }
        
        // Check if there's a pending completion (user accepted, waiting for admin to complete)
        const pendingCompletion = await User.findOne({
            superAdminInviteAccepted: true,
            superAdminTransferPendingCompletion: true
        });
        
        if (pendingCompletion) {
            return res.status(400).json({
                success: false,
                error: `${pendingCompletion.name} has already accepted an invitation. Complete or cancel the transfer first.`,
                awaitingCompletion: true,
                pendingUser: pendingCompletion.name
            });
        }
        
        const targetUser = await User.findById(req.params.userId);
        if (!targetUser) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        // Only allow inviting principals and faculty
        if (!['principal', 'faculty'].includes(targetUser.role)) {
            return res.status(400).json({
                success: false,
                error: 'Only principals and faculty can be invited as super-admin successors'
            });
        }
        
        // Generate secure invitation token (24 hours validity, one-time use)
        const inviteToken = crypto.randomBytes(32).toString('hex');
        const inviteExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
        
        targetUser.superAdminInviteToken = inviteToken;
        targetUser.superAdminInviteExpires = inviteExpires;
        targetUser.superAdminInviteAccepted = false;
        targetUser.superAdminInvitedBy = admin._id;
        targetUser.previousRole = targetUser.role;
        await targetUser.save();
        
        // Create audit log
        await createAuditLog('SUPER_ADMIN_INVITATION_SENT', admin, targetUser, {
            invitedUser: targetUser.name,
            invitedUserRgno: targetUser.rgno,
            expiresAt: inviteExpires
        }, req);
        
        // Send email notification to invited user
        try {
            if (targetUser.email) {
                await sendEmail({
                    from: `"LOGI System" <${process.env.EMAIL_USER}>`,
                    to: targetUser.email,
                    subject: '👑 You have been invited to become Super-Admin',
                    html: `
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <h2 style="color: #667eea;">Super-Admin Invitation</h2>
                            <p>The current super-admin (<strong>${admin.name}</strong>) has invited you to become the new super-admin of the LOGI system.</p>
                            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 15px 0;">
                                <p><strong>⏰ This invitation expires in 24 hours</strong></p>
                                <p><strong>📌 One-time use only</strong></p>
                            </div>
                            <div style="background: #fff3cd; padding: 15px; border-radius: 8px; margin: 15px 0; border: 1px solid #ffc107;">
                                <p><strong>Important:</strong></p>
                                <ul>
                                    <li>You will gain full administrative control of the system</li>
                                    <li>You will need to set up Two-Factor Authentication (2FA)</li>
                                    <li>The current super-admin will be demoted to a regular user</li>
                                </ul>
                            </div>
                            <p>To accept this invitation, log in to LOGI and check your notifications.</p>
                            <p style="color: #d32f2f;">If you did not expect this invitation, please ignore it.</p>
                        </div>
                    `
                });
            }
        } catch (emailError) {
            console.error('[SUPER-ADMIN INVITATION] Email notification failed:', emailError.message);
        }
        
        res.json({
            success: true,
            message: `Invitation sent to ${targetUser.name}. They have 24 hours to accept.`,
            expiresAt: inviteExpires
        });
        
    } catch (error) {
        console.error('Send invitation error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get pending invitation status (super-admin only)
app.get('/api/auth/super-admin-invitation-status', authenticateAndTouchSession, async (req, res) => {
    try {
        const admin = await User.findById(req.auth.decoded.userId);
        if (!admin || admin.role !== 'super-admin') {
            return res.status(403).json({ success: false, error: 'Super-admin access required' });
        }
        
        // Find any pending invitation
        const pendingInvitation = await User.findOne({
            superAdminInviteToken: { $exists: true, $ne: null },
            superAdminInviteExpires: { $gt: new Date() }
        }).select('name email rgno role college superAdminInviteExpires superAdminInviteAccepted superAdminInviteAcceptedAt');
        
        // Find if someone has accepted and is waiting for completion
        const awaitingCompletion = await User.findOne({
            superAdminInviteAccepted: true,
            superAdminTransferPendingCompletion: true
        }).select('name email rgno role college superAdminInviteAcceptedAt');
        
        // Check if there's a grace period active (for reversal)
        const gracePeriodActive = admin.superAdminTransferGracePeriodEnds && new Date() < admin.superAdminTransferGracePeriodEnds;
        
        res.json({
            success: true,
            pendingInvitation: pendingInvitation ? {
                user: pendingInvitation,
                expiresAt: pendingInvitation.superAdminInviteExpires,
                accepted: pendingInvitation.superAdminInviteAccepted
            } : null,
            awaitingCompletion: awaitingCompletion ? {
                user: awaitingCompletion,
                acceptedAt: awaitingCompletion.superAdminInviteAcceptedAt
            } : null,
            gracePeriodActive
        });
        
    } catch (error) {
        console.error('Get invitation status error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Cancel pending invitation (super-admin only)
app.post('/api/auth/cancel-super-admin-invitation', authenticateAndTouchSession, async (req, res) => {
    try {
        const admin = await User.findById(req.auth.decoded.userId);
        if (!admin || admin.role !== 'super-admin') {
            return res.status(403).json({ success: false, error: 'Super-admin access required' });
        }
        
        // Find and clear the invitation
        const invitedUser = await User.findOne({
            $or: [
                { superAdminInviteToken: { $exists: true, $ne: null } },
                { superAdminTransferPendingCompletion: true }
            ]
        });
        
        if (!invitedUser) {
            return res.status(400).json({ success: false, error: 'No pending invitation found' });
        }
        
        // Clear invitation fields
        invitedUser.superAdminInviteToken = null;
        invitedUser.superAdminInviteExpires = null;
        invitedUser.superAdminInviteAccepted = false;
        invitedUser.superAdminInviteAcceptedAt = null;
        invitedUser.superAdminInvitedBy = null;
        invitedUser.superAdminTransferPendingCompletion = false;
        await invitedUser.save();
        
        // Create audit log
        await createAuditLog('SUPER_ADMIN_INVITATION_CANCELLED', admin, invitedUser, {
            cancelledFor: invitedUser.name
        }, req);
        
        // Notify the user
        try {
            if (invitedUser.email) {
                await sendEmail({
                    from: `"LOGI System" <${process.env.EMAIL_USER}>`,
                    to: invitedUser.email,
                    subject: '❌ Super-Admin Invitation Cancelled',
                    html: `
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <h2 style="color: #d32f2f;">Invitation Cancelled</h2>
                            <p>The super-admin invitation has been cancelled by the current administrator.</p>
                        </div>
                    `
                });
            }
        } catch (emailError) {
            console.error('[SUPER-ADMIN INVITATION] Email notification failed:', emailError.message);
        }
        
        res.json({ success: true, message: 'Invitation cancelled successfully' });
        
    } catch (error) {
        console.error('Cancel invitation error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Check if current user has a pending invitation (for the invited user)
app.get('/api/auth/my-super-admin-invitation', authenticateAndTouchSession, async (req, res) => {
    try {
        const user = await User.findById(req.auth.decoded.userId)
            .populate('superAdminInvitedBy', 'name email rgno');
        
        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        // Check if user has a valid pending invitation
        const hasValidInvitation = user.superAdminInviteToken && 
                                   user.superAdminInviteExpires && 
                                   new Date() < user.superAdminInviteExpires &&
                                   !user.superAdminInviteAccepted;
        
        res.json({
            success: true,
            hasInvitation: hasValidInvitation,
            invitation: hasValidInvitation ? {
                expiresAt: user.superAdminInviteExpires,
                invitedBy: user.superAdminInvitedBy ? {
                    name: user.superAdminInvitedBy.name,
                    email: user.superAdminInvitedBy.email
                } : null
            } : null
        });
        
    } catch (error) {
        console.error('Check invitation error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Accept super-admin invitation (for the invited user)
app.post('/api/auth/accept-super-admin-invitation', authenticateAndTouchSession, async (req, res) => {
    try {
        const user = await User.findById(req.auth.decoded.userId);
        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        // Verify invitation is valid
        if (!user.superAdminInviteToken || !user.superAdminInviteExpires) {
            return res.status(400).json({ success: false, error: 'You do not have a pending invitation' });
        }
        
        if (new Date() > user.superAdminInviteExpires) {
            // Clear expired invitation
            user.superAdminInviteToken = null;
            user.superAdminInviteExpires = null;
            await user.save();
            return res.status(400).json({ success: false, error: 'Invitation has expired' });
        }
        
        if (user.superAdminInviteAccepted) {
            return res.status(400).json({ success: false, error: 'You have already accepted this invitation. Waiting for super-admin to complete the transfer.' });
        }
        
        // Mark as accepted
        user.superAdminInviteAccepted = true;
        user.superAdminInviteAcceptedAt = new Date();
        user.superAdminTransferPendingCompletion = true;
        await user.save();
        
        // Get current super-admin to notify
        const currentAdmin = await User.findOne({ role: 'super-admin' });
        
        // Create audit log
        await createAuditLog('SUPER_ADMIN_INVITATION_ACCEPTED', user, currentAdmin, {
            acceptedBy: user.name,
            acceptedByRgno: user.rgno
        }, req);
        
        // Notify current super-admin
        try {
            if (currentAdmin && currentAdmin.email) {
                await sendEmail({
                    from: `"LOGI System" <${process.env.EMAIL_USER}>`,
                    to: currentAdmin.email,
                    subject: '✅ Super-Admin Invitation Accepted - Action Required',
                    html: `
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <h2 style="color: #667eea;">Invitation Accepted!</h2>
                            <p><strong>${user.name}</strong> has accepted your super-admin succession invitation.</p>
                            <div style="background: #d4edda; padding: 15px; border-radius: 8px; margin: 15px 0; border: 1px solid #28a745;">
                                <p><strong>🔐 Action Required:</strong></p>
                                <p>Log in to your admin dashboard and complete the transfer by entering your password and 2FA code.</p>
                            </div>
                            <p style="color: #666;">User Details:</p>
                            <ul>
                                <li>Name: ${user.name}</li>
                                <li>RGNO: ${user.rgno}</li>
                                <li>Role: ${user.role}</li>
                                <li>College: ${user.college}</li>
                            </ul>
                        </div>
                    `
                });
            }
        } catch (emailError) {
            console.error('[SUPER-ADMIN INVITATION] Email notification failed:', emailError.message);
        }
        
        res.json({
            success: true,
            message: 'Invitation accepted! The current super-admin has been notified to complete the transfer.'
        });
        
    } catch (error) {
        console.error('Accept invitation error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Decline super-admin invitation (for the invited user)
app.post('/api/auth/decline-super-admin-invitation', authenticateAndTouchSession, async (req, res) => {
    try {
        const user = await User.findById(req.auth.decoded.userId);
        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        if (!user.superAdminInviteToken) {
            return res.status(400).json({ success: false, error: 'You do not have a pending invitation' });
        }
        
        const currentAdmin = await User.findOne({ role: 'super-admin' });
        
        // Clear invitation
        user.superAdminInviteToken = null;
        user.superAdminInviteExpires = null;
        user.superAdminInviteAccepted = false;
        user.superAdminInviteAcceptedAt = null;
        user.superAdminInvitedBy = null;
        user.superAdminTransferPendingCompletion = false;
        await user.save();
        
        // Create audit log
        await createAuditLog('SUPER_ADMIN_INVITATION_DECLINED', user, currentAdmin, {
            declinedBy: user.name
        }, req);
        
        // Notify current super-admin
        try {
            if (currentAdmin && currentAdmin.email) {
                await sendEmail({
                    from: `"LOGI System" <${process.env.EMAIL_USER}>`,
                    to: currentAdmin.email,
                    subject: '❌ Super-Admin Invitation Declined',
                    html: `
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <h2 style="color: #d32f2f;">Invitation Declined</h2>
                            <p><strong>${user.name}</strong> has declined your super-admin succession invitation.</p>
                            <p>You can invite another principal or faculty member from the admin dashboard.</p>
                        </div>
                    `
                });
            }
        } catch (emailError) {
            console.error('[SUPER-ADMIN INVITATION] Email notification failed:', emailError.message);
        }
        
        res.json({ success: true, message: 'Invitation declined' });
        
    } catch (error) {
        console.error('Decline invitation error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Complete super-admin transfer (requires password + 2FA from current super-admin)
app.post('/api/auth/complete-super-admin-transfer', authenticateAndTouchSession, async (req, res) => {
    try {
        const { password, twoFactorCode } = req.body;
        
        // Verify current super-admin
        const currentAdmin = await User.findById(req.auth.decoded.userId);
        if (!currentAdmin || currentAdmin.role !== 'super-admin') {
            return res.status(403).json({ success: false, error: 'Super-admin access required' });
        }
        
        // Find user who accepted the invitation
        const newAdmin = await User.findOne({
            superAdminInviteAccepted: true,
            superAdminTransferPendingCompletion: true
        });
        
        if (!newAdmin) {
            return res.status(400).json({
                success: false,
                error: 'No user has accepted an invitation yet'
            });
        }
        
        // Verify password
        if (!password) {
            return res.status(400).json({ success: false, error: 'Password is required' });
        }
        const isPasswordValid = await verifyPassword(password, currentAdmin.password);
        if (!isPasswordValid) {
            return res.status(401).json({ success: false, error: 'Invalid password' });
        }
        
        // Verify 2FA if enabled
        if (currentAdmin.twoFactorEnabled) {
            if (!twoFactorCode) {
                return res.status(400).json({
                    success: false,
                    requiresTwoFactor: true,
                    error: '2FA code is required for this high-security operation'
                });
            }
            
            const isBackupCode = twoFactorCode.length === 8;
            let verified = false;
            
            if (isBackupCode) {
                const backupCodeIndex = currentAdmin.twoFactorBackupCodes.findIndex(
                    bc => bc.code === twoFactorCode.toUpperCase() && !bc.used
                );
                if (backupCodeIndex !== -1) {
                    currentAdmin.twoFactorBackupCodes[backupCodeIndex].used = true;
                    verified = true;
                }
            } else {
                const speakeasy = require('speakeasy');
                verified = speakeasy.totp.verify({
                    secret: currentAdmin.twoFactorSecret,
                    encoding: 'base32',
                    token: twoFactorCode,
                    window: 1
                });
            }
            
            if (!verified) {
                return res.status(401).json({ success: false, error: 'Invalid 2FA code' });
            }
        }
        
        // Store old admin's info for email
        const oldAdminEmail = currentAdmin.email;
        const oldAdminName = currentAdmin.name;
        
        // === PERFORM THE TRANSFER ===
        
        // 1. Demote current super-admin to regular user (student role)
        currentAdmin.role = 'student';
        currentAdmin.demotedFromSuperAdmin = true;
        currentAdmin.demotedAt = new Date();
        currentAdmin.superAdminTransferGracePeriodEnds = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
        // Revoke all 2FA settings
        currentAdmin.twoFactorEnabled = false;
        currentAdmin.twoFactorSecret = null;
        currentAdmin.twoFactorBackupCodes = [];
        currentAdmin.department = null;
        await currentAdmin.save();
        
        // 2. Promote new user to super-admin
        // Save their previous college/department so we can restore if reclaimed
        newAdmin.previousRole = newAdmin.role;
        newAdmin.previousCollege = newAdmin.college;
        newAdmin.previousDepartment = newAdmin.department;
        newAdmin.role = 'super-admin';
        newAdmin.college = 'SYSTEM';
        newAdmin.department = 'Administration';
        newAdmin.approvalStatus = 'approved';
        // Clear invitation fields
        newAdmin.superAdminInviteToken = null;
        newAdmin.superAdminInviteExpires = null;
        newAdmin.superAdminInviteAccepted = false;
        newAdmin.superAdminInviteAcceptedAt = null;
        newAdmin.superAdminInvitedBy = null;
        newAdmin.superAdminTransferPendingCompletion = false;
        await newAdmin.save();
        
        // 3. Invalidate all sessions for old admin
        await Session.updateMany(
            { userId: currentAdmin._id },
            { isExpired: true, expiredAt: new Date() }
        );
        
        // 4. Create audit log
        await createAuditLog('SUPER_ADMIN_TRANSFER_COMPLETED', currentAdmin, newAdmin, {
            oldAdminName: oldAdminName,
            oldAdminRgno: currentAdmin.rgno,
            newAdminName: newAdmin.name,
            newAdminRgno: newAdmin.rgno,
            gracePeriodEnds: currentAdmin.superAdminTransferGracePeriodEnds
        }, req);
        
        // 5. Send email notifications
        try {
            // Email to old admin
            if (oldAdminEmail) {
                await sendEmail({
                    from: `"LOGI System" <${process.env.EMAIL_USER}>`,
                    to: oldAdminEmail,
                    subject: '⚠️ Super-Admin Transfer Completed',
                    html: `
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <h2 style="color: #d32f2f;">Super-Admin Transfer Completed</h2>
                            <p>You have completed the transfer of super-admin privileges to:</p>
                            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 15px 0;">
                                <p><strong>New Super-Admin:</strong> ${newAdmin.name}</p>
                                <p><strong>RGNO:</strong> ${newAdmin.rgno}</p>
                            </div>
                            <p><strong>Your account changes:</strong></p>
                            <ul>
                                <li>Your role has been changed to: <strong>Student</strong></li>
                                <li>Your 2FA settings have been revoked</li>
                                <li>All your active sessions have been invalidated</li>
                            </ul>
                            <div style="background: #d4edda; padding: 15px; border-radius: 8px; margin: 15px 0; border: 1px solid #28a745;">
                                <p style="color: #155724; font-weight: bold;">🔐 24-Hour Safety Period</p>
                                <p style="color: #155724; margin: 10px 0 0;">If this was a mistake or if the new super-admin is not cooperating, you can <strong>RECLAIM</strong> your super-admin access within 24 hours.</p>
                                <p style="color: #155724; margin: 10px 0 0;">Simply log in and go to your Profile page - you'll see the reclaim option.</p>
                            </div>
                        </div>
                    `
                });
            }
            
            // Email to new admin
            if (newAdmin.email) {
                await sendEmail({
                    from: `"LOGI System" <${process.env.EMAIL_USER}>`,
                    to: newAdmin.email,
                    subject: '🎉 You are now the Super-Admin',
                    html: `
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <h2 style="color: #667eea;">Congratulations! You are now the Super-Admin</h2>
                            <p>The transfer has been completed by ${oldAdminName}.</p>
                            <div style="background: #fff3cd; padding: 15px; border-radius: 8px; margin: 15px 0; border: 1px solid #ffc107;">
                                <p><strong>🔐 Important Security Steps:</strong></p>
                                <ol>
                                    <li>Log in to the system immediately</li>
                                    <li>Set up Two-Factor Authentication (2FA)</li>
                                    <li>Review and update your password if needed</li>
                                </ol>
                            </div>
                            <p style="color: #d32f2f;">⚠️ There is a 24-hour grace period during which the transfer can be reversed.</p>
                        </div>
                    `
                });
            }
        } catch (emailError) {
            console.error('[SUPER-ADMIN TRANSFER] Email notification failed:', emailError.message);
        }
        
        res.json({
            success: true,
            message: 'Super-admin transfer completed successfully. You have been logged out.',
            newAdminName: newAdmin.name,
            gracePeriodEnds: currentAdmin.superAdminTransferGracePeriodEnds
        });
        
    } catch (error) {
        console.error('Complete transfer error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Reverse super-admin transfer (within 24-hour grace period, by new super-admin)
app.post('/api/auth/reverse-super-admin-transfer', authenticateAndTouchSession, async (req, res) => {
    try {
        const { password, twoFactorCode } = req.body;
        
        // Current user must be the NEW super-admin
        const currentAdmin = await User.findById(req.auth.decoded.userId);
        if (!currentAdmin || currentAdmin.role !== 'super-admin') {
            return res.status(403).json({ success: false, error: 'Super-admin access required' });
        }
        
        // Verify password
        if (!password) {
            return res.status(400).json({ success: false, error: 'Password is required' });
        }
        const isPasswordValid = await verifyPassword(password, currentAdmin.password);
        if (!isPasswordValid) {
            return res.status(401).json({ success: false, error: 'Invalid password' });
        }
        
        // Verify 2FA if enabled
        if (currentAdmin.twoFactorEnabled) {
            if (!twoFactorCode) {
                return res.status(400).json({
                    success: false,
                    requiresTwoFactor: true,
                    error: '2FA code is required for this high-security operation'
                });
            }
            
            const isBackupCode = twoFactorCode.length === 8;
            let verified = false;
            
            if (isBackupCode) {
                const backupCodeIndex = currentAdmin.twoFactorBackupCodes.findIndex(
                    bc => bc.code === twoFactorCode.toUpperCase() && !bc.used
                );
                if (backupCodeIndex !== -1) {
                    currentAdmin.twoFactorBackupCodes[backupCodeIndex].used = true;
                    verified = true;
                }
            } else {
                const speakeasy = require('speakeasy');
                verified = speakeasy.totp.verify({
                    secret: currentAdmin.twoFactorSecret,
                    encoding: 'base32',
                    token: twoFactorCode,
                    window: 1
                });
            }
            
            if (!verified) {
                return res.status(401).json({ success: false, error: 'Invalid 2FA code' });
            }
        }
        
        // Find the old admin (who was demoted)
        const oldAdmin = await User.findOne({
            demotedFromSuperAdmin: true,
            superAdminTransferGracePeriodEnds: { $gt: new Date() }
        });
        
        if (!oldAdmin) {
            return res.status(400).json({
                success: false,
                error: 'No eligible previous super-admin found or grace period has expired'
            });
        }
        
        // === PERFORM THE REVERSAL ===
        
        const currentAdminName = currentAdmin.name;
        
        // 1. Demote current (new) super-admin back to their previous role
        currentAdmin.role = currentAdmin.previousRole || 'student';
        // Restore their original college and department
        currentAdmin.college = currentAdmin.previousCollege || currentAdmin.college;
        currentAdmin.department = currentAdmin.previousDepartment || currentAdmin.department;
        // Clear previous fields
        currentAdmin.previousRole = null;
        currentAdmin.previousCollege = null;
        currentAdmin.previousDepartment = null;
        // Revoke 2FA
        currentAdmin.twoFactorEnabled = false;
        currentAdmin.twoFactorSecret = null;
        currentAdmin.twoFactorBackupCodes = [];
        await currentAdmin.save();
        
        // 2. Restore old admin to super-admin
        oldAdmin.role = 'super-admin';
        oldAdmin.demotedFromSuperAdmin = false;
        oldAdmin.superAdminTransferGracePeriodEnds = null;
        oldAdmin.college = 'SYSTEM';
        oldAdmin.department = 'Administration';
        await oldAdmin.save();
        
        // 3. Invalidate sessions for the demoted admin
        await Session.updateMany(
            { userId: currentAdmin._id },
            { isExpired: true, expiredAt: new Date() }
        );
        
        // 4. Create audit log
        await createAuditLog('SUPER_ADMIN_TRANSFER_REVERSED', currentAdmin, oldAdmin, {
            reversedBy: currentAdminName,
            restoredAdmin: oldAdmin.name,
            restoredAdminRgno: oldAdmin.rgno
        }, req);
        
        // 5. Send email notification
        try {
            if (oldAdmin.email) {
                await sendEmail({
                    from: `"LOGI System" <${process.env.EMAIL_USER}>`,
                    to: oldAdmin.email,
                    subject: '🔄 Super-Admin Transfer Reversed',
                    html: `
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <h2 style="color: #667eea;">Transfer Reversed - You are Super-Admin Again</h2>
                            <p>The super-admin transfer has been reversed by ${currentAdminName}.</p>
                            <p>You have been restored as the super-admin.</p>
                            <p style="color: #d32f2f; font-weight: bold;">⚠️ Important: Your 2FA settings were cleared. Please set up 2FA again immediately.</p>
                        </div>
                    `
                });
            }
        } catch (emailError) {
            console.error('[SUPER-ADMIN TRANSFER] Email notification failed:', emailError.message);
        }
        
        res.json({
            success: true,
            message: 'Super-admin transfer reversed successfully. The previous admin has been restored.',
            restoredAdminName: oldAdmin.name
        });
        
    } catch (error) {
        console.error('Reverse transfer error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Reclaim super-admin (within 24-hour grace period, by OLD/demoted super-admin)
// This is the SAFETY MECHANISM if the new super-admin is malicious or transfer was a mistake
app.post('/api/auth/reclaim-super-admin', authenticateAndTouchSession, async (req, res) => {
    try {
        const { password } = req.body;
        
        // Current user must be the OLD demoted super-admin
        const oldAdmin = await User.findById(req.auth.decoded.userId);
        if (!oldAdmin) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        // Check if this user was recently demoted from super-admin
        if (!oldAdmin.demotedFromSuperAdmin) {
            return res.status(403).json({ 
                success: false, 
                error: 'You were not recently demoted from super-admin' 
            });
        }
        
        // Check if within grace period
        if (!oldAdmin.superAdminTransferGracePeriodEnds || new Date() > oldAdmin.superAdminTransferGracePeriodEnds) {
            return res.status(400).json({ 
                success: false, 
                error: '24-hour grace period has expired. You can no longer reclaim super-admin access.' 
            });
        }
        
        // Verify password
        if (!password) {
            return res.status(400).json({ success: false, error: 'Password is required' });
        }
        const isPasswordValid = await verifyPassword(password, oldAdmin.password);
        if (!isPasswordValid) {
            return res.status(401).json({ success: false, error: 'Invalid password' });
        }
        
        // Find current super-admin (the one who was promoted)
        const currentAdmin = await User.findOne({ role: 'super-admin' });
        if (!currentAdmin) {
            return res.status(500).json({ success: false, error: 'No current super-admin found - system error' });
        }
        
        // === PERFORM THE RECLAIM ===
        
        const oldAdminName = oldAdmin.name;
        const currentAdminName = currentAdmin.name;
        
        // 1. Demote current super-admin back to their previous role
        currentAdmin.role = currentAdmin.previousRole || 'student';
        // Restore their original college and department
        currentAdmin.college = currentAdmin.previousCollege || currentAdmin.college;
        currentAdmin.department = currentAdmin.previousDepartment || currentAdmin.department;
        // Clear previous fields
        currentAdmin.previousRole = null;
        currentAdmin.previousCollege = null;
        currentAdmin.previousDepartment = null;
        // Revoke their 2FA
        currentAdmin.twoFactorEnabled = false;
        currentAdmin.twoFactorSecret = null;
        currentAdmin.twoFactorBackupCodes = [];
        // Clear invitation fields
        currentAdmin.superAdminInviteToken = null;
        currentAdmin.superAdminInviteExpires = null;
        currentAdmin.superAdminInviteAccepted = false;
        currentAdmin.superAdminInvitedBy = null;
        await currentAdmin.save();
        
        // 2. Restore old admin to super-admin
        oldAdmin.role = 'super-admin';
        oldAdmin.demotedFromSuperAdmin = false;
        oldAdmin.superAdminTransferGracePeriodEnds = null;
        oldAdmin.college = 'SYSTEM';
        oldAdmin.department = 'Administration';
        await oldAdmin.save();
        
        // 3. Invalidate ALL sessions for the demoted admin (security measure)
        await Session.updateMany(
            { userId: currentAdmin._id },
            { isExpired: true, expiredAt: new Date() }
        );
        
        // 4. Create audit log
        await createAuditLog('SUPER_ADMIN_RECLAIMED', oldAdmin, currentAdmin, {
            reclaimedBy: oldAdminName,
            demotedAdmin: currentAdminName,
            demotedAdminRgno: currentAdmin.rgno,
            reason: 'Grace period reclaim by previous super-admin'
        }, req);
        
        // 5. Send email notifications
        try {
            // Email to reclaiming admin
            if (oldAdmin.email) {
                await sendEmail({
                    from: `"LOGI System" <${process.env.EMAIL_USER}>`,
                    to: oldAdmin.email,
                    subject: '🔐 Super-Admin Access Reclaimed',
                    html: `
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <h2 style="color: #667eea;">Super-Admin Access Restored</h2>
                            <p>You have successfully reclaimed your super-admin privileges.</p>
                            <div style="background: #d4edda; padding: 15px; border-radius: 8px; margin: 15px 0; border: 1px solid #28a745;">
                                <p><strong>✓ You are now the super-admin again</strong></p>
                                <p>${currentAdminName} has been demoted to ${currentAdmin.previousRole || 'student'}</p>
                            </div>
                            <p style="color: #d32f2f; font-weight: bold;">⚠️ Important: Please set up 2FA again immediately for security.</p>
                        </div>
                    `
                });
            }
            
            // Email to demoted admin
            if (currentAdmin.email) {
                await sendEmail({
                    from: `"LOGI System" <${process.env.EMAIL_USER}>`,
                    to: currentAdmin.email,
                    subject: '⚠️ Super-Admin Access Revoked',
                    html: `
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <h2 style="color: #d32f2f;">Super-Admin Access Revoked</h2>
                            <p>The previous super-admin (${oldAdminName}) has reclaimed their super-admin privileges within the 24-hour grace period.</p>
                            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 15px 0;">
                                <p><strong>Your new role:</strong> ${currentAdmin.previousRole || 'Student'}</p>
                                <p><strong>Your 2FA settings have been cleared</strong></p>
                                <p><strong>All your sessions have been invalidated</strong></p>
                            </div>
                        </div>
                    `
                });
            }
        } catch (emailError) {
            console.error('[SUPER-ADMIN RECLAIM] Email notification failed:', emailError.message);
        }
        
        res.json({
            success: true,
            message: 'Super-admin access reclaimed successfully! Please set up 2FA again.',
            demotedUser: currentAdminName
        });
        
    } catch (error) {
        console.error('Reclaim super-admin error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Check if current user can reclaim super-admin (for UI)
app.get('/api/auth/can-reclaim-super-admin', authenticateAndTouchSession, async (req, res) => {
    try {
        const user = await User.findById(req.auth.decoded.userId);
        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        const canReclaim = user.demotedFromSuperAdmin && 
                          user.superAdminTransferGracePeriodEnds && 
                          new Date() < user.superAdminTransferGracePeriodEnds;
        
        const remainingTime = canReclaim 
            ? Math.max(0, user.superAdminTransferGracePeriodEnds - new Date()) 
            : 0;
        
        res.json({
            success: true,
            canReclaim,
            gracePeriodEnds: user.superAdminTransferGracePeriodEnds,
            remainingMs: remainingTime,
            remainingHours: Math.floor(remainingTime / (1000 * 60 * 60)),
            remainingMinutes: Math.floor((remainingTime % (1000 * 60 * 60)) / (1000 * 60))
        });
        
    } catch (error) {
        console.error('Check reclaim status error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==================== SUPER ADMIN SEED ENDPOINT ====================
// One-time use to create your super-admin account
// Access: GET /api/auth/seed-super-admin?secret=YOUR_SECRET_KEY
// After use, set SUPER_ADMIN_SEED_ENABLED=false in .env
app.get('/api/auth/seed-super-admin', async (req, res) => {
    try {
        // Security: Require secret key and feature flag
        const seedEnabled = process.env.SUPER_ADMIN_SEED_ENABLED === 'true';
        const seedSecret = process.env.SUPER_ADMIN_SEED_SECRET;
        
        if (!seedEnabled) {
            return res.status(403).json({ 
                success: false, 
                error: 'Super admin seeding is disabled. Set SUPER_ADMIN_SEED_ENABLED=true in .env' 
            });
        }
        
        if (!seedSecret || req.query.secret !== seedSecret) {
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid seed secret. Pass ?secret=YOUR_SECRET' 
            });
        }
        
        // Check if super-admin already exists
        const existingSuperAdmin = await User.findOne({ role: 'super-admin' });
        if (existingSuperAdmin) {
            return res.status(400).json({ 
                success: false, 
                error: 'Super admin already exists',
                superAdmin: {
                    name: existingSuperAdmin.name,
                    email: existingSuperAdmin.email,
                    rgno: existingSuperAdmin.rgno
                }
            });
        }
        
        // Create super-admin with values from environment or defaults
        const superAdminData = {
            name: process.env.SUPER_ADMIN_NAME || 'System Administrator',
            email: process.env.SUPER_ADMIN_EMAIL || 'admin@logi.system',
            rgno: parseInt(process.env.SUPER_ADMIN_RGNO) || 999999999,
            password: await hashPassword(process.env.SUPER_ADMIN_PASSWORD || 'ChangeThisPassword123!'),
            role: 'super-admin',
            college: 'SYSTEM', // Super-admin is system-wide
            department: 'Administration',
            approvalStatus: 'approved', // Auto-approved
            approvedAt: new Date(),
            isActive: true
        };
        
        const superAdmin = new User(superAdminData);
        await superAdmin.save();
        
        console.log('✅ Super Admin created successfully!');
        console.log(`   Email: ${superAdminData.email}`);
        console.log(`   RGNO: ${superAdminData.rgno}`);
        
        res.json({
            success: true,
            message: 'Super admin created successfully! IMPORTANT: Set SUPER_ADMIN_SEED_ENABLED=false now!',
            superAdmin: {
                name: superAdminData.name,
                email: superAdminData.email,
                rgno: superAdminData.rgno,
                college: superAdminData.college
            },
            loginWith: {
                rgno: superAdminData.rgno,
                password: 'The password you set in SUPER_ADMIN_PASSWORD env var'
            }
        });
    } catch (error) {
        console.error('Seed super admin error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==================== NOTIFICATION SYSTEM ====================
// Notification Schema for in-app notifications
const notificationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { 
        type: String, 
        enum: ['logbook_review', 'logbook_approved', 'user_approved', 'user_rejected', 
               'security_alert', 'system', 'template_shared', 'password_reset'],
        required: true 
    },
    title: { type: String, required: true },
    message: { type: String, required: true },
    link: { type: String }, // Optional link to redirect
    read: { type: Boolean, default: false },
    priority: { type: String, enum: ['low', 'normal', 'high', 'urgent'], default: 'normal' },
    relatedUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    metadata: { type: mongoose.Schema.Types.Mixed }, // Additional data
    createdAt: { type: Date, default: Date.now },
    expiresAt: { type: Date } // Auto-delete after this date
});

notificationSchema.index({ userId: 1, read: 1, createdAt: -1 });
notificationSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // TTL index

const Notification = authConnection.model('Notification', notificationSchema);

// Logbook Template Schema
const templateSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String },
    category: { type: String, required: true }, // e.g., 'Electronics', 'Computer Science', 'Mechanical'
    content: { type: mongoose.Schema.Types.Mixed, required: true }, // Template structure/fields
    college: { type: String }, // If college-specific, otherwise null for global
    department: { type: String }, // If department-specific
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    createdByName: { type: String },
    isGlobal: { type: Boolean, default: false }, // Super-admin can create global templates
    isActive: { type: Boolean, default: true },
    usageCount: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

templateSchema.index({ college: 1, category: 1, isActive: 1 });
templateSchema.index({ isGlobal: 1, isActive: 1 });

const Template = authConnection.model('Template', templateSchema);

// Security Alert Schema for tracking suspicious activities
const securityAlertSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    userRgno: { type: Number, required: true },
    userRole: { type: String, required: true },
    alertType: { 
        type: String, 
        enum: ['failed_login', 'unusual_location', 'password_reset', 'brute_force', 'account_compromised'],
        required: true 
    },
    severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], required: true },
    details: { type: mongoose.Schema.Types.Mixed },
    ipAddress: { type: String },
    userAgent: { type: String },
    resolved: { type: Boolean, default: false },
    resolvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    resolvedAt: { type: Date },
    notifiedAdmin: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

securityAlertSchema.index({ userId: 1, createdAt: -1 });
securityAlertSchema.index({ alertType: 1, resolved: 1 });
securityAlertSchema.index({ userRole: 1, severity: 1 });

const SecurityAlert = authConnection.model('SecurityAlert', securityAlertSchema);

// Helper function to create notification
async function createNotification(userId, type, title, message, options = {}) {
    try {
        const notification = new Notification({
            userId,
            type,
            title,
            message,
            link: options.link,
            priority: options.priority || 'normal',
            relatedUser: options.relatedUser,
            metadata: options.metadata,
            expiresAt: options.expiresAt || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days default
        });
        await notification.save();
        return notification;
    } catch (error) {
        console.error('[NOTIFICATION] Error creating notification:', error);
        return null;
    }
}

// Helper function to create security alert and notify admin
async function createSecurityAlert(user, alertType, severity, details, req) {
    try {
        const alert = new SecurityAlert({
            userId: user._id,
            userRgno: user.rgno,
            userRole: user.role,
            alertType,
            severity,
            details,
            ipAddress: req?.ip || req?.headers?.['x-forwarded-for'] || 'unknown',
            userAgent: req?.headers?.['user-agent'] || 'unknown'
        });
        await alert.save();

        // For principals, notify super-admin
        if (user.role === 'principal' && (severity === 'high' || severity === 'critical')) {
            const superAdmin = await User.findOne({ role: 'super-admin' });
            if (superAdmin) {
                await createNotification(
                    superAdmin._id,
                    'security_alert',
                    '🚨 Principal Account Security Alert',
                    `Suspicious activity detected on principal account: ${user.name} (${user.college}). Type: ${alertType}`,
                    { priority: 'urgent', relatedUser: user._id, metadata: { alertId: alert._id } }
                );
                alert.notifiedAdmin = true;
                await alert.save();
            }
        }

        return alert;
    } catch (error) {
        console.error('[SECURITY ALERT] Error creating alert:', error);
        return null;
    }
}

// ==================== NOTIFICATION ENDPOINTS ====================

// Get user's notifications
app.get('/api/notifications', authenticateAndTouchSession, async (req, res) => {
    try {
        const userId = req.auth.decoded.userId;
        const limit = parseInt(req.query.limit) || 20;
        const page = parseInt(req.query.page) || 1;
        const unreadOnly = req.query.unread === 'true';

        const query = { userId };
        if (unreadOnly) query.read = false;

        const notifications = await Notification.find(query)
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(limit);

        const unreadCount = await Notification.countDocuments({ userId, read: false });
        const total = await Notification.countDocuments(query);

        res.json({
            success: true,
            notifications,
            unreadCount,
            total,
            page,
            totalPages: Math.ceil(total / limit)
        });
    } catch (error) {
        console.error('Get notifications error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Mark notification as read
app.put('/api/notifications/:id/read', authenticateAndTouchSession, async (req, res) => {
    try {
        const notification = await Notification.findOneAndUpdate(
            { _id: req.params.id, userId: req.auth.decoded.userId },
            { read: true },
            { new: true }
        );
        
        if (!notification) {
            return res.status(404).json({ success: false, error: 'Notification not found' });
        }

        res.json({ success: true, notification });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Mark all notifications as read
app.put('/api/notifications/read-all', authenticateAndTouchSession, async (req, res) => {
    try {
        await Notification.updateMany(
            { userId: req.auth.decoded.userId, read: false },
            { read: true }
        );
        res.json({ success: true, message: 'All notifications marked as read' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Delete notification
app.delete('/api/notifications/:id', authenticateAndTouchSession, async (req, res) => {
    try {
        await Notification.findOneAndDelete({ 
            _id: req.params.id, 
            userId: req.auth.decoded.userId 
        });
        res.json({ success: true, message: 'Notification deleted' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==================== ANALYTICS ENDPOINTS ====================

// Get dashboard analytics
app.get('/api/analytics/dashboard', authenticateAndTouchSession, async (req, res) => {
    try {
        const user = await User.findById(req.auth.decoded.userId);
        if (!user || !['super-admin', 'principal', 'hod', 'faculty'].includes(user.role)) {
            return res.status(403).json({ success: false, error: 'Access denied' });
        }

        const now = new Date();
        const thirtyDaysAgo = new Date(now - 30 * 24 * 60 * 60 * 1000);
        const sevenDaysAgo = new Date(now - 7 * 24 * 60 * 60 * 1000);

        // Build query based on role
        let userQuery = {};
        if (user.role === 'principal') {
            userQuery.college = user.college;
        } else if (user.role === 'hod') {
            userQuery.college = user.college;
            userQuery.department = user.department;
        } else if (user.role === 'faculty') {
            userQuery.college = user.college;
            userQuery.role = 'student';
        }

        // Get user statistics
        const totalUsers = await User.countDocuments(userQuery);
        const activeUsers = await User.countDocuments({ ...userQuery, approvalStatus: 'approved' });
        const pendingUsers = await User.countDocuments({ ...userQuery, approvalStatus: 'pending' });
        
        // New registrations in last 7 days
        const newRegistrations = await User.countDocuments({
            ...userQuery,
            createdAt: { $gte: sevenDaysAgo }
        });

        // Recent logins (users who logged in within 7 days)
        const recentLogins = await User.countDocuments({
            ...userQuery,
            lastLoginAt: { $gte: sevenDaysAgo }
        });

        // Users by role
        const usersByRole = await User.aggregate([
            { $match: userQuery },
            { $group: { _id: '$role', count: { $sum: 1 } } }
        ]);

        // Registrations per day (last 7 days)
        const registrationTrend = await User.aggregate([
            { 
                $match: { 
                    ...userQuery,
                    createdAt: { $gte: sevenDaysAgo } 
                } 
            },
            {
                $group: {
                    _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
                    count: { $sum: 1 }
                }
            },
            { $sort: { _id: 1 } }
        ]);

        // Approvals per day (last 7 days)
        const approvalTrend = await User.aggregate([
            { 
                $match: { 
                    ...userQuery,
                    approvedAt: { $gte: sevenDaysAgo } 
                } 
            },
            {
                $group: {
                    _id: { $dateToString: { format: '%Y-%m-%d', date: '$approvedAt' } },
                    count: { $sum: 1 }
                }
            },
            { $sort: { _id: 1 } }
        ]);

        // Security alerts (for super-admin only)
        let securityStats = null;
        if (user.role === 'super-admin') {
            const unresolvedAlerts = await SecurityAlert.countDocuments({ resolved: false });
            const criticalAlerts = await SecurityAlert.countDocuments({ severity: 'critical', resolved: false });
            const recentAlerts = await SecurityAlert.find({ resolved: false })
                .sort({ createdAt: -1 })
                .limit(5)
                .populate('userId', 'name email rgno role college');
            
            securityStats = {
                unresolvedAlerts,
                criticalAlerts,
                recentAlerts
            };
        }

        res.json({
            success: true,
            analytics: {
                overview: {
                    totalUsers,
                    activeUsers,
                    pendingUsers,
                    newRegistrations,
                    recentLogins
                },
                usersByRole: usersByRole.reduce((acc, item) => {
                    acc[item._id] = item.count;
                    return acc;
                }, {}),
                trends: {
                    registrations: registrationTrend,
                    approvals: approvalTrend
                },
                security: securityStats
            }
        });
    } catch (error) {
        console.error('Dashboard analytics error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==================== TEMPLATE LIBRARY ENDPOINTS ====================

// Get templates
app.get('/api/templates', authenticateAndTouchSession, async (req, res) => {
    try {
        const user = await User.findById(req.auth.decoded.userId);
        const category = req.query.category;

        // Build query - show global templates + college templates
        const query = {
            isActive: true,
            $or: [
                { isGlobal: true },
                { college: user.college }
            ]
        };
        
        if (category) query.category = category;

        const templates = await Template.find(query)
            .sort({ usageCount: -1, createdAt: -1 });

        res.json({ success: true, templates });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Create template (faculty, HOD, principal, super-admin)
app.post('/api/templates', authenticateAndTouchSession, async (req, res) => {
    try {
        const user = await User.findById(req.auth.decoded.userId);
        if (!user || !['super-admin', 'principal', 'hod', 'faculty'].includes(user.role)) {
            return res.status(403).json({ success: false, error: 'Access denied' });
        }

        const { name, description, category, content, isGlobal } = req.body;

        const template = new Template({
            name,
            description,
            category,
            content,
            college: user.role === 'super-admin' && isGlobal ? null : user.college,
            department: user.department,
            createdBy: user._id,
            createdByName: user.name,
            isGlobal: user.role === 'super-admin' && isGlobal
        });

        await template.save();

        res.json({ success: true, template, message: 'Template created successfully' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Update template
app.put('/api/templates/:id', authenticateAndTouchSession, async (req, res) => {
    try {
        const user = await User.findById(req.auth.decoded.userId);
        const template = await Template.findById(req.params.id);

        if (!template) {
            return res.status(404).json({ success: false, error: 'Template not found' });
        }

        // Only creator, principal of same college, or super-admin can edit
        const canEdit = template.createdBy.equals(user._id) ||
                       user.role === 'super-admin' ||
                       (user.role === 'principal' && template.college === user.college);

        if (!canEdit) {
            return res.status(403).json({ success: false, error: 'Not authorized to edit this template' });
        }

        const { name, description, category, content, isActive } = req.body;
        
        template.name = name || template.name;
        template.description = description !== undefined ? description : template.description;
        template.category = category || template.category;
        template.content = content || template.content;
        template.isActive = isActive !== undefined ? isActive : template.isActive;
        template.updatedAt = new Date();

        await template.save();

        res.json({ success: true, template, message: 'Template updated successfully' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Delete template
app.delete('/api/templates/:id', authenticateAndTouchSession, async (req, res) => {
    try {
        const user = await User.findById(req.auth.decoded.userId);
        const template = await Template.findById(req.params.id);

        if (!template) {
            return res.status(404).json({ success: false, error: 'Template not found' });
        }

        // Only creator, principal of same college, or super-admin can delete
        const canDelete = template.createdBy.equals(user._id) ||
                         user.role === 'super-admin' ||
                         (user.role === 'principal' && template.college === user.college);

        if (!canDelete) {
            return res.status(403).json({ success: false, error: 'Not authorized to delete this template' });
        }

        await template.deleteOne();

        res.json({ success: true, message: 'Template deleted successfully' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Increment template usage
app.post('/api/templates/:id/use', authenticateAndTouchSession, async (req, res) => {
    try {
        await Template.findByIdAndUpdate(req.params.id, { $inc: { usageCount: 1 } });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get template categories
app.get('/api/templates/categories', authenticateAndTouchSession, async (req, res) => {
    try {
        const categories = await Template.distinct('category', { isActive: true });
        res.json({ success: true, categories });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==================== SECURITY ALERTS ENDPOINTS ====================

// Get security alerts (super-admin only)
app.get('/api/security-alerts', authenticateAndTouchSession, async (req, res) => {
    try {
        const user = await User.findById(req.auth.decoded.userId);
        if (user.role !== 'super-admin') {
            return res.status(403).json({ success: false, error: 'Super-admin access required' });
        }

        const limit = parseInt(req.query.limit) || 50;
        const resolved = req.query.resolved;
        const severity = req.query.severity;

        const query = {};
        if (resolved !== undefined) query.resolved = resolved === 'true';
        if (severity) query.severity = severity;

        const alerts = await SecurityAlert.find(query)
            .sort({ createdAt: -1 })
            .limit(limit)
            .populate('userId', 'name email rgno role college');

        res.json({ success: true, alerts });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Resolve security alert
app.put('/api/security-alerts/:id/resolve', authenticateAndTouchSession, async (req, res) => {
    try {
        const user = await User.findById(req.auth.decoded.userId);
        if (user.role !== 'super-admin') {
            return res.status(403).json({ success: false, error: 'Super-admin access required' });
        }

        const alert = await SecurityAlert.findByIdAndUpdate(
            req.params.id,
            { 
                resolved: true, 
                resolvedBy: user._id, 
                resolvedAt: new Date() 
            },
            { new: true }
        );

        if (!alert) {
            return res.status(404).json({ success: false, error: 'Alert not found' });
        }

        res.json({ success: true, alert, message: 'Alert resolved' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==================== SUPER-ADMIN RECOVERY SYSTEM ====================
// Uses SUPER_ADMIN_RECOVERY_KEY environment variable for emergency access

// Step 1: Initiate recovery - validates recovery key and sends OTP to super-admin email
app.post('/api/auth/super-admin-recovery/initiate', async (req, res) => {
    try {
        const { recoveryKey } = req.body;
        const envRecoveryKey = process.env.SUPER_ADMIN_RECOVERY_KEY;

        if (!envRecoveryKey) {
            return res.status(503).json({ 
                success: false, 
                error: 'Recovery system not configured. Contact system administrator.' 
            });
        }

        if (recoveryKey !== envRecoveryKey) {
            // Log failed recovery attempt
            console.warn('[SECURITY] Failed super-admin recovery attempt - invalid key');
            return res.status(401).json({ success: false, error: 'Invalid recovery key' });
        }

        const superAdmin = await User.findOne({ role: 'super-admin' });
        if (!superAdmin) {
            return res.status(404).json({ success: false, error: 'No super-admin account found' });
        }

        // Generate 6-digit OTP
        const otp = crypto.randomInt(100000, 999999).toString();
        const otpExpiry = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

        // Store OTP in user record (reusing resetPasswordToken fields)
        superAdmin.resetPasswordToken = crypto.createHash('sha256').update(otp).digest('hex');
        superAdmin.resetPasswordExpires = otpExpiry;
        await superAdmin.save();

        // Send OTP to super-admin email
        try {
            await sendEmail({
                from: `"LOGI System Security" <${process.env.EMAIL_USER}>`,
                to: superAdmin.email,
                subject: '🔐 Super-Admin Account Recovery OTP',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #d32f2f;">🔐 Account Recovery Request</h2>
                        <p>A recovery request was initiated for your super-admin account.</p>
                        <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0; text-align: center;">
                            <p style="margin: 0; color: #666;">Your OTP code is:</p>
                            <h1 style="font-size: 36px; letter-spacing: 8px; color: #667eea; margin: 10px 0;">${otp}</h1>
                            <p style="margin: 0; color: #999; font-size: 12px;">Valid for 15 minutes</p>
                        </div>
                        <p style="color: #d32f2f;"><strong>⚠️ If you did not request this, your recovery key may be compromised!</strong></p>
                        <p>IP Address: ${req.ip || req.headers['x-forwarded-for'] || 'unknown'}</p>
                    </div>
                `
            });
        } catch (emailError) {
            console.error('[RECOVERY] Failed to send OTP email:', emailError);
            return res.status(500).json({ 
                success: false, 
                error: 'Failed to send OTP. Please try again.' 
            });
        }

        // Mask email for response
        const maskedEmail = superAdmin.email.replace(/(.{2})(.*)(@.*)/, '$1***$3');

        res.json({ 
            success: true, 
            message: `OTP sent to ${maskedEmail}`,
            expiresIn: '15 minutes'
        });
    } catch (error) {
        console.error('Super-admin recovery initiate error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Step 2: Verify OTP and reset password
app.post('/api/auth/super-admin-recovery/reset', async (req, res) => {
    try {
        const { otp, newPassword } = req.body;

        if (!otp || !newPassword) {
            return res.status(400).json({ success: false, error: 'OTP and new password required' });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({ success: false, error: 'Password must be at least 8 characters' });
        }

        const hashedOtp = crypto.createHash('sha256').update(otp).digest('hex');
        
        const superAdmin = await User.findOne({
            role: 'super-admin',
            resetPasswordToken: hashedOtp,
            resetPasswordExpires: { $gt: new Date() }
        });

        if (!superAdmin) {
            return res.status(400).json({ success: false, error: 'Invalid or expired OTP' });
        }

        // Reset password
        superAdmin.password = await hashPassword(newPassword);
        superAdmin.resetPasswordToken = undefined;
        superAdmin.resetPasswordExpires = undefined;
        superAdmin.failedLoginAttempts = 0;
        superAdmin.lockoutUntil = undefined;
        superAdmin.accountFrozen = false;
        await superAdmin.save();

        // Invalidate all sessions for security
        await Session.updateMany(
            { userId: superAdmin._id },
            { isExpired: true, expiredAt: new Date() }
        );

        // Create audit log
        await createAuditLog('SUPER_ADMIN_PASSWORD_RECOVERED', superAdmin, superAdmin, {
            method: 'recovery_key',
            ipAddress: req.ip || req.headers['x-forwarded-for']
        }, req);

        // Send confirmation email
        try {
            await sendEmail({
                from: `"LOGI System Security" <${process.env.EMAIL_USER}>`,
                to: superAdmin.email,
                subject: '✅ Password Reset Successful',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #4caf50;">✅ Password Reset Successful</h2>
                        <p>Your super-admin password has been reset successfully.</p>
                        <p>All existing sessions have been invalidated for security.</p>
                        <p><strong>Please login with your new password.</strong></p>
                        <p style="color: #d32f2f; margin-top: 20px;">
                            <strong>⚠️ Important:</strong> Consider changing your SUPER_ADMIN_RECOVERY_KEY 
                            in the environment variables if you suspect it may have been compromised.
                        </p>
                    </div>
                `
            });
        } catch (emailError) {
            console.error('[RECOVERY] Failed to send confirmation email:', emailError);
        }

        res.json({ 
            success: true, 
            message: 'Password reset successfully. Please login with your new password.' 
        });
    } catch (error) {
        console.error('Super-admin recovery reset error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.listen(PORT, () => {
    console.log(`Auth Server running on port ${PORT}`);
});

