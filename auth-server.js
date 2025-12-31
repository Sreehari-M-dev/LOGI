// Load environment variables from .env for local development
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const cors = require('cors');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || process.env.AUTH_SERVICE_PORT || 3002;
const JWT_SECRET = process.env.JWT_SECRET;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/LOGI';
const JWT_EXPIRY = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds
const IDLE_TIMEOUT_MS = parseInt(process.env.IDLE_TIMEOUT_MS || '900000'); // 15 minutes default
const TOUCH_INTERVAL_MS = 60000; // update lastActivity at most once per minute

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
        'http://127.0.0.1:3003'
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
app.use(express.json());

// MongoDB Connection
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('Connected to MongoDB - Database: LOGI');
}).catch(err => {
    console.error('MongoDB connection error:', err);
});

// User Schema - using Register Number (rgno) as unique identifier
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true }, // Unique email for password reset flow
    rollno: { type: Number, sparse: true }, // For students
    rgno: { type: Number, required: true, unique: true }, // Unique identifier (Register Number)
    password: { type: String, required: true }, // Hashed
    role: { type: String, enum: ['student', 'faculty', 'admin'], default: 'student' },
    department: String,
    semester: Number,
    createdAt: { type: Date, default: Date.now },
    isActive: { type: Boolean, default: true },
    // Password reset fields
    resetPasswordToken: { type: String, default: undefined },
    resetPasswordExpires: { type: Date, default: undefined }
});

const User = mongoose.model('User', userSchema);

// Session Schema for idle timeout and server-side session tracking
const sessionSchema = new mongoose.Schema({
    sid: { type: String, required: true, unique: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    rgno: { type: Number, required: true },
    role: { type: String, required: true },
    lastActivity: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now },
    expiredAt: { type: Date },
    isExpired: { type: Boolean, default: false }
});
const Session = mongoose.model('Session', sessionSchema);

// Simple password hashing using crypto
function hashPassword(password) {
    return crypto.createHash('sha256').update(password + JWT_SECRET).digest('hex');
}

// Verify password
function verifyPassword(password, hash) {
    return hashPassword(password) === hash;
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

        const now = Date.now();
        const last = session.lastActivity ? session.lastActivity.getTime() : session.createdAt.getTime();
        if (now - last > IDLE_TIMEOUT_MS) {
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
        const now = Date.now();
        const last = session.lastActivity ? session.lastActivity.getTime() : session.createdAt.getTime();

        // If already expired by idle window
        if (now - last > IDLE_TIMEOUT_MS) {
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

// Register Route - using Register Number
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

        const rgno = rgnoRaw !== undefined && rgnoRaw !== null && rgnoRaw !== '' ? parseInt(rgnoRaw, 10) : null;
        const rollno = rollnoRaw !== undefined && rollnoRaw !== null && rollnoRaw !== '' ? parseInt(rollnoRaw, 10) : null;
        const semester = semesterRaw !== undefined && semesterRaw !== null && semesterRaw !== '' ? parseInt(semesterRaw, 10) : null;

        // Validation - rgno is required
        if (!name || !rgno || !password) {
            return res.status(400).json({ 
                success: false, 
                error: 'Name, register number, and password are required' 
            });
        }

        // Check if user already exists by register number
        const existingUser = await User.findOne({ rgno });
        if (existingUser) {
            return res.status(409).json({ 
                success: false, 
                error: 'This register number is already registered.' 
            });
        }

        // Hash password
        const hashedPassword = hashPassword(password);

        // Create new user
        const newUser = new User({
            name,
            email: email || null,
            password: hashedPassword,
            rollno: rollno || null,
            rgno,
            role: role || 'student',
            department: department || null,
            semester: semester || null
        });

        await newUser.save();

        // Create server-side session and generate token with session id (sid)
        const sid = crypto.randomBytes(16).toString('hex');
        await new Session({ sid, userId: newUser._id, rgno: newUser.rgno, role: newUser.role }).save();

        // Generate token using rgno + sid
        const token = generateToken(newUser._id, newUser.rgno, newUser.role, sid);

        res.status(201).json({
            success: true,
            message: 'Registration successful',
            token,
            user: {
                id: newUser._id,
                name: newUser.name,
                rgno: newUser.rgno,
                role: newUser.role,
                rollno: newUser.rollno
            }
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

// Login Route - using Register Number
app.post('/api/auth/login', async (req, res) => {
    try {
        const { rgno, password } = req.body;

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

        // Verify password
        const isPasswordValid = verifyPassword(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid register number or password' 
            });
        }

        // Create server-side session and generate token with session id (sid)
        const sid = crypto.randomBytes(16).toString('hex');
        await new Session({ sid, userId: user._id, rgno: user.rgno, role: user.role }).save();

        // Generate token using rgno + sid
        const token = generateToken(user._id, user.rgno, user.role, sid);

        res.json({
            success: true,
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                name: user.name,
                rgno: user.rgno,
                role: user.role,
                rollno: user.rollno,
                email: user.email
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Verify Token Route
app.post('/api/auth/verify', authenticateAndTouchSession, (req, res) => {
    try {
        // If middleware passed, session is valid and activity updated
        res.json({ success: true, user: req.auth.decoded });
    } catch (error) {
        res.status(401).json({ success: false, error: 'Invalid token' });
    }
});

// Get User Profile
app.get('/api/auth/profile', authenticateAndTouchSession, async (req, res) => {
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

// Change Password Route
app.post('/api/auth/change-password', authenticateAndTouchSession, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const user = await User.findById(req.auth.decoded.userId);

        // Verify current password
        const isValid = verifyPassword(currentPassword, user.password);
        if (!isValid) {
            return res.status(401).json({ success: false, error: 'Current password is incorrect' });
        }

        // Hash new password
        const hashedPassword = hashPassword(newPassword);

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

// Add these to your .env:
// EMAIL_USER=your_gmail_address@gmail.com
// EMAIL_PASS=your_gmail_app_password
// FRONTEND_URL=https://sreehari-m-dev.github.io/LOGI

const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://sreehari-m-dev.github.io/LOGI';

// Validate email credentials
if (!EMAIL_USER || !EMAIL_PASS) {
    console.warn('⚠️ EMAIL_USER or EMAIL_PASS not configured in .env - Password reset emails will not work');
}

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: EMAIL_USER,
        pass: EMAIL_PASS
    }
});

// Test transporter connection
if (EMAIL_USER && EMAIL_PASS) {
    transporter.verify((error, success) => {
        if (error) {
            console.error('❌ Email transporter error:', error.message);
        } else {
            console.log('✅ Email transporter ready');
        }
    });
}

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
        
        // Check if running locally or in production
        const isLocal = process.env.NODE_ENV !== 'production' && (process.env.FRONTEND_URL?.includes('localhost') || process.env.FRONTEND_URL?.includes('127.0.0.1'));
        if (isLocal) {
            console.log('[FORGOT PASSWORD] Running in local mode');
        } else {
            console.log('[FORGOT PASSWORD] Running in production mode');
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
            from: `LOGI <${EMAIL_USER}>`,
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
        await transporter.sendMail(mailOptions);
        console.log('[FORGOT PASSWORD] Email sent successfully');
        
        res.json({ success: true, message: 'Password reset email sent' });
    } catch (error) {
        console.error('[FORGOT PASSWORD] Error:', error.message);
        console.error('[FORGOT PASSWORD] Full error:', error);
        res.status(500).json({ success: false, error: 'Failed to send reset email: ' + error.message });
    }
});

// --- Password Reset: Reset Password Endpoint ---
app.post('/api/auth/reset-password/:token', async (req, res) => {
    try {
        const { token } = req.params;
        const { password } = req.body;
        if (!token || !password) {
            return res.status(400).json({ success: false, error: 'Token and new password are required' });
        }

        // Debug log for reset token
        console.log('[RESET PASSWORD] Token received:', token);

        // Find user by reset token and expiry
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            console.log('[RESET PASSWORD] Invalid or expired token');
            return res.status(400).json({ success: false, error: 'Invalid or expired token' });
        }

        console.log('[RESET PASSWORD] User found:', user);

        // Hash the new password
        const hashedPassword = hashPassword(password);
        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        // Save the updated user document
        await user.save();
        console.log('[RESET PASSWORD] Password updated successfully for user:', user.rgno);

        res.json({ success: true, message: 'Password has been reset successfully' });
    } catch (error) {
        console.error('[RESET PASSWORD] Error:', error);
        res.status(500).json({ success: false, error: 'Failed to reset password' });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'Auth Server running on port 3002' });
});

app.listen(PORT, () => {
    console.log(`Auth Server running on port ${PORT}`);
});

