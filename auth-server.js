const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || process.env.AUTH_SERVICE_PORT || 3002;
const JWT_SECRET = process.env.JWT_SECRET;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/LOGI';
const JWT_EXPIRY = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds

// Require a secret before starting
if (!JWT_SECRET) {
    console.error('JWT_SECRET is not set. Please define it in the environment.');
    process.exit(1);
}

// Middleware
const allowedOrigins = [
    'https://sreehari-m-dev.github.io',
    'http://localhost:3000',
    'http://localhost:8080'
];

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
    email: { type: String, sparse: true }, // Optional for faculty
    rollno: { type: Number, sparse: true }, // For students
    rgno: { type: Number, required: true, unique: true }, // Unique identifier (Register Number)
    password: { type: String, required: true }, // Hashed
    role: { type: String, enum: ['student', 'faculty', 'admin'], default: 'student' },
    department: String,
    semester: Number,
    createdAt: { type: Date, default: Date.now },
    isActive: { type: Boolean, default: true }
});

const User = mongoose.model('User', userSchema);

// Simple password hashing using crypto
function hashPassword(password) {
    return crypto.createHash('sha256').update(password + JWT_SECRET).digest('hex');
}

// Verify password
function verifyPassword(password, hash) {
    return hashPassword(password) === hash;
}

// Simple JWT token generation (without external library)
function generateToken(userId, rgno, role) {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64');
    const now = Math.floor(Date.now() / 1000);
    const payload = {
        userId: userId.toString(),
        rgno: rgno,
        role: role,
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
        const { name, email, password, rollno, rgno, role, department, semester } = req.body;

        // Validation - rgno is required
        if (!name || !rgno || !password) {
            return res.status(400).json({ 
                success: false, 
                error: 'Name, register number, and password are required' 
            });
        }

        // Check if user already exists by register number
        const existingUser = await User.findOne({ rgno: parseInt(rgno) });
        if (existingUser) {
            return res.status(400).json({ 
                success: false, 
                error: 'Register number already registered' 
            });
        }

        // Hash password
        const hashedPassword = hashPassword(password);

        // Create new user
        const newUser = new User({
            name,
            email: email || null,
            password: hashedPassword,
            rollno: rollno ? parseInt(rollno) : null,
            rgno: parseInt(rgno),
            role: role || 'student',
            department,
            semester: semester ? parseInt(semester) : null
        });

        await newUser.save();

        // Generate token using rgno
        const token = generateToken(newUser._id, newUser.rgno, newUser.role);

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

        // Generate token using rgno
        const token = generateToken(user._id, user.rgno, user.role);

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
app.post('/api/auth/verify', (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ success: false, error: 'No token provided' });
        }

        const decoded = verifyToken(token);
        if (!decoded) {
            return res.status(401).json({ success: false, error: 'Invalid token' });
        }

        res.json({ 
            success: true, 
            user: decoded 
        });

    } catch (error) {
        res.status(401).json({ success: false, error: 'Invalid token' });
    }
});

// Get User Profile
app.get('/api/auth/profile', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ success: false, error: 'No token provided' });
        }

        const decoded = verifyToken(token);
        if (!decoded) {
            return res.status(401).json({ success: false, error: 'Invalid token' });
        }

        const user = await User.findById(decoded.userId).select('-password');
        
        res.json({ 
            success: true, 
            user 
        });

    } catch (error) {
        res.status(401).json({ success: false, error: 'Invalid token' });
    }
});

// Change Password Route
app.post('/api/auth/change-password', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const { currentPassword, newPassword } = req.body;

        if (!token) {
            return res.status(401).json({ success: false, error: 'No token provided' });
        }

        const decoded = verifyToken(token);
        if (!decoded) {
            return res.status(401).json({ success: false, error: 'Invalid token' });
        }

        const user = await User.findById(decoded.userId);

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
app.post('/api/auth/logout', (req, res) => {
    // In JWT, logout is typically handled on client-side by removing token
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
app.get('/api/auth/users', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ success: false, error: 'No token provided' });
        }

        const decoded = verifyToken(token);
        if (!decoded) {
            return res.status(401).json({ success: false, error: 'Invalid token' });
        }
        
        // Check if user is admin
        if (decoded.role !== 'admin') {
            return res.status(403).json({ success: false, error: 'Access denied' });
        }

        const users = await User.find().select('-password');
        res.json({ success: true, users });

    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'Auth Server running on port 3002' });
});

app.listen(PORT, () => {
    console.log(`Auth Server running on port ${PORT}`);
});

