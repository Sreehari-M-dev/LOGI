/**
 * Migration Script: Convert SHA-256 hashed passwords to bcrypt
 * 
 * This script will:
 * 1. Find all users with legacy SHA-256 passwords (64 hex characters)
 * 2. Keep the hashes as-is (they'll work via the legacy compatibility layer)
 * 3. When users log in next time with the correct password, their password 
 *    will be automatically upgraded to bcrypt through the login flow
 * 
 * NOTE: This script is for documentation purposes. The actual migration 
 * happens automatically when users log in, thanks to the backwards-compatible
 * verifyPassword() function in auth-server.js that detects legacy hashes.
 * 
 * If you want to force-migrate all passwords (requires knowing plaintext),
 * you would need to reset all passwords which is not recommended.
 * 
 * Run with: node migrate-passwords-to-bcrypt.js
 */

require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/LOGI';
const BCRYPT_SALT_ROUNDS = 12;

// User Schema (must match auth-server.js)
const userSchema = new mongoose.Schema({
    password: { type: String, required: true },
    name: String,
    rgno: Number,
    role: String
}, { strict: false });

const User = mongoose.model('User', userSchema);

async function analyzeMigrationStatus() {
    try {
        await mongoose.connect(MONGODB_URI);
        console.log('Connected to MongoDB\n');

        const allUsers = await User.find({}, 'name rgno role password');
        
        let legacyCount = 0;
        let bcryptCount = 0;
        
        console.log('=== Password Hash Analysis ===\n');
        
        for (const user of allUsers) {
            const isBcrypt = user.password && user.password.startsWith('$2');
            const hashType = isBcrypt ? 'bcrypt' : 'SHA-256 (legacy)';
            
            if (isBcrypt) {
                bcryptCount++;
            } else {
                legacyCount++;
            }
            
            console.log(`User: ${user.name || 'N/A'} (RGNO: ${user.rgno}) - Role: ${user.role}`);
            console.log(`  Hash Type: ${hashType}`);
            console.log(`  Hash Preview: ${user.password ? user.password.substring(0, 20) + '...' : 'N/A'}`);
            console.log('');
        }
        
        console.log('=== Summary ===');
        console.log(`Total Users: ${allUsers.length}`);
        console.log(`Bcrypt Hashes: ${bcryptCount}`);
        console.log(`Legacy SHA-256 Hashes: ${legacyCount}`);
        console.log('');
        
        if (legacyCount > 0) {
            console.log('📌 Note: Legacy hashes will automatically upgrade to bcrypt');
            console.log('   when users log in with their correct password.');
            console.log('   No manual migration is needed!');
        } else {
            console.log('✅ All passwords are using bcrypt!');
        }
        
    } catch (error) {
        console.error('Error:', error.message);
    } finally {
        await mongoose.disconnect();
        console.log('\nDisconnected from MongoDB');
    }
}

// Add automatic password upgrade on successful login
// This function can be called after successful login to upgrade legacy passwords
async function upgradePasswordIfLegacy(userId, plainPassword) {
    try {
        const user = await User.findById(userId);
        if (!user) return false;
        
        // Check if password is legacy (not bcrypt)
        if (user.password && !user.password.startsWith('$2')) {
            // Upgrade to bcrypt
            const newHash = await bcrypt.hash(plainPassword, BCRYPT_SALT_ROUNDS);
            user.password = newHash;
            await user.save();
            console.log(`✅ Upgraded password to bcrypt for user: ${user.rgno}`);
            return true;
        }
        return false;
    } catch (error) {
        console.error('Error upgrading password:', error.message);
        return false;
    }
}

// Run analysis
analyzeMigrationStatus();
