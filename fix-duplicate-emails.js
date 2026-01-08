/**
 * Fix duplicate emails in MongoDB
 * Removes duplicates, keeping the first occurrence
 */

const mongoose = require('mongoose');
require('dotenv').config();

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/LOGI';

mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(async () => {
    console.log('Connected to MongoDB');
    
    const userSchema = new mongoose.Schema({
        name: String,
        email: String,
        rgno: Number,
        password: String,
        role: String,
        createdAt: Date,
        isActive: Boolean,
        resetPasswordToken: String,
        resetPasswordExpires: Date
    });
    
    const User = mongoose.model('User', userSchema);
    
    try {
        // Find all emails and their counts
        console.log('\n[1] Checking for duplicate emails...\n');
        
        const duplicates = await User.aggregate([
            { $group: { _id: '$email', count: { $sum: 1 }, users: { $push: '$_id' } } },
            { $match: { count: { $gt: 1 } } },
            { $sort: { count: -1 } }
        ]);
        
        if (duplicates.length === 0) {
            console.log('✅ No duplicate emails found!');
        } else {
            console.log(`⚠️  Found ${duplicates.length} duplicate email(s):\n`);
            
            for (const dup of duplicates) {
                const email = dup._id || '(empty/null)';
                console.log(`Email: "${email}" - ${dup.count} users`);
                
                // Show affected users
                for (let i = 0; i < dup.users.length; i++) {
                    const user = await User.findById(dup.users[i]);
                    console.log(`  [${i + 1}] ${user.name} (rgno: ${user.rgno}, id: ${user._id})`);
                }
                console.log('');
            }
            
            // Remove duplicates: keep first, remove rest
            console.log('[2] Removing duplicate records (keeping first, removing rest)...\n');
            
            let removedCount = 0;
            for (const dup of duplicates) {
                // Keep the first user, remove the rest
                for (let i = 1; i < dup.users.length; i++) {
                    const result = await User.findByIdAndDelete(dup.users[i]);
                    console.log(`  Deleted: ${result.name} (rgno: ${result.rgno})`);
                    removedCount++;
                }
            }
            
            console.log(`\n✅ Removed ${removedCount} duplicate record(s)`);
        }
        
        // Now check if unique index exists and create it
        console.log('\n[3] Creating unique email index...\n');
        
        try {
            await User.collection.dropIndex('email_1');
            console.log('  Dropped old email index');
        } catch (e) {
            // Index doesn't exist, that's fine
        }
        
        await User.collection.createIndex({ email: 1 }, { unique: true, sparse: true });
        console.log('✅ Created unique email index');
        
        console.log('\n✅ All done! Email field is now unique.');
        
    } catch (error) {
        console.error('Error:', error.message);
    } finally {
        mongoose.connection.close();
    }
    
}).catch(err => {
    console.error('MongoDB connection error:', err);
});
