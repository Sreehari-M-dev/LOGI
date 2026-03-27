/**
 * MongoDB Migration Script - Clean Up User Schema by Role
 * 
 * This script removes unnecessary fields from existing user documents
 * based on their role to save MongoDB storage space.
 * 
 * Run with: node migrate-cleanup-schema.js
 * 
 * IMPORTANT: 
 * - Backup your database before running this script!
 * - Test on a staging database first
 * - Run with DRY_RUN=true first to see what would change
 */

require('dotenv').config();
const mongoose = require('mongoose');

// Configuration
const DRY_RUN = process.env.DRY_RUN === 'true' || false; // Set to true to preview changes without applying
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/logi';

// Define which fields each role should KEEP
const BASE_FIELDS = [
    '_id', 'name', 'email', 'password', 'rgno', 'role', 'college', 
    'createdAt', 'isActive', 'approvalStatus', 'approvedBy', 'approvedAt',
    'rejectionReason', 'lastLoginAt', 'lastLoginIP', 'failedLoginAttempts', 
    'lockoutUntil', 'resetPasswordToken', 'resetPasswordExpires', '__v'
];

const ROLE_SPECIFIC_FIELDS = {
    'student': ['rollno', 'department', 'semester'],
    'faculty': ['department'],
    'principal': ['department', 'navbarPreferences'],
    'super-admin': ['department', 'twoFactorSecret', 'twoFactorEnabled', 'twoFactorBackupCodes', 'navbarPreferences']
};

// Fields to potentially remove (all role-specific fields that might exist on wrong roles)
const ALL_REMOVABLE_FIELDS = [
    'twoFactorSecret', 
    'twoFactorEnabled', 
    'twoFactorBackupCodes', 
    'navbarPreferences',
    'rollno',
    'semester'
];

// Calculate fields to remove for each role
function getFieldsToRemove(role) {
    const allowedFields = [...BASE_FIELDS, ...(ROLE_SPECIFIC_FIELDS[role] || [])];
    return ALL_REMOVABLE_FIELDS.filter(field => !allowedFields.includes(field));
}

// Connect to MongoDB
async function connectDB() {
    try {
        await mongoose.connect(MONGODB_URI);
        console.log('✅ Connected to MongoDB');
        console.log(`📍 Database: ${mongoose.connection.db.databaseName}`);
        return mongoose.connection.db;
    } catch (error) {
        console.error('❌ MongoDB connection error:', error);
        process.exit(1);
    }
}

// Get collection stats
async function getCollectionStats(db, collectionName) {
    try {
        const stats = await db.command({ collStats: collectionName });
        return {
            count: stats.count,
            size: (stats.size / 1024).toFixed(2) + ' KB',
            avgObjSize: (stats.avgObjSize || 0) + ' bytes'
        };
    } catch (error) {
        // Fallback if collStats doesn't work
        const count = await db.collection(collectionName).countDocuments();
        return {
            count: count,
            size: 'N/A',
            avgObjSize: 'N/A'
        };
    }
}

// Main migration function
async function migrateUsers() {
    const db = await connectDB();
    const usersCollection = db.collection('users');
    
    console.log('\n' + '='.repeat(60));
    console.log(DRY_RUN ? '🔍 DRY RUN MODE - No changes will be made' : '⚠️  LIVE MODE - Changes will be applied');
    console.log('='.repeat(60));
    
    // Get initial stats
    const initialStats = await getCollectionStats(db, 'users');
    console.log(`\n📊 Initial Collection Stats:`);
    console.log(`   Documents: ${initialStats.count}`);
    console.log(`   Total Size: ${initialStats.size}`);
    console.log(`   Avg Document Size: ${initialStats.avgObjSize}`);
    
    // Get all users grouped by role
    const roles = ['student', 'faculty', 'principal', 'super-admin'];
    const summary = {
        processed: 0,
        modified: 0,
        errors: 0,
        byRole: {}
    };
    
    for (const role of roles) {
        const fieldsToRemove = getFieldsToRemove(role);
        console.log(`\n🔧 Processing ${role}s...`);
        console.log(`   Fields to remove: ${fieldsToRemove.length > 0 ? fieldsToRemove.join(', ') : 'none'}`);
        
        if (fieldsToRemove.length === 0) {
            console.log(`   ✓ No cleanup needed for ${role}s`);
            continue;
        }
        
        // Find users with this role that have any of the fields to remove
        const query = {
            role: role,
            $or: fieldsToRemove.map(field => ({ [field]: { $exists: true } }))
        };
        
        const usersToUpdate = await usersCollection.find(query).toArray();
        console.log(`   Found ${usersToUpdate.length} ${role}(s) with unnecessary fields`);
        
        summary.byRole[role] = {
            found: usersToUpdate.length,
            updated: 0
        };
        
        for (const user of usersToUpdate) {
            summary.processed++;
            
            // Build $unset object for fields that actually exist on this document
            const unsetFields = {};
            const fieldsBeingRemoved = [];
            
            for (const field of fieldsToRemove) {
                if (user[field] !== undefined) {
                    unsetFields[field] = '';
                    fieldsBeingRemoved.push(field);
                }
            }
            
            if (Object.keys(unsetFields).length === 0) {
                continue; // No fields to remove
            }
            
            console.log(`   → User: ${user.name} (${user.rgno})`);
            console.log(`     Removing: ${fieldsBeingRemoved.join(', ')}`);
            
            if (!DRY_RUN) {
                try {
                    const result = await usersCollection.updateOne(
                        { _id: user._id },
                        { $unset: unsetFields }
                    );
                    
                    if (result.modifiedCount > 0) {
                        summary.modified++;
                        summary.byRole[role].updated++;
                        console.log(`     ✅ Updated successfully`);
                    }
                } catch (error) {
                    summary.errors++;
                    console.error(`     ❌ Error: ${error.message}`);
                }
            } else {
                summary.modified++;
                summary.byRole[role].updated++;
                console.log(`     📝 Would update (dry run)`);
            }
        }
    }
    
    // Get final stats (only in live mode)
    console.log('\n' + '='.repeat(60));
    console.log('📈 Migration Summary');
    console.log('='.repeat(60));
    console.log(`   Total processed: ${summary.processed}`);
    console.log(`   Documents ${DRY_RUN ? 'would be ' : ''}modified: ${summary.modified}`);
    console.log(`   Errors: ${summary.errors}`);
    
    console.log('\n   By Role:');
    for (const [role, stats] of Object.entries(summary.byRole)) {
        console.log(`   - ${role}: ${stats.found} found, ${stats.updated} ${DRY_RUN ? 'would be ' : ''}updated`);
    }
    
    if (!DRY_RUN && summary.modified > 0) {
        // Compact the collection to reclaim space (optional, may take time)
        console.log('\n🗜️  Running compact to reclaim space...');
        try {
            await db.command({ compact: 'users' });
            console.log('   ✅ Compaction complete');
        } catch (error) {
            console.log(`   ⚠️  Compaction skipped: ${error.message}`);
            console.log('   (This is normal for shared/free tier MongoDB Atlas)');
        }
        
        const finalStats = await getCollectionStats(db, 'users');
        console.log(`\n📊 Final Collection Stats:`);
        console.log(`   Documents: ${finalStats.count}`);
        console.log(`   Total Size: ${finalStats.size}`);
        console.log(`   Avg Document Size: ${finalStats.avgObjSize}`);
        
        // Calculate savings
        const initialSize = parseFloat(initialStats.size);
        const finalSize = parseFloat(finalStats.size);
        const savedKB = (initialSize - finalSize).toFixed(2);
        const savedPercent = ((initialSize - finalSize) / initialSize * 100).toFixed(1);
        
        if (savedKB > 0) {
            console.log(`\n💰 Storage Saved: ${savedKB} KB (${savedPercent}%)`);
        }
    }
    
    console.log('\n' + '='.repeat(60));
    if (DRY_RUN) {
        console.log('🔍 This was a DRY RUN. Run without DRY_RUN=true to apply changes.');
        console.log('   Command: node migrate-cleanup-schema.js');
    } else {
        console.log('✅ Migration complete!');
    }
    console.log('='.repeat(60));
    
    await mongoose.connection.close();
    console.log('\n🔌 Database connection closed');
}

// Run the migration
migrateUsers().catch(error => {
    console.error('Migration failed:', error);
    process.exit(1);
});
