/**
 * Reusable role-based authorization middleware for admin endpoints.
 * Replaces the duplicated hierarchy checks across 8+ endpoints.
 * 
 * Usage:
 *   const { authorizeHierarchy, loadTargetUser } = require('./middleware/authorizeHierarchy');
 *   app.post('/api/auth/approve-user/:userId', authenticate, loadTargetUser, authorizeHierarchy(), handler);
 */

const mongoose = require('mongoose');

/**
 * Middleware: Load the target user from req.params.userId and attach to req.targetUser.
 * Must be called before authorizeHierarchy.
 */
function loadTargetUser(UserModel) {
    return async (req, res, next) => {
        try {
            const targetUser = await UserModel.findById(req.params.userId);
            if (!targetUser) {
                return res.status(404).json({ success: false, error: 'User not found' });
            }
            req.targetUser = targetUser;
            next();
        } catch (error) {
            return res.status(500).json({ success: false, error: error.message });
        }
    };
}

/**
 * Middleware: Check if the authenticated admin is authorized to perform 
 * an action on req.targetUser based on role hierarchy.
 * 
 * Hierarchy rules:
 * - super-admin: can act on anyone except other super-admins
 * - principal: can act on HODs, faculty, and students in their college
 * - hod: can act on faculty and students in their college + department
 * - faculty: can act on students in their college (+ department if set)
 * 
 * @param {Object} options
 * @param {string[]} [options.allowedAdminRoles] - Roles allowed to perform this action.
 *   Defaults to ['super-admin', 'principal', 'hod', 'faculty'].
 * @param {boolean} [options.requireSuperAdmin] - If true, only super-admin is allowed.
 */
function authorizeHierarchy(UserModel, options = {}) {
    const {
        allowedAdminRoles = ['super-admin', 'principal', 'hod', 'faculty'],
        requireSuperAdmin = false
    } = options;

    return async (req, res, next) => {
        try {
            const admin = await UserModel.findById(req.auth.decoded.userId);
            if (!admin) {
                return res.status(404).json({ success: false, error: 'Admin not found' });
            }
            req.adminUser = admin;

            if (requireSuperAdmin) {
                if (admin.role !== 'super-admin') {
                    return res.status(403).json({ success: false, error: 'Super-admin access required' });
                }
                return next();
            }

            if (!allowedAdminRoles.includes(admin.role)) {
                return res.status(403).json({ success: false, error: 'Not authorized for this action' });
            }

            const targetUser = req.targetUser;
            if (!targetUser) {
                return next(); // No target user to check against (e.g. list endpoints)
            }

            // Super-admin can act on anyone except other super-admins
            if (admin.role === 'super-admin') {
                if (targetUser.role === 'super-admin' && targetUser._id.toString() !== admin._id.toString()) {
                    return res.status(403).json({ success: false, error: 'Cannot perform this action on another super-admin' });
                }
                return next();
            }

            // Cannot act on super-admins
            if (targetUser.role === 'super-admin') {
                return res.status(403).json({ success: false, error: 'Cannot perform this action on a super-admin account' });
            }

            let authorized = false;

            if (admin.role === 'principal') {
                // Principal: can act on HOD, faculty, students in their college (not other principals)
                const targetableRoles = ['hod', 'faculty', 'student'];
                authorized = targetableRoles.includes(targetUser.role) &&
                             admin.college === targetUser.college;
            } else if (admin.role === 'hod') {
                // HOD: can act on faculty, students in their college AND department
                const targetableRoles = ['faculty', 'student'];
                authorized = targetableRoles.includes(targetUser.role) &&
                             admin.college === targetUser.college &&
                             admin.department === targetUser.department;
            } else if (admin.role === 'faculty') {
                // Faculty: can act on students in their college (+ department if faculty has one)
                authorized = targetUser.role === 'student' &&
                             admin.college === targetUser.college;
                if (admin.department && targetUser.department) {
                    authorized = authorized && admin.department === targetUser.department;
                }
            }

            if (!authorized) {
                return res.status(403).json({ success: false, error: 'Not authorized to perform this action on this user' });
            }

            next();
        } catch (error) {
            return res.status(500).json({ success: false, error: error.message });
        }
    };
}

module.exports = { authorizeHierarchy, loadTargetUser };
