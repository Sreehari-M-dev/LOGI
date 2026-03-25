/**
 * Email template helpers for LOGI.
 * Centralizes all inline HTML email templates from auth-server.js
 * into reusable functions. Each returns an HTML string.
 */

// Shared email wrapper
function emailWrapper(content) {
    return `<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">${content}</div>`;
}

function superAdminInvitation({ adminName, expiresIn = '24 hours' }) {
    return emailWrapper(`
        <h2 style="color: #667eea;">Super-Admin Invitation</h2>
        <p>The current super-admin (<strong>${adminName}</strong>) has invited you to become the new super-admin of the LOGI system.</p>
        <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 15px 0;">
            <p><strong>⏰ This invitation expires in ${expiresIn}</strong></p>
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
    `);
}

function superAdminInvitationCancelled() {
    return emailWrapper(`
        <h2 style="color: #d32f2f;">Invitation Cancelled</h2>
        <p>The super-admin invitation has been cancelled by the current administrator.</p>
    `);
}

function superAdminInvitationAccepted({ userName, userRgno, userRole, userCollege }) {
    return emailWrapper(`
        <h2 style="color: #667eea;">Invitation Accepted!</h2>
        <p><strong>${userName}</strong> has accepted your super-admin succession invitation.</p>
        <div style="background: #d4edda; padding: 15px; border-radius: 8px; margin: 15px 0; border: 1px solid #28a745;">
            <p><strong>🔐 Action Required:</strong></p>
            <p>Log in to your admin dashboard and complete the transfer by entering your password and 2FA code.</p>
        </div>
        <p style="color: #666;">User Details:</p>
        <ul>
            <li>Name: ${userName}</li>
            <li>RGNO: ${userRgno}</li>
            <li>Role: ${userRole}</li>
            <li>College: ${userCollege}</li>
        </ul>
    `);
}

function superAdminInvitationDeclined({ userName }) {
    return emailWrapper(`
        <h2 style="color: #d32f2f;">Invitation Declined</h2>
        <p><strong>${userName}</strong> has declined your super-admin succession invitation.</p>
        <p>You can invite another principal or faculty member from the admin dashboard.</p>
    `);
}

function superAdminTransferCompleted({ newAdminName, newAdminRgno }) {
    return emailWrapper(`
        <h2 style="color: #d32f2f;">Super-Admin Transfer Completed</h2>
        <p>You have completed the transfer of super-admin privileges to:</p>
        <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 15px 0;">
            <p><strong>New Super-Admin:</strong> ${newAdminName}</p>
            <p><strong>RGNO:</strong> ${newAdminRgno}</p>
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
    `);
}

function superAdminWelcome({ oldAdminName }) {
    return emailWrapper(`
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
    `);
}

function superAdminTransferReversed({ reversedByName }) {
    return emailWrapper(`
        <h2 style="color: #667eea;">Transfer Reversed - You are Super-Admin Again</h2>
        <p>The super-admin transfer has been reversed by ${reversedByName}.</p>
        <p>You have been restored as the super-admin.</p>
        <p style="color: #d32f2f; font-weight: bold;">⚠️ Important: Your 2FA settings were cleared. Please set up 2FA again immediately.</p>
    `);
}

function superAdminAccessReclaimed() {
    return emailWrapper(`
        <h2 style="color: #667eea;">Super-Admin Access Restored</h2>
        <p>You have successfully reclaimed your super-admin privileges.</p>
        <div style="background: #d4edda; padding: 15px; border-radius: 8px; margin: 15px 0; border: 1px solid #28a745;">
            <p><strong>✓ You are now the super-admin again</strong></p>
        </div>
        <p style="color: #d32f2f; font-weight: bold;">⚠️ Important: Please set up 2FA again immediately for security.</p>
    `);
}

function superAdminAccessRevoked({ reclaimedByName, newRole }) {
    return emailWrapper(`
        <h2 style="color: #d32f2f;">Super-Admin Access Revoked</h2>
        <p>The previous super-admin (${reclaimedByName}) has reclaimed their super-admin privileges within the 24-hour grace period.</p>
        <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 15px 0;">
            <p><strong>Your new role:</strong> ${newRole}</p>
            <p><strong>Your 2FA settings have been cleared</strong></p>
            <p><strong>All your sessions have been invalidated</strong></p>
        </div>
    `);
}

module.exports = {
    superAdminInvitation,
    superAdminInvitationCancelled,
    superAdminInvitationAccepted,
    superAdminInvitationDeclined,
    superAdminTransferCompleted,
    superAdminWelcome,
    superAdminTransferReversed,
    superAdminAccessReclaimed,
    superAdminAccessRevoked
};
