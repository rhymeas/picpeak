const jwt = require('jsonwebtoken');
const { db } = require('../database/db');
const { trackSuccessfulLogin } = require('../utils/authSecurity');
const {
  setAdminAuthCookie,
  buildClearCookieOptions,
} = require('../utils/tokenUtils');

async function establishAdminSession(res, admin, ipAddress, userAgent, lockoutKey) {
  await trackSuccessfulLogin(lockoutKey, ipAddress, userAgent);

  try {
    const setupService = require('./setupService');
    if (!(await setupService.isSetupWizardCompleted())) {
      await setupService.markSetupWizardCompleted();
    }
  } catch (_) { /* best-effort */ }

  await db('admin_users').where('id', admin.id).update({
    last_login: new Date(),
    last_login_ip: ipAddress,
  });

  const token = jwt.sign({
    id: admin.id,
    username: admin.username,
    type: 'admin',
    role: admin.role_name,
    ip: ipAddress,
    loginTime: Date.now(),
  }, process.env.JWT_SECRET, {
    expiresIn: '24h',
    issuer: 'picpeak-auth',
  });

  setAdminAuthCookie(res, token);
  res.clearCookie('oidc_id_token', { ...buildClearCookieOptions(), path: '/api/auth' });

  return {
    id: admin.id,
    username: admin.username,
    email: admin.email,
    mustChangePassword: admin.must_change_password || false,
    role: admin.role_name ? {
      name: admin.role_name,
      displayName: admin.role_display_name,
    } : null,
  };
}

module.exports = { establishAdminSession };
