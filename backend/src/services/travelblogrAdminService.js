const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { db } = require('../database/db');
const { formatBoolean } = require('../utils/dbCompat');
const { getBcryptRounds } = require('../utils/passwordValidation');
const logger = require('../utils/logger');

const TRAVELBLOGR_ISSUER = 'travelblogr';

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function configuredAdminEmails() {
  return new Set(
    (process.env.TRAVELBLOGR_ADMIN_EMAILS || '')
      .split(',')
      .map(normalizeEmail)
      .filter(Boolean)
  );
}

function isAllowedTravelBlogrAdminEmail(email) {
  return configuredAdminEmails().has(normalizeEmail(email));
}

function isActive(admin) {
  return admin?.is_active === true || admin?.is_active === 1 || admin?.is_active === '1';
}

function isUniqueViolation(error) {
  return error?.code === '23505'
    || error?.code === 'SQLITE_CONSTRAINT'
    || /unique constraint/i.test(error?.message || '');
}

async function consumeTravelBlogrAdminNonce(jti, expiresAt) {
  try {
    await db('travelblogr_admin_nonces')
      .where('expires_at', '<', new Date())
      .del();
    await db('travelblogr_admin_nonces').insert({
      jti,
      expires_at: expiresAt,
      created_at: new Date(),
    });
    return true;
  } catch (error) {
    if (isUniqueViolation(error)) return false;
    throw error;
  }
}

function inactiveError() {
  const error = new Error('Admin account is inactive');
  error.code = 'TRAVELBLOGR_ADMIN_INACTIVE';
  return error;
}

async function resolveTravelBlogrAdmin({ subject, email }) {
  const normalizedEmail = normalizeEmail(email);
  const bySubject = await db('admin_users')
    .where('external_issuer', TRAVELBLOGR_ISSUER)
    .where('external_subject', subject)
    .first();

  if (bySubject) {
    if (!isActive(bySubject)) throw inactiveError();
    if (normalizeEmail(bySubject.email) !== normalizedEmail) {
      const error = new Error('TravelBlogr identity email does not match its PicPeak account');
      error.code = 'TRAVELBLOGR_ADMIN_MISMATCH';
      throw error;
    }
    return bySubject;
  }

  const byEmail = await db('admin_users')
    .whereRaw('LOWER(email) = ?', [normalizedEmail])
    .first();
  if (byEmail) {
    if (!isActive(byEmail)) throw inactiveError();

    if (!byEmail.external_subject) {
      await db('admin_users')
        .where('id', byEmail.id)
        .whereNull('external_subject')
        .update({
          external_issuer: TRAVELBLOGR_ISSUER,
          external_subject: subject,
          updated_at: new Date(),
        });
    }
    return byEmail;
  }

  const role = await db('roles').where('name', 'super_admin').first();
  if (!role) {
    const error = new Error('PicPeak super_admin role is missing');
    error.code = 'TRAVELBLOGR_ADMIN_CONFIG';
    throw error;
  }

  const passwordHash = await bcrypt.hash(
    crypto.randomBytes(32).toString('base64url'),
    getBcryptRounds()
  );

  let adminId;
  try {
    const inserted = await db('admin_users').insert({
      username: normalizedEmail,
      email: normalizedEmail,
      password_hash: passwordHash,
      role_id: role.id,
      is_active: formatBoolean(true),
      must_change_password: formatBoolean(false),
      auth_provider: 'oidc',
      external_issuer: TRAVELBLOGR_ISSUER,
      external_subject: subject,
      created_at: new Date(),
      updated_at: new Date(),
    }).returning('id');
    adminId = inserted[0]?.id || inserted[0];
  } catch (error) {
    if (!isUniqueViolation(error)) throw error;
    const raced = await db('admin_users')
      .whereRaw('LOWER(email) = ?', [normalizedEmail])
      .first();
    if (!raced || !isActive(raced)) throw error;
    return raced;
  }

  logger.info('TravelBlogr: provisioned allow-listed PicPeak admin', { adminId });
  return db('admin_users').where('id', adminId).first();
}

module.exports = {
  consumeTravelBlogrAdminNonce,
  isAllowedTravelBlogrAdminEmail,
  resolveTravelBlogrAdmin,
};
