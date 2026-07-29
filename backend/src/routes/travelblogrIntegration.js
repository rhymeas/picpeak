const express = require('express');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const { db, logActivity } = require('../database/db');
const { formatBoolean } = require('../utils/dbCompat');
const { getClientIp } = require('../utils/requestIp');
const { getFrontendBaseUrl } = require('../utils/frontendUrl');
const { establishAdminSession } = require('../services/adminSessionService');
const {
  consumeTravelBlogrAdminNonce,
  isAllowedTravelBlogrAdminEmail,
  resolveTravelBlogrAdmin,
} = require('../services/travelblogrAdminService');
const logger = require('../utils/logger');

const router = express.Router();

const bridgeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3000,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => res.status(429).json({ error: 'Too many session requests' }),
});

const adminBridgeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => res.status(429).json({ error: 'Too many admin session requests' }),
});

function configuredEventSlugs() {
  return new Set(
    (process.env.TRAVELBLOGR_ALLOWED_EVENT_SLUGS || '')
      .split(',')
      .map(value => value.trim())
      .filter(Boolean)
  );
}

function tokenTtlSeconds() {
  const configured = Number.parseInt(process.env.TRAVELBLOGR_GALLERY_TOKEN_TTL_SECONDS || '3600', 10);
  if (!Number.isFinite(configured)) return 3600;
  return Math.min(Math.max(configured, 300), 86400);
}

router.post('/session', bridgeLimiter, async (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');

  const secret = process.env.TRAVELBLOGR_AUTH_BRIDGE_SECRET;
  const allowedSlugs = configuredEventSlugs();
  if (!secret || secret.length < 32 || allowedSlugs.size === 0 || !process.env.JWT_SECRET) {
    logger.error('TravelBlogr auth bridge is not fully configured');
    return res.status(503).json({ error: 'Integration unavailable' });
  }

  const assertion = req.body?.assertion;
  if (typeof assertion !== 'string' || assertion.length === 0 || assertion.length > 4096) {
    return res.status(400).json({ error: 'Invalid assertion' });
  }

  let claims;
  try {
    claims = jwt.verify(assertion, secret, {
      algorithms: ['HS256'],
      issuer: 'travelblogr',
      audience: 'picpeak',
      clockTolerance: 5,
      maxAge: '90s',
    });
  } catch (error) {
    logger.warn('TravelBlogr auth assertion rejected', { reason: error.name });
    return res.status(401).json({ error: 'Invalid assertion' });
  }

  if (
    !['travelblogr_session', 'travelblogr_guest_session'].includes(claims.type) ||
    typeof claims.sub !== 'string' ||
    claims.sub.length === 0 ||
    claims.sub.length > 128 ||
    typeof claims.eventSlug !== 'string' ||
    claims.eventSlug.length === 0 ||
    claims.eventSlug.length > 128 ||
    typeof claims.jti !== 'string' ||
    claims.jti.length === 0 ||
    claims.jti.length > 128 ||
    !allowedSlugs.has(claims.eventSlug)
  ) {
    return res.status(403).json({ error: 'Gallery access denied' });
  }

  try {
    const event = await db('events')
      .where({
        slug: claims.eventSlug,
        is_active: formatBoolean(true),
        is_archived: formatBoolean(false),
        is_draft: formatBoolean(false),
      })
      .first();

    if (!event) {
      return res.status(404).json({ error: 'Gallery not found' });
    }

    const expiresIn = tokenTtlSeconds();
    const token = jwt.sign({
      eventId: event.id,
      eventSlug: event.slug,
      type: 'gallery',
      accessLevel: 'guest',
      via: 'travelblogr',
      travelblogrUserId: claims.sub,
      travelblogrSessionType: claims.type,
      sessionId: `travelblogr_${claims.jti}`,
    }, process.env.JWT_SECRET, {
      algorithm: 'HS256',
      expiresIn,
      issuer: 'picpeak-auth',
    });

    return res.json({
      token,
      expires_in: expiresIn,
      event: {
        id: event.id,
        slug: event.slug,
        event_name: event.event_name,
        allow_user_uploads: event.allow_user_uploads === true || event.allow_user_uploads === 1,
        upload_category_id: event.upload_category_id || null,
      },
    });
  } catch (error) {
    logger.error('TravelBlogr session exchange failed', { error: error.message });
    return res.status(500).json({ error: 'Session exchange failed' });
  }
});

router.post('/admin-session', adminBridgeLimiter, async (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');

  const frontendBase = (await getFrontendBaseUrl().catch(() => '')) || '';
  const fail = (key) => res.redirect(303, `${frontendBase}/admin/login?travelblogr_error=${key}`);
  const secret = process.env.TRAVELBLOGR_AUTH_BRIDGE_SECRET;
  if (!secret || secret.length < 32 || !process.env.JWT_SECRET || !process.env.TRAVELBLOGR_ADMIN_EMAILS) {
    logger.error('TravelBlogr admin bridge is not fully configured');
    return fail('config');
  }

  const assertion = req.body?.assertion;
  if (typeof assertion !== 'string' || assertion.length === 0 || assertion.length > 4096) {
    return fail('invalid');
  }

  let claims;
  try {
    claims = jwt.verify(assertion, secret, {
      algorithms: ['HS256'],
      issuer: 'travelblogr',
      audience: 'picpeak',
      clockTolerance: 5,
      maxAge: '90s',
    });
  } catch (error) {
    logger.warn('TravelBlogr admin assertion rejected', { reason: error.name });
    return fail('invalid');
  }

  const email = typeof claims.email === 'string' ? claims.email.trim().toLowerCase() : '';
  if (
    claims.type !== 'travelblogr_admin_session'
    || typeof claims.sub !== 'string'
    || claims.sub.length === 0
    || claims.sub.length > 128
    || typeof claims.jti !== 'string'
    || claims.jti.length === 0
    || claims.jti.length > 128
    || claims.email_verified !== true
    || !email
    || email.length > 320
    || typeof claims.exp !== 'number'
  ) {
    return fail('invalid');
  }
  if (!isAllowedTravelBlogrAdminEmail(email)) {
    logger.warn('TravelBlogr admin email is not allow-listed');
    return fail('forbidden');
  }

  try {
    const consumed = await consumeTravelBlogrAdminNonce(claims.jti, new Date(claims.exp * 1000));
    if (!consumed) return fail('replayed');

    const resolved = await resolveTravelBlogrAdmin({ subject: claims.sub, email });
    const admin = await db('admin_users')
      .leftJoin('roles', 'roles.id', 'admin_users.role_id')
      .where('admin_users.id', resolved.id)
      .select('admin_users.*', 'roles.name as role_name', 'roles.display_name as role_display_name')
      .first();
    const active = admin?.is_active === true || admin?.is_active === 1 || admin?.is_active === '1';
    if (!active) return fail('inactive');

    const ipAddress = getClientIp(req);
    const userAgent = req.headers['user-agent'] || '';
    await establishAdminSession(res, admin, ipAddress, userAgent, email);
    await logActivity('admin_sso_login', { provider: 'travelblogr' }, null, {
      type: 'admin', id: admin.id, name: admin.username,
    });

    return res.redirect(303, `${frontendBase}/admin/dashboard`);
  } catch (error) {
    const key = error.code === 'TRAVELBLOGR_ADMIN_INACTIVE' ? 'inactive' : 'failed';
    logger.error('TravelBlogr admin session exchange failed', { error: error.message });
    return fail(key);
  }
});

module.exports = router;
