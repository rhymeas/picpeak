const express = require('express');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const { db } = require('../database/db');
const { formatBoolean } = require('../utils/dbCompat');
const logger = require('../utils/logger');

const router = express.Router();

const bridgeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => res.status(429).json({ error: 'Too many session requests' }),
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
    claims.type !== 'travelblogr_session' ||
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

module.exports = router;
