const request = require('supertest');
const express = require('express');
const jwt = require('jsonwebtoken');

jest.mock('../../database/db', () => {
  const chain = {
    where: jest.fn().mockReturnThis(),
    first: jest.fn(),
  };
  const db = jest.fn(() => chain);
  db.__chain = chain;
  return { db };
});

const { db } = require('../../database/db');
const router = require('../travelblogrIntegration');

describe('TravelBlogr integration session', () => {
  const bridgeSecret = 'bridge-secret-with-at-least-thirty-two-characters';
  const jwtSecret = 'picpeak-jwt-secret-with-at-least-thirty-two-characters';
  const app = express();
  app.use(express.json());
  app.use('/api/integrations/travelblogr', router);

  beforeEach(() => {
    jest.clearAllMocks();
    process.env.TRAVELBLOGR_AUTH_BRIDGE_SECRET = bridgeSecret;
    process.env.TRAVELBLOGR_ALLOWED_EVENT_SLUGS = 'susanne-rimas';
    process.env.JWT_SECRET = jwtSecret;
    db.__chain.first.mockResolvedValue({
      id: 42,
      slug: 'susanne-rimas',
      event_name: 'Susanne & Rimas',
      allow_user_uploads: true,
      upload_category_id: 7,
    });
  });

  afterAll(() => {
    delete process.env.TRAVELBLOGR_AUTH_BRIDGE_SECRET;
    delete process.env.TRAVELBLOGR_ALLOWED_EVENT_SLUGS;
    delete process.env.TRAVELBLOGR_GALLERY_TOKEN_TTL_SECONDS;
    delete process.env.JWT_SECRET;
  });

  function assertion(overrides = {}) {
    return jwt.sign({
      type: 'travelblogr_session',
      sub: 'travelblogr-user-123',
      eventSlug: 'susanne-rimas',
      jti: 'assertion-123',
      ...overrides,
    }, bridgeSecret, {
      algorithm: 'HS256',
      expiresIn: '60s',
      issuer: 'travelblogr',
      audience: 'picpeak',
    });
  }

  it('exchanges a valid assertion for a scoped gallery token', async () => {
    const response = await request(app)
      .post('/api/integrations/travelblogr/session')
      .send({ assertion: assertion() })
      .expect(200);

    const galleryClaims = jwt.verify(response.body.token, jwtSecret, {
      algorithms: ['HS256'],
      issuer: 'picpeak-auth',
    });

    expect(galleryClaims).toMatchObject({
      eventId: 42,
      eventSlug: 'susanne-rimas',
      type: 'gallery',
      accessLevel: 'guest',
      via: 'travelblogr',
      travelblogrUserId: 'travelblogr-user-123',
    });
    expect(response.body.event).toMatchObject({ id: 42, slug: 'susanne-rimas' });
    expect(response.headers['cache-control']).toBe('no-store');
  });

  it('rejects a gallery slug outside the allow-list', async () => {
    await request(app)
      .post('/api/integrations/travelblogr/session')
      .send({ assertion: assertion({ eventSlug: 'another-wedding' }) })
      .expect(403);

    expect(db).not.toHaveBeenCalled();
  });

  it('rejects assertions with the wrong audience', async () => {
    const invalid = jwt.sign({
      type: 'travelblogr_session',
      sub: 'travelblogr-user-123',
      eventSlug: 'susanne-rimas',
    }, bridgeSecret, {
      expiresIn: '60s',
      issuer: 'travelblogr',
      audience: 'not-picpeak',
    });

    await request(app)
      .post('/api/integrations/travelblogr/session')
      .send({ assertion: invalid })
      .expect(401);
  });

  it('rejects assertions without a unique token id', async () => {
    await request(app)
      .post('/api/integrations/travelblogr/session')
      .send({ assertion: assertion({ jti: undefined }) })
      .expect(403);

    expect(db).not.toHaveBeenCalled();
  });

  it('fails closed when the bridge is not configured', async () => {
    delete process.env.TRAVELBLOGR_AUTH_BRIDGE_SECRET;

    await request(app)
      .post('/api/integrations/travelblogr/session')
      .send({ assertion: assertion() })
      .expect(503);
  });
});
