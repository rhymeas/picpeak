const request = require('supertest');
const express = require('express');
const jwt = require('jsonwebtoken');

jest.mock('../../database/db', () => {
  const chain = {
    leftJoin: jest.fn().mockReturnThis(),
    where: jest.fn().mockReturnThis(),
    select: jest.fn().mockReturnThis(),
    first: jest.fn(),
  };
  const db = jest.fn(() => chain);
  db.__chain = chain;
  return { db, logActivity: jest.fn() };
});
jest.mock('../../services/adminSessionService', () => ({
  establishAdminSession: jest.fn(),
}));
jest.mock('../../services/travelblogrAdminService', () => ({
  consumeTravelBlogrAdminNonce: jest.fn(),
  isAllowedTravelBlogrAdminEmail: jest.fn(),
  resolveTravelBlogrAdmin: jest.fn(),
}));
jest.mock('../../utils/frontendUrl', () => ({
  getFrontendBaseUrl: jest.fn().mockResolvedValue('https://photos.example.com'),
}));
jest.mock('../../utils/requestIp', () => ({
  getClientIp: jest.fn().mockReturnValue('203.0.113.10'),
}));

const { db, logActivity } = require('../../database/db');
const { establishAdminSession } = require('../../services/adminSessionService');
const {
  consumeTravelBlogrAdminNonce,
  isAllowedTravelBlogrAdminEmail,
  resolveTravelBlogrAdmin,
} = require('../../services/travelblogrAdminService');
const router = require('../travelblogrIntegration');

describe('TravelBlogr admin integration', () => {
  const bridgeSecret = 'bridge-secret-with-at-least-thirty-two-characters';
  const app = express();
  app.use(express.urlencoded({ extended: true }));
  app.use('/api/integrations/travelblogr', router);

  beforeEach(() => {
    jest.clearAllMocks();
    process.env.TRAVELBLOGR_AUTH_BRIDGE_SECRET = bridgeSecret;
    process.env.TRAVELBLOGR_ADMIN_EMAILS = 'host@example.com';
    process.env.JWT_SECRET = 'picpeak-jwt-secret-with-at-least-thirty-two-characters';
    isAllowedTravelBlogrAdminEmail.mockReturnValue(true);
    consumeTravelBlogrAdminNonce.mockResolvedValue(true);
    resolveTravelBlogrAdmin.mockResolvedValue({ id: 7 });
    db.__chain.first.mockResolvedValue({
      id: 7,
      username: 'host@example.com',
      email: 'host@example.com',
      is_active: true,
      role_name: 'super_admin',
      role_display_name: 'Super Admin',
    });
    establishAdminSession.mockResolvedValue({ id: 7 });
    logActivity.mockResolvedValue(undefined);
  });

  afterAll(() => {
    delete process.env.TRAVELBLOGR_AUTH_BRIDGE_SECRET;
    delete process.env.TRAVELBLOGR_ADMIN_EMAILS;
    delete process.env.JWT_SECRET;
  });

  function assertion(overrides = {}) {
    return jwt.sign({
      type: 'travelblogr_admin_session',
      sub: 'travelblogr-admin-123',
      email: 'host@example.com',
      email_verified: true,
      jti: 'admin-assertion-123',
      ...overrides,
    }, bridgeSecret, {
      algorithm: 'HS256',
      expiresIn: '60s',
      issuer: 'travelblogr',
      audience: 'picpeak',
    });
  }

  it('consumes a signed form once and establishes the normal admin session', async () => {
    const response = await request(app)
      .post('/api/integrations/travelblogr/admin-session')
      .type('form')
      .send({ assertion: assertion() })
      .expect(303);

    expect(response.headers.location).toBe('https://photos.example.com/admin/dashboard');
    expect(consumeTravelBlogrAdminNonce).toHaveBeenCalledWith(
      'admin-assertion-123',
      expect.any(Date),
    );
    expect(resolveTravelBlogrAdmin).toHaveBeenCalledWith({
      subject: 'travelblogr-admin-123',
      email: 'host@example.com',
    });
    expect(establishAdminSession).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ id: 7, role_name: 'super_admin' }),
      '203.0.113.10',
      expect.any(String),
      'host@example.com',
    );
    expect(logActivity).toHaveBeenCalledWith(
      'admin_sso_login',
      { provider: 'travelblogr' },
      null,
      { type: 'admin', id: 7, name: 'host@example.com' },
    );
  });

  it('rejects a replay before creating another admin session', async () => {
    consumeTravelBlogrAdminNonce.mockResolvedValue(false);

    const response = await request(app)
      .post('/api/integrations/travelblogr/admin-session')
      .type('form')
      .send({ assertion: assertion() })
      .expect(303);

    expect(response.headers.location).toContain('travelblogr_error=replayed');
    expect(resolveTravelBlogrAdmin).not.toHaveBeenCalled();
    expect(establishAdminSession).not.toHaveBeenCalled();
  });

  it('checks the PicPeak-side admin allow-list', async () => {
    isAllowedTravelBlogrAdminEmail.mockReturnValue(false);

    const response = await request(app)
      .post('/api/integrations/travelblogr/admin-session')
      .type('form')
      .send({ assertion: assertion() })
      .expect(303);

    expect(response.headers.location).toContain('travelblogr_error=forbidden');
    expect(consumeTravelBlogrAdminNonce).not.toHaveBeenCalled();
  });

  it('rejects an expired or incorrectly signed handoff', async () => {
    const invalid = jwt.sign({
      type: 'travelblogr_admin_session',
      sub: 'travelblogr-admin-123',
      email: 'host@example.com',
      email_verified: true,
      jti: 'invalid-123',
    }, 'different-secret-with-at-least-thirty-two-characters', {
      expiresIn: '60s',
      issuer: 'travelblogr',
      audience: 'picpeak',
    });

    const response = await request(app)
      .post('/api/integrations/travelblogr/admin-session')
      .type('form')
      .send({ assertion: invalid })
      .expect(303);

    expect(response.headers.location).toContain('travelblogr_error=invalid');
    expect(consumeTravelBlogrAdminNonce).not.toHaveBeenCalled();
  });
});
