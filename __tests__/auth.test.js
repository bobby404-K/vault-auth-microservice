import assert from 'node:assert';
import test from 'node:test';
import { TokenService } from '../dist/token.service.js';

test('TokenService signs and validates JWT tokens with blacklist revocation', () => {
  const service = new TokenService('test-secret');
  const tokens = service.createTokens('u_101', 'dev@example.com', 'admin');
  const payload = service.verify(tokens.accessToken);

  assert.ok(payload);
  assert.strictEqual(payload.email, 'dev@example.com');
  assert.strictEqual(payload.role, 'admin');

  service.revoke(tokens.accessToken);
  assert.strictEqual(service.verify(tokens.accessToken), null);
});
