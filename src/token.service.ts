import crypto from 'crypto';
import { TokenPayload, AuthTokens, UserRole } from './types.js';

export class TokenService {
  private secret: string;
  private blacklist = new Set<string>();

  constructor(secret = 'vault-super-secure-production-secret-2025') {
    this.secret = secret;
  }

  createTokens(userId: string, email: string, role: UserRole): AuthTokens {
    const now = Math.floor(Date.now() / 1000);
    const accessPayload: TokenPayload = { sub: userId, email, role, iat: now, exp: now + 900 };
    const refreshPayload: TokenPayload = { sub: userId, email, role, iat: now, exp: now + 86400 * 7 };

    return {
      accessToken: this.sign(accessPayload),
      refreshToken: this.sign(refreshPayload),
      expiresIn: 900
    };
  }

  private sign(payload: TokenPayload): string {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = crypto.createHmac('sha256', this.secret).update(`${header}.${body}`).digest('base64url');
    return `${header}.${body}.${signature}`;
  }

  verify(token: string): TokenPayload | null {
    if (this.blacklist.has(token)) return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [header, body, sig] = parts;
    const expected = crypto.createHmac('sha256', this.secret).update(`${header}.${body}`).digest('base64url');
    if (sig !== expected) return null;

    try {
      const payload: TokenPayload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
      if (payload.exp < Math.floor(Date.now() / 1000)) return null;
      return payload;
    } catch {
      return null;
    }
  }

  revoke(token: string): void {
    this.blacklist.add(token);
  }
}
