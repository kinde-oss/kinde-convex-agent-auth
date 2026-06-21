import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  test,
  vi
} from 'vitest';
import {SignJWT, exportJWK, generateKeyPair} from 'jose';
import type {JWK} from 'jose';
import {AgentAuth, verifyCaller} from './index.js';
import {components} from '../../example/convex/_generated/api.js';
import {expectFail, initConvexTest, makeRunCtx} from './setup.test.js';

const DOMAIN = 'testco.kinde.com';
const ISSUER = `https://${DOMAIN}`;
const AUDIENCE = 'https://api.example.test';
const CONFIG_URL = `https://${DOMAIN}/.well-known/openid-configuration`;
const JWKS_URL = `https://${DOMAIN}/.well-known/jwks`;

const component = components.agentAuth;

type JwkRecord = Record<string, string | string[]>;
type SigningKey = Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];

let mainKey: SigningKey;
let rogueKey: SigningKey;
let rotatedKey: SigningKey;
let mainJwk: JwkRecord;
let rotatedJwk: JwkRecord;

function toJwkRecord(jwk: JWK, kid: string): JwkRecord {
  const record: JwkRecord = {kid, alg: 'RS256', use: 'sig'};
  for (const [member, value] of Object.entries(jwk)) {
    if (typeof value === 'string') {
      record[member] = value;
    } else if (
      Array.isArray(value) &&
      value.every((item): item is string => typeof item === 'string')
    ) {
      record[member] = value;
    }
  }
  return record;
}

beforeAll(async () => {
  const main = await generateKeyPair('RS256', {extractable: true});
  const rogue = await generateKeyPair('RS256', {extractable: true});
  const rotated = await generateKeyPair('RS256', {extractable: true});
  mainKey = main.privateKey;
  rogueKey = rogue.privateKey;
  rotatedKey = rotated.privateKey;
  mainJwk = toJwkRecord(await exportJWK(main.publicKey), 'key-main');
  rotatedJwk = toJwkRecord(await exportJWK(rotated.publicKey), 'key-rotated');
});

function stubKindeEndpoints(keys: () => JwkRecord[]) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === CONFIG_URL) {
        return new Response(JSON.stringify({jwks_uri: JWKS_URL}), {
          status: 200,
          headers: {'Content-Type': 'application/json'}
        });
      }
      if (url === JWKS_URL) {
        return new Response(JSON.stringify({keys: keys()}), {
          status: 200,
          headers: {'Content-Type': 'application/json'}
        });
      }
      throw new Error(`Unexpected fetch: ${url}`);
    })
  );
}

interface MintOptions {
  key?: SigningKey;
  kid?: string;
  iss?: string;
  aud?: string;
  sub?: string;
  azp?: string;
  orgCode?: string;
  scope?: string;
  scp?: string[];
  expiresInSeconds?: number;
}

async function mint(options: MintOptions = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const claims: Record<string, unknown> = {gty: 'client_credentials'};
  if (options.azp !== undefined) {
    claims['azp'] = options.azp;
  }
  if (options.orgCode !== undefined) {
    claims['org_code'] = options.orgCode;
  }
  if (options.scope !== undefined) {
    claims['scope'] = options.scope;
  }
  if (options.scp !== undefined) {
    claims['scp'] = options.scp;
  }
  let jwt = new SignJWT(claims)
    .setProtectedHeader({alg: 'RS256', kid: options.kid ?? 'key-main'})
    .setIssuedAt(now - 60)
    .setIssuer(options.iss ?? ISSUER)
    .setExpirationTime(now + (options.expiresInSeconds ?? 3600));
  if (options.sub !== undefined) {
    jwt = jwt.setSubject(options.sub);
  }
  if (options.aud !== undefined) {
    jwt = jwt.setAudience(options.aud);
  }
  return await jwt.sign(options.key ?? mainKey);
}

async function setupOrgAgent(t: ReturnType<typeof initConvexTest>) {
  return await t.mutation(component.agents.register, {
    name: 'Org Bot',
    slug: 'org-bot',
    ownerKind: 'org' as const,
    orgCode: 'org_123',
    kindeClientId: 'client_abc',
    kind: 'autonomous' as const,
    allowedTools: ['tickets.read'],
    scopes: ['read:tickets']
  });
}

describe('verifyCaller', () => {
  beforeEach(() => {
    vi.stubEnv('KINDE_DOMAIN', DOMAIN);
    stubKindeEndpoints(() => [mainJwk]);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  test('verifies a valid org-scoped token for a registered agent', async () => {
    const t = initConvexTest();
    const agentId = await setupOrgAgent(t);
    const token = await mint({
      sub: 'client_abc',
      azp: 'client_abc',
      orgCode: 'org_123',
      scp: ['read:tickets', 'write:tickets']
    });
    const verified = await verifyCaller(makeRunCtx(t), component, token);
    expect(verified).toEqual({
      subject: 'client_abc',
      agentId,
      orgCode: 'org_123',
      scopes: ['read:tickets', 'write:tickets'],
      claims: expect.objectContaining({
        iss: ISSUER,
        azp: 'client_abc',
        org_code: 'org_123',
        gty: 'client_credentials'
      })
    });
  });

  test('falls back to the space-separated scope claim', async () => {
    const t = initConvexTest();
    const token = await mint({
      azp: 'client_unregistered',
      scope: 'read:a write:b'
    });
    const verified = await verifyCaller(makeRunCtx(t), component, token);
    expect(verified.scopes).toEqual(['read:a', 'write:b']);
    expect(verified.agentId).toBeNull();
    expect(verified.subject).toBe('client_unregistered');
  });

  test('rejects an expired token', async () => {
    const t = initConvexTest();
    const token = await mint({azp: 'client_abc', expiresInSeconds: -60});
    await expectFail(
      verifyCaller(makeRunCtx(t), component, token),
      'token_expired'
    );
  });

  test('rejects a token from another issuer', async () => {
    const t = initConvexTest();
    const token = await mint({
      azp: 'client_abc',
      iss: 'https://evil.example.com'
    });
    await expectFail(
      verifyCaller(makeRunCtx(t), component, token),
      'invalid_issuer'
    );
  });

  test('rejects a token with the wrong audience', async () => {
    const t = initConvexTest();
    const token = await mint({azp: 'client_abc', aud: 'https://other.api'});
    await expectFail(
      verifyCaller(makeRunCtx(t), component, token, {audience: AUDIENCE}),
      'invalid_audience'
    );
  });

  test('accepts the right audience from component config', async () => {
    vi.stubEnv('KINDE_AUDIENCE', AUDIENCE);
    const t = initConvexTest();
    const token = await mint({azp: 'client_abc', aud: AUDIENCE});
    const verified = await verifyCaller(makeRunCtx(t), component, token);
    expect(verified.subject).toBe('client_abc');
  });

  test('rejects a forged signature with a known key id', async () => {
    const t = initConvexTest();
    const token = await mint({azp: 'client_abc', key: rogueKey});
    await expectFail(
      verifyCaller(makeRunCtx(t), component, token),
      'invalid_signature'
    );
  });

  test('refreshes the JWKS cache when the key id is unknown (rotation)', async () => {
    const t = initConvexTest();
    // Warm the cache with only the main key.
    let served = [mainJwk];
    stubKindeEndpoints(() => served);
    await verifyCaller(makeRunCtx(t), component, await mint({azp: 'c1'}));

    // Kinde rotates: new tokens are signed with a key not in the cache.
    served = [mainJwk, rotatedJwk];
    const rotatedToken = await mint({
      azp: 'c1',
      key: rotatedKey,
      kid: 'key-rotated'
    });
    const verified = await verifyCaller(makeRunCtx(t), component, rotatedToken);
    expect(verified.subject).toBe('c1');
  });

  test('rejects an unknown key id even after refresh', async () => {
    const t = initConvexTest();
    const token = await mint({azp: 'c1', kid: 'key-never-published'});
    await expectFail(
      verifyCaller(makeRunCtx(t), component, token),
      'unknown_key'
    );
  });

  test('rejects a token with neither sub nor azp', async () => {
    const t = initConvexTest();
    const token = await mint({});
    await expectFail(
      verifyCaller(makeRunCtx(t), component, token),
      'missing_subject'
    );
  });

  test('denies a revoked agent despite a valid unexpired JWT (I2)', async () => {
    const t = initConvexTest();
    const agentId = await setupOrgAgent(t);
    const token = await mint({
      sub: 'client_abc',
      azp: 'client_abc',
      orgCode: 'org_123'
    });
    // Works before revocation.
    await verifyCaller(makeRunCtx(t), component, token);
    await t.mutation(component.revocations.revoke, {
      targetKind: 'agent',
      targetId: agentId
    });
    // The same still-valid JWT is now denied.
    await expectFail(
      verifyCaller(makeRunCtx(t), component, token),
      'revoked_agent'
    );
  });

  test('denies on org and global revocations (I2)', async () => {
    const t = initConvexTest();
    await setupOrgAgent(t);
    const token = await mint({
      sub: 'client_abc',
      azp: 'client_abc',
      orgCode: 'org_123'
    });
    await t.mutation(component.revocations.revoke, {
      targetKind: 'org',
      targetId: 'org_123'
    });
    await expectFail(
      verifyCaller(makeRunCtx(t), component, token),
      'revoked_org'
    );
    await t.mutation(component.revocations.revoke, {targetKind: 'global'});
    await expectFail(
      verifyCaller(makeRunCtx(t), component, token),
      'revoked_global'
    );
  });

  test('denies a suspended agent', async () => {
    const t = initConvexTest();
    const agentId = await setupOrgAgent(t);
    await t.mutation(component.agents.suspend, {agentId});
    const token = await mint({
      sub: 'client_abc',
      azp: 'client_abc',
      orgCode: 'org_123'
    });
    await expectFail(
      verifyCaller(makeRunCtx(t), component, token),
      'agent_suspended'
    );
  });

  test('org_code is a binding contract: expectedOrgCode mismatch denies (I3)', async () => {
    const t = initConvexTest();
    await setupOrgAgent(t);
    const token = await mint({
      sub: 'client_abc',
      azp: 'client_abc',
      orgCode: 'org_123'
    });
    await expectFail(
      verifyCaller(makeRunCtx(t), component, token, {
        expectedOrgCode: 'org_other'
      }),
      'org_mismatch'
    );
  });

  test('an agent bound to another org is denied (I3)', async () => {
    const t = initConvexTest();
    await setupOrgAgent(t);
    const tokenOtherOrg = await mint({
      sub: 'client_abc',
      azp: 'client_abc',
      orgCode: 'org_other'
    });
    await expectFail(
      verifyCaller(makeRunCtx(t), component, tokenOtherOrg),
      'org_mismatch'
    );
    const tokenNoOrg = await mint({sub: 'client_abc', azp: 'client_abc'});
    await expectFail(
      verifyCaller(makeRunCtx(t), component, tokenNoOrg),
      'org_mismatch'
    );
  });

  test('works through the AgentAuth class wrapper', async () => {
    const t = initConvexTest();
    const agentAuth = new AgentAuth(component);
    const ctx = makeRunCtx(t);
    const agentId = await agentAuth.registerAgent(ctx, {
      name: 'Org Bot',
      slug: 'org-bot',
      ownerKind: 'org',
      orgCode: 'org_123',
      kindeClientId: 'client_abc',
      kind: 'autonomous',
      allowedTools: ['tickets.read'],
      scopes: ['read:tickets']
    });
    const token = await mint({
      sub: 'client_abc',
      azp: 'client_abc',
      orgCode: 'org_123',
      scp: ['read:tickets']
    });
    const verified = await agentAuth.verifyCaller(ctx, token);
    expect(verified.agentId).toBe(agentId);
    expect(verified.orgCode).toBe('org_123');
  });
});
