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
import {initConvexTest} from './setup.test.js';
import {components} from './_generated/api.js';

const DOMAIN = 'testco.kinde.com';
const ISSUER = `https://${DOMAIN}`;
const CONFIG_URL = `https://${DOMAIN}/.well-known/openid-configuration`;
const JWKS_URL = `https://${DOMAIN}/.well-known/jwks`;
const HOUR = 60 * 60 * 1000;

const component = components.agentAuth;
type ConvexTest = ReturnType<typeof initConvexTest>;
type JwkRecord = Record<string, string | string[]>;
type SigningKey = Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];

let mainKey: SigningKey;
let rogueKey: SigningKey;
let mainJwk: JwkRecord;

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
  mainKey = main.privateKey;
  rogueKey = rogue.privateKey;
  mainJwk = toJwkRecord(await exportJWK(main.publicKey), 'key-main');
});

function stubKindeEndpoints() {
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
        return new Response(JSON.stringify({keys: [mainJwk]}), {
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
  sub?: string;
  azp?: string;
  orgCode?: string;
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
  if (options.scp !== undefined) {
    claims['scp'] = options.scp;
  }
  let jwt = new SignJWT(claims)
    .setProtectedHeader({alg: 'RS256', kid: 'key-main'})
    .setIssuedAt(now - 60)
    .setIssuer(ISSUER)
    .setExpirationTime(now + (options.expiresInSeconds ?? 3600));
  if (options.sub !== undefined) {
    jwt = jwt.setSubject(options.sub);
  }
  return await jwt.sign(options.key ?? mainKey);
}

async function registerOrgAgent(t: ConvexTest) {
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

async function makeElevationRequest(t: ConvexTest) {
  const agentId = await t.mutation(component.agents.register, {
    name: 'Worker',
    slug: `worker-${Math.random().toString(36).slice(2)}`,
    ownerKind: 'platform' as const,
    kind: 'autonomous' as const,
    allowedTools: [],
    scopes: ['read']
  });
  const instanceId = await t.mutation(component.instances.start, {
    agentId,
    runId: `run-${Math.random().toString(36).slice(2)}`,
    expiresAt: Date.now() + HOUR
  });
  return await t.mutation(component.elevation.request, {
    instanceId,
    requestedScopes: ['write'],
    reason: 'need write'
  });
}

describe('registerRoutes (mounted by the example app)', () => {
  beforeEach(() => {
    vi.stubEnv('KINDE_DOMAIN', DOMAIN);
    stubKindeEndpoints();
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  test('POST /agent/verify returns the VerifiedAgent for a valid token', async () => {
    const t = initConvexTest();
    const agentId = await registerOrgAgent(t);
    const token = await mint({
      sub: 'client_abc',
      azp: 'client_abc',
      orgCode: 'org_123',
      scp: ['read:tickets']
    });
    const res = await t.fetch('/agent/verify', {
      method: 'POST',
      headers: {Authorization: `Bearer ${token}`}
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toMatchObject({
      subject: 'client_abc',
      agentId,
      orgCode: 'org_123',
      scopes: ['read:tickets']
    });
  });

  test('POST /agent/verify without a bearer token is 401', async () => {
    const t = initConvexTest();
    const res = await t.fetch('/agent/verify', {method: 'POST'});
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({code: 'missing_token'});
  });

  test('POST /agent/verify with an expired token is 401', async () => {
    const t = initConvexTest();
    await registerOrgAgent(t);
    const token = await mint({azp: 'client_abc', expiresInSeconds: -60});
    const res = await t.fetch('/agent/verify', {
      method: 'POST',
      headers: {Authorization: `Bearer ${token}`}
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({code: 'token_expired'});
  });

  test('POST /agent/verify with a forged signature is 401', async () => {
    const t = initConvexTest();
    await registerOrgAgent(t);
    const token = await mint({azp: 'client_abc', key: rogueKey});
    const res = await t.fetch('/agent/verify', {
      method: 'POST',
      headers: {Authorization: `Bearer ${token}`}
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({code: 'invalid_signature'});
  });

  test('POST /agent/verify for a revoked agent is 403 (I2)', async () => {
    const t = initConvexTest();
    const agentId = await registerOrgAgent(t);
    await t.mutation(component.revocations.revoke, {
      targetKind: 'agent',
      targetId: agentId
    });
    const token = await mint({
      sub: 'client_abc',
      azp: 'client_abc',
      orgCode: 'org_123'
    });
    const res = await t.fetch('/agent/verify', {
      method: 'POST',
      headers: {Authorization: `Bearer ${token}`}
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({code: 'revoked_agent'});
  });

  test('POST /agent/elevation/respond approves with a body approverSubject', async () => {
    const t = initConvexTest();
    const requestId = await makeElevationRequest(t);
    const res = await t.fetch('/agent/elevation/respond', {
      method: 'POST',
      body: JSON.stringify({
        requestId,
        decision: 'approve',
        approverSubject: 'human_admin'
      })
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ok: true, decision: 'approve'});
    const row = await t.query(component.elevation.getStatus, {requestId});
    expect(row).toMatchObject({
      status: 'approved',
      approverSubject: 'human_admin'
    });
  });

  test('POST /agent/elevation/respond denies', async () => {
    const t = initConvexTest();
    const requestId = await makeElevationRequest(t);
    const res = await t.fetch('/agent/elevation/respond', {
      method: 'POST',
      body: JSON.stringify({
        requestId,
        decision: 'deny',
        approverSubject: 'human_admin'
      })
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ok: true, decision: 'deny'});
  });

  test('POST /agent/elevation/respond requires approverSubject when unhooked', async () => {
    const t = initConvexTest();
    const requestId = await makeElevationRequest(t);
    const res = await t.fetch('/agent/elevation/respond', {
      method: 'POST',
      body: JSON.stringify({requestId, decision: 'approve'})
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({code: 'approver_required'});
  });

  test('the admin mount derives approverSubject from the authorizeApprover hook', async () => {
    const t = initConvexTest();
    const requestId = await makeElevationRequest(t);
    // The hook supplies the subject; the body value (if any) is ignored.
    const res = await t.fetch('/agent-admin/elevation/respond', {
      method: 'POST',
      headers: {'X-Admin-Subject': 'admin_jane'},
      body: JSON.stringify({requestId, decision: 'approve'})
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({approverSubject: 'admin_jane'});
  });

  test('the admin mount rejects a request with no authenticated admin (403)', async () => {
    const t = initConvexTest();
    const requestId = await makeElevationRequest(t);
    const res = await t.fetch('/agent-admin/elevation/respond', {
      method: 'POST',
      body: JSON.stringify({
        requestId,
        decision: 'approve',
        approverSubject: 'sneaky'
      })
    });
    expect(res.status).toBe(403);
  });
});
