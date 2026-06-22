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
import {api} from './_generated/api.js';
import {initConvexTest} from './setup.test.js';

const DOMAIN = 'acme.kinde.com';
const ISSUER = `https://${DOMAIN}`;
const CONFIG_URL = `https://${DOMAIN}/.well-known/openid-configuration`;
const JWKS_URL = `https://${DOMAIN}/.well-known/jwks`;

type JwkRecord = Record<string, string | string[]>;
type SigningKey = Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];

let mainKey: SigningKey;
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
  mainKey = main.privateKey;
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
  azp?: string;
  sub?: string;
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
  return await jwt.sign(mainKey);
}

describe('end-to-end agent lifecycle', () => {
  beforeEach(() => {
    vi.stubEnv('KINDE_DOMAIN', DOMAIN);
    stubKindeEndpoints();
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  test('the full story: provision → verify → run → authz → elevation → kill switch → audit', async () => {
    const t = initConvexTest();

    // 1. Provision an org-scoped agent from a Kinde M2M client_id. Its granted
    //    scope is tickets.read only; tickets.write is an allowed tool but NOT a
    //    granted scope (so it will need elevation later).
    const agentId = await t.mutation(api.example.provisionAgent, {
      name: 'Support Bot',
      slug: 'support-bot',
      orgCode: 'org_acme',
      kindeClientId: 'm2m_acme',
      allowedTools: ['tickets.read', 'tickets.write'],
      scopes: ['tickets.read']
    });

    // 2. A valid token for that client_id + org_code resolves, via the
    //    /agent/verify route, to the registered agent with the right orgCode.
    const token = await mint({
      sub: 'm2m_acme',
      azp: 'm2m_acme',
      orgCode: 'org_acme',
      scp: ['tickets.read']
    });
    const verifyRes = await t.fetch('/agent/verify', {
      method: 'POST',
      headers: {Authorization: `Bearer ${token}`}
    });
    expect(verifyRes.status).toBe(200);
    expect(await verifyRes.json()).toMatchObject({
      subject: 'm2m_acme',
      agentId,
      orgCode: 'org_acme',
      scopes: ['tickets.read']
    });

    // 3. Start an instance for the agent acting for a user subject.
    const instanceId = await t.mutation(api.example.startRun, {
      agentId,
      runId: 'run-1',
      actingForSubject: 'user_jane',
      orgCode: 'org_acme'
    });

    // 4. An in-scope tool is allowed.
    const readAllowed = await t.mutation(api.example.checkAction, {
      instanceId,
      action: 'tickets.read',
      resource: 'ticket:42'
    });
    expect(readAllowed).toMatchObject({allowed: true, reason: 'authorized'});

    // 5. An out-of-scope tool is denied, and tells the caller what to request.
    const writeDenied = await t.mutation(api.example.checkAction, {
      instanceId,
      action: 'tickets.write'
    });
    expect(writeDenied).toMatchObject({
      allowed: false,
      reason: 'insufficient_scope',
      requiredScopes: ['tickets.write']
    });

    // 6. The agent files an elevation request; a human approves it through the
    //    /agent-admin/elevation/respond route (the hook supplies the approver).
    //    The very same authz check now passes, granted via the elevation (I6).
    const requestId = await t.mutation(api.example.requestElevation, {
      instanceId,
      requestedScopes: ['tickets.write'],
      reason: 'customer asked us to update the ticket'
    });
    const respondRes = await t.fetch('/agent-admin/elevation/respond', {
      method: 'POST',
      headers: {'X-Admin-Subject': 'admin_alice'},
      body: JSON.stringify({requestId, decision: 'approve'})
    });
    expect(respondRes.status).toBe(200);
    const writeAllowed = await t.mutation(api.example.checkAction, {
      instanceId,
      action: 'tickets.write'
    });
    expect(writeAllowed).toMatchObject({allowed: true, reason: 'authorized'});

    // 7. Kill switch mid-run: revoke the agent. The next authz check denies
    //    immediately, even though the token is still valid and unexpired (I2).
    await t.mutation(api.example.revokeAgent, {
      agentId,
      reason: 'security incident'
    });
    const afterRevoke = await t.mutation(api.example.checkAction, {
      instanceId,
      action: 'tickets.read'
    });
    expect(afterRevoke).toMatchObject({
      allowed: false,
      reason: 'revoked_agent'
    });

    // 8. The audit trail reads as a coherent, ordered story (newest-first),
    //    every decision carrying a correlationId (I4), and the elevated allow
    //    recording grantedVia 'elevation'.
    const audit = await t.query(api.example.recentAudit, {
      paginationOpts: {numItems: 50, cursor: null},
      agentId,
      eventType: 'authz.decision'
    });
    expect(audit.page.map((row) => row.detail.reason)).toEqual([
      'revoked_agent',
      'authorized',
      'insufficient_scope',
      'authorized'
    ]);
    expect(
      audit.page.every((row) => typeof row.correlationId === 'string')
    ).toBe(true);
    // The write-allow (second newest) was granted by the human elevation.
    expect(audit.page[1].detail.grantedVia).toBe('elevation');
    // The correlationId returned to the caller matches its audit row.
    expect(audit.page[0].correlationId).toBe(afterRevoke.correlationId);
  });

  test('org isolation: a token for another org is not authorized (I3)', async () => {
    const t = initConvexTest();
    await t.mutation(api.example.provisionAgent, {
      name: 'Support Bot',
      slug: 'support-bot',
      orgCode: 'org_acme',
      kindeClientId: 'm2m_acme',
      allowedTools: ['tickets.read'],
      scopes: ['tickets.read']
    });
    // Same client_id, but the token claims a different org than the agent binds.
    const token = await mint({
      sub: 'm2m_acme',
      azp: 'm2m_acme',
      orgCode: 'org_evil',
      scp: ['tickets.read']
    });
    const res = await t.fetch('/agent/verify', {
      method: 'POST',
      headers: {Authorization: `Bearer ${token}`}
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({code: 'org_mismatch'});
  });

  test('introspectToken (client path) resolves a valid token', async () => {
    const t = initConvexTest();
    const agentId = await t.mutation(api.example.provisionAgent, {
      name: 'Support Bot',
      slug: 'support-bot',
      orgCode: 'org_acme',
      kindeClientId: 'm2m_acme',
      allowedTools: ['tickets.read'],
      scopes: ['tickets.read']
    });
    const token = await mint({
      sub: 'm2m_acme',
      azp: 'm2m_acme',
      orgCode: 'org_acme',
      scp: ['tickets.read']
    });
    expect(await t.action(api.example.introspectToken, {token})).toEqual({
      subject: 'm2m_acme',
      agentId,
      orgCode: 'org_acme',
      scopes: ['tickets.read']
    });
  });

  test('an expired token is rejected at the /verify route (401)', async () => {
    const t = initConvexTest();
    await t.mutation(api.example.provisionAgent, {
      name: 'Support Bot',
      slug: 'support-bot',
      orgCode: 'org_acme',
      kindeClientId: 'm2m_acme',
      allowedTools: ['tickets.read'],
      scopes: ['tickets.read']
    });
    const token = await mint({
      azp: 'm2m_acme',
      orgCode: 'org_acme',
      expiresInSeconds: -60
    });
    const res = await t.fetch('/agent/verify', {
      method: 'POST',
      headers: {Authorization: `Bearer ${token}`}
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({code: 'token_expired'});
  });
});
