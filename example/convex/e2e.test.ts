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
import {ConvexError} from 'convex/values';
import {api, internal} from './_generated/api.js';
import {initConvexTest} from './setup.test.js';

/** The machine-readable code carried by a ConvexError, handling convex-test's
 * occasional JSON-string re-serialization of the error data. */
function convexCode(error: unknown): string | null {
  if (!(error instanceof ConvexError)) {
    return null;
  }
  const raw: unknown = error.data;
  const data = typeof raw === 'string' ? (JSON.parse(raw) as unknown) : raw;
  return (data as {code?: string}).code ?? null;
}

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
    vi.stubEnv('DELEGATION_SIGNING_SECRET', 'test-delegation-secret');
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
    //    granted scope (so it will need elevation later). provisionAgent is an
    //    INTERNAL admin-only function — reached here via `internal`, never a
    //    public client call.
    const agentId = await t.mutation(internal.example.provisionAgent, {
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

    // 4. An in-scope tool is allowed. checkAction is an action: it verifies the
    //    bearer token and binds that caller to the instance via authorize().
    const readAllowed = await t.action(api.example.checkAction, {
      token,
      instanceId,
      action: 'tickets.read',
      resource: 'ticket:42'
    });
    expect(readAllowed).toMatchObject({allowed: true, reason: 'authorized'});

    // 5. An out-of-scope tool is denied, and tells the caller what to request.
    const writeDenied = await t.action(api.example.checkAction, {
      token,
      instanceId,
      action: 'tickets.write'
    });
    expect(writeDenied).toMatchObject({
      allowed: false,
      reason: 'insufficient_scope',
      requiredScopes: ['tickets.write']
    });

    // 6. The agent files an elevation request (its token is verified and the
    //    instance ownership checked first); a human approves it through the
    //    /agent-admin/elevation/respond route by presenting a verified Kinde
    //    user token. The very same authz check now passes, granted via the
    //    elevation (I6).
    const requestId = await t.action(api.example.requestElevation, {
      token,
      instanceId,
      requestedScopes: ['tickets.write'],
      reason: 'customer asked us to update the ticket'
    });
    const adminToken = await mint({sub: 'admin_alice'});
    const respondRes = await t.fetch('/agent-admin/elevation/respond', {
      method: 'POST',
      headers: {Authorization: `Bearer ${adminToken}`},
      body: JSON.stringify({requestId, decision: 'approve'})
    });
    expect(respondRes.status).toBe(200);
    const writeAllowed = await t.action(api.example.checkAction, {
      token,
      instanceId,
      action: 'tickets.write'
    });
    expect(writeAllowed).toMatchObject({allowed: true, reason: 'authorized'});

    // 7. Kill switch mid-run: revoke the agent. The very next call cannot even
    //    get past token verification — authorize()/verifyCaller consult the
    //    revocation overlay and throw before any decision is made (I2), even
    //    though the token is still cryptographically valid and unexpired.
    await t.mutation(api.example.revokeAgent, {
      agentId,
      reason: 'security incident'
    });
    let revokedError: unknown;
    try {
      await t.action(api.example.checkAction, {
        token,
        instanceId,
        action: 'tickets.read'
      });
    } catch (error) {
      revokedError = error;
    }
    expect(convexCode(revokedError)).toBe('revoked_agent');

    // 8. The authz decision trail reads as a coherent, ordered story
    //    (newest-first), every decision carrying a correlationId (I4), and the
    //    elevated allow recording grantedVia 'elevation'. The revoked read
    //    never reached an authz decision — the kill switch stopped it at token
    //    verification.
    const audit = await t.query(api.example.recentAudit, {
      paginationOpts: {numItems: 50, cursor: null},
      agentId,
      eventType: 'authz.decision'
    });
    expect(audit.page.map((row) => row.detail.reason)).toEqual([
      'authorized',
      'insufficient_scope',
      'authorized'
    ]);
    expect(
      audit.page.every((row) => typeof row.correlationId === 'string')
    ).toBe(true);
    // The newest allow (tickets.write) was granted by the human elevation.
    expect(audit.page[0].detail.grantedVia).toBe('elevation');

    // The kill switch is visible as a caller.verified deny (revoked_agent),
    // not an authz decision — verification refused the token outright.
    const verifiedTrail = await t.query(api.example.recentAudit, {
      paginationOpts: {numItems: 50, cursor: null},
      agentId,
      eventType: 'caller.verified'
    });
    expect(verifiedTrail.page[0].decision).toBe('deny');
    expect(verifiedTrail.page[0].detail.code).toBe('revoked_agent');
  });

  test('an agent cannot file elevation against another agent instance (instance_not_owned)', async () => {
    const t = initConvexTest();
    // Two agents in the same org. Agent B owns the instance; agent A holds a
    // valid token but no claim to B's run.
    const agentB = await t.mutation(internal.example.provisionAgent, {
      name: 'Bot B',
      slug: 'bot-b',
      orgCode: 'org_acme',
      kindeClientId: 'm2m_b',
      allowedTools: ['tickets.read'],
      scopes: ['tickets.read']
    });
    await t.mutation(internal.example.provisionAgent, {
      name: 'Bot A',
      slug: 'bot-a',
      orgCode: 'org_acme',
      kindeClientId: 'm2m_a',
      allowedTools: ['tickets.read'],
      scopes: ['tickets.read']
    });
    const instanceB = await t.mutation(api.example.startRun, {
      agentId: agentB,
      runId: 'run-b',
      actingForSubject: 'user_x',
      orgCode: 'org_acme'
    });
    const tokenA = await mint({
      sub: 'm2m_a',
      azp: 'm2m_a',
      orgCode: 'org_acme',
      scp: ['tickets.read']
    });
    let error: unknown;
    try {
      await t.action(api.example.requestElevation, {
        token: tokenA,
        instanceId: instanceB,
        requestedScopes: ['tickets.write'],
        reason: 'not my instance'
      });
    } catch (caught) {
      error = caught;
    }
    expect(convexCode(error)).toBe('instance_not_owned');
  });

  test('org isolation: a token for another org is not authorized (I3)', async () => {
    const t = initConvexTest();
    await t.mutation(internal.example.provisionAgent, {
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
    const agentId = await t.mutation(internal.example.provisionAgent, {
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
    await t.mutation(internal.example.provisionAgent, {
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
