import {afterEach, beforeEach, describe, expect, test, vi} from 'vitest';
import {api} from './_generated/api.js';
import {expectFail, initConvexTest} from './setup.test.js';

const DOMAIN = 'testco.kinde.com';
const CONFIG_URL = `https://${DOMAIN}/.well-known/openid-configuration`;
const JWKS_URL = `https://${DOMAIN}/.well-known/jwks`;

const sampleJwk = {
  kty: 'RSA',
  kid: 'key-1',
  alg: 'RS256',
  use: 'sig',
  n: 'sample-modulus',
  e: 'AQAB'
};

function stubKindeEndpoints(jwksBody: unknown, configBody?: unknown) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === CONFIG_URL) {
        return new Response(
          JSON.stringify(configBody ?? {jwks_uri: JWKS_URL}),
          {status: 200, headers: {'Content-Type': 'application/json'}}
        );
      }
      if (url === JWKS_URL) {
        return new Response(JSON.stringify(jwksBody), {
          status: 200,
          headers: {'Content-Type': 'application/json'}
        });
      }
      throw new Error(`Unexpected fetch: ${url}`);
    })
  );
}

describe('jwks', () => {
  beforeEach(() => {
    vi.stubEnv('KINDE_DOMAIN', DOMAIN);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  test('refresh fetches via the OpenID configuration and caches', async () => {
    stubKindeEndpoints({keys: [sampleJwk]});
    const t = initConvexTest();
    const keys = await t.action(api.jwks.refresh, {});
    expect(keys).toEqual([sampleJwk]);

    const cached = await t.query(api.jwks.get, {});
    expect(cached?.domain).toBe(DOMAIN);
    expect(cached?.keys).toEqual([sampleJwk]);
  });

  test('refresh updates the existing cache row in place', async () => {
    stubKindeEndpoints({keys: [sampleJwk]});
    const t = initConvexTest();
    await t.action(api.jwks.refresh, {});

    const rotated = {...sampleJwk, kid: 'key-2'};
    stubKindeEndpoints({keys: [rotated]});
    await t.action(api.jwks.refresh, {});

    const rows = await t.run(async (ctx) =>
      ctx.db.query('jwksCache').collect()
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].keys).toEqual([rotated]);
  });

  test('non-string JWK members (e.g. boolean ext) are dropped', async () => {
    stubKindeEndpoints({
      keys: [{...sampleJwk, ext: true, key_ops: ['verify']}]
    });
    const t = initConvexTest();
    const keys = await t.action(api.jwks.refresh, {});
    expect(keys).toEqual([{...sampleJwk, key_ops: ['verify']}]);
  });

  test('get returns null when nothing is cached', async () => {
    const t = initConvexTest();
    expect(await t.query(api.jwks.get, {})).toBeNull();
  });

  test('refresh fails on a malformed key set', async () => {
    stubKindeEndpoints({keys: 'not-an-array'});
    const t = initConvexTest();
    await expectFail(t.action(api.jwks.refresh, {}), 'jwks_malformed');
  });

  test('refresh maps a non-JSON OpenID config response to a typed failure', async () => {
    // Kinde returns an HTML error page instead of JSON.
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        if (String(input) === CONFIG_URL) {
          return new Response('<html><body>error</body></html>', {
            status: 200,
            headers: {'Content-Type': 'text/html'}
          });
        }
        throw new Error(`Unexpected fetch: ${String(input)}`);
      })
    );
    const t = initConvexTest();
    await expectFail(t.action(api.jwks.refresh, {}), 'oidc_config_malformed');
  });

  test('refresh maps a non-JSON JWKS response to a typed failure', async () => {
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
          return new Response('<html><body>error</body></html>', {
            status: 200,
            headers: {'Content-Type': 'text/html'}
          });
        }
        throw new Error(`Unexpected fetch: ${url}`);
      })
    );
    const t = initConvexTest();
    await expectFail(t.action(api.jwks.refresh, {}), 'jwks_malformed');
  });

  test('refresh fails when the OpenID configuration lacks jwks_uri', async () => {
    stubKindeEndpoints({keys: []}, {issuer: 'whatever'});
    const t = initConvexTest();
    await expectFail(t.action(api.jwks.refresh, {}), 'jwks_uri_missing');
  });

  test('everything fails fast when KINDE_DOMAIN is unset', async () => {
    vi.stubEnv('KINDE_DOMAIN', '');
    const t = initConvexTest();
    await expectFail(t.query(api.jwks.get, {}), 'kinde_domain_unset');
    await expectFail(t.action(api.jwks.refresh, {}), 'kinde_domain_unset');
    await expectFail(t.query(api.config.get, {}), 'kinde_domain_unset');
  });

  test('config.get exposes domain, audience and mode', async () => {
    // vitest itself sets MODE=test in process.env, so pin it explicitly.
    vi.stubEnv('KINDE_AUDIENCE', 'https://api.example.test');
    vi.stubEnv('MODE', 'live');
    const t = initConvexTest();
    expect(await t.query(api.config.get, {})).toEqual({
      domain: DOMAIN,
      audience: 'https://api.example.test',
      mode: 'live',
      jwksMaxAgeMs: 24 * 60 * 60 * 1000
    });

    vi.stubEnv('MODE', 'test');
    expect(await t.query(api.config.get, {})).toMatchObject({mode: 'test'});
  });
});
