import { createHash } from 'node:crypto'
import anyTest, { type TestFn } from 'ava'
import * as jose from 'jose'
import setup, {
  client,
  endpoint,
  getResponse,
  issuer,
  setupJwks,
  teardown,
  type ContextWithAlgs,
} from './_setup.js'
import * as lib from './_lib.js'

const test = anyTest as TestFn<ContextWithAlgs>

test.before(setup())
test.before(setupJwks)
test.after(teardown)

const as: lib.AuthorizationServer = { ...issuer, jwks_uri: endpoint('jwks') }
const jwtClient: lib.Client = { ...client, id_token_signed_response_alg: 'ES256' }
const skipAudClient: lib.Client = { ...jwtClient, [lib.skipAudienceCheck]: true }
const codeHash = createHash('sha256').update('code').digest().subarray(0, 16).toString('base64url')

async function idToken(privateKey: CryptoKey, claims: jose.JWTPayload = {}) {
  const now = Math.floor(Date.now() / 1000)
  return new jose.SignJWT({
    iss: as.issuer,
    aud: client.client_id,
    sub: 'subject',
    iat: now,
    exp: now + 300,
    ...claims,
  })
    .setProtectedHeader({ alg: 'ES256' })
    .sign(privateKey)
}

function tokenResponse(id_token: string) {
  return getResponse(JSON.stringify({ access_token: 'token', token_type: 'Bearer', id_token }))
}

test('skipAudienceCheck skips ID Token aud and azp checks', async (t) => {
  const key = t.context.ES256.privateKey

  for (const claims of [
    { aud: 'other' },
    { aud: ['other', 'another'] },
    { aud: [client.client_id, 'other'] },
    { aud: [client.client_id, 'other'], azp: 'other' },
  ]) {
    await t.throwsAsync(
      lib.processAuthorizationCodeResponse(
        as,
        jwtClient,
        tokenResponse(await idToken(key, claims)),
      ),
      { code: lib.JWT_CLAIM_COMPARISON },
    )
    await t.notThrowsAsync(
      lib.processAuthorizationCodeResponse(
        as,
        skipAudClient,
        tokenResponse(await idToken(key, claims)),
      ),
    )
  }

  await t.throwsAsync(
    lib.processAuthorizationCodeResponse(
      as,
      skipAudClient,
      tokenResponse(await idToken(key, { aud: undefined })),
    ),
    { message: 'JWT "aud" (audience) claim missing' },
  )
})

test('skipAudienceCheck skips JWT UserInfo aud check', async (t) => {
  const userinfoClient = { ...skipAudClient, userinfo_signed_response_alg: 'ES256' }
  const jwt = await new jose.SignJWT({ sub: 'subject', aud: 'other' })
    .setProtectedHeader({ alg: 'ES256' })
    .sign(t.context.ES256.privateKey)
  const response = () =>
    getResponse(jwt, { headers: new Headers({ 'content-type': 'application/jwt' }) })

  await t.throwsAsync(
    lib.processUserInfoResponse(
      as,
      { ...userinfoClient, [lib.skipAudienceCheck]: false },
      'subject',
      response(),
    ),
    { message: 'unexpected JWT "aud" (audience) claim value' },
  )
  await t.notThrowsAsync(lib.processUserInfoResponse(as, userinfoClient, 'subject', response()))
})

test('skipNonceCheck skips authorization code ID Token nonce checks', async (t) => {
  const key = t.context.ES256.privateKey

  for (const nonce of [undefined, 'random-value']) {
    for (const options of [
      { expectedNonce: lib.skipNonceCheck },
      { expectedNonce: lib.skipNonceCheck, requireIdToken: true },
      { expectedNonce: lib.skipNonceCheck, maxAge: lib.skipAuthTimeCheck },
    ] satisfies lib.ProcessAuthorizationCodeResponseOptions[]) {
      await t.notThrowsAsync(
        lib.processAuthorizationCodeResponse(
          as,
          jwtClient,
          tokenResponse(await idToken(key, { nonce })),
          options,
        ),
      )
    }
  }

  await t.throwsAsync(
    lib.processAuthorizationCodeResponse(
      as,
      jwtClient,
      tokenResponse(await idToken(key, { nonce: 'random-value' })),
    ),
    { message: 'unexpected ID Token "nonce" claim value' },
  )

  await t.notThrowsAsync(
    lib.processAuthorizationCodeResponse(
      as,
      jwtClient,
      getResponse(JSON.stringify({ access_token: 'token', token_type: 'Bearer' })),
      { expectedNonce: lib.skipNonceCheck },
    ),
  )
})

for (const [name, validate] of [
  ['code id_token', lib.validateCodeIdTokenResponse],
  ['detached signature', lib.validateDetachedSignatureResponse],
] as const) {
  test(`${name} skipNonceCheck and skipAudienceCheck`, async (t) => {
    const key = t.context.ES256.privateKey
    const params = async (claims: jose.JWTPayload) =>
      new URLSearchParams({
        code: 'code',
        id_token: await idToken(key, { c_hash: codeHash, ...claims }),
      })

    for (const nonce of [undefined, 'other']) {
      await t.throwsAsync(validate(as, jwtClient, await params({ nonce }), 'nonce'))
      await t.notThrowsAsync(validate(as, jwtClient, await params({ nonce }), lib.skipNonceCheck))
    }

    await t.throwsAsync(
      validate(as, jwtClient, await params({ nonce: 'nonce', aud: 'other' }), 'nonce'),
      { message: 'unexpected JWT "aud" (audience) claim value' },
    )
    await t.notThrowsAsync(
      validate(
        as,
        skipAudClient,
        await params({ nonce: 'nonce', aud: [client.client_id, 'other'], azp: 'other' }),
        'nonce',
      ),
    )
  })
}
