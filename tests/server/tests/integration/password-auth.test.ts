import { config } from '@rctf/config'
import { createDatabase, pendingUserVerifications, users } from '@rctf/db'
import {
  BadCredentials,
  BadEmail,
  BadKnownName,
  BadPassword,
  BadRateLimit,
  BadToken,
  BadTokenVerification,
  BadZeroAuth,
  GoodLogin,
  GoodPasswordRemoved,
  GoodPasswordSet,
  GoodRegisterV2,
  GoodToken,
  GoodUserSelfDataV2,
  GoodVerify,
  GoodVerifySent,
} from '@rctf/types'
import { beforeAll, beforeEach, describe, expect, test } from 'bun:test'
import { eq } from 'drizzle-orm'
import type { Hono } from 'hono'
import {
  compiledACLs,
  defaultDivision,
} from '../../../../apps/api/src/util/acl'
import { createRedis } from '../../../../apps/api/src/util/redis'
import { getApp, request } from '../../app'
import { hashPassword } from '../../../../apps/api/src/services/passwords'
import {
  clearDatabase,
  expectResponse,
  generateAuthToken,
  lastEmailTo,
} from '../../util'

let app: Hono<any>
const getDb = () => createDatabase(config.database.sql).db

const PASSWORD = 'correct-horse-battery-staple'

const send = (
  method: string,
  path: string,
  body: unknown,
  authToken?: string
) =>
  request(app, path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
    },
    body: JSON.stringify(body),
  })

const post = (path: string, body: unknown, authToken?: string) =>
  send('POST', path, body, authToken)

const get = (path: string, authToken: string) =>
  request(app, path, {
    method: 'GET',
    headers: { Authorization: `Bearer ${authToken}` },
  })

// config is module-level and shared by every test in the process, so it has to
// be put back even when the body throws.
const withoutEmailProvider = async <T>(fn: () => Promise<T>): Promise<T> => {
  const previous = config.email
  config.email = undefined
  try {
    return await fn()
  } finally {
    config.email = previous
  }
}

// A password registration now waits on its address, so the account only
// exists after the emailed link is opened.
const registerWithPassword = async (
  overrides: Record<string, unknown> = {}
) => {
  const name = crypto.randomUUID()
  const email = `${crypto.randomUUID()}@password.test`
  const res = await post('/api/v2/auth/register', {
    name,
    email,
    password: PASSWORD,
    ...overrides,
  })
  await expectResponse(res, GoodVerifySent)

  const mail = lastEmailTo(email)!
  const verified = await post('/api/v2/auth/verify', {
    verifyToken: mail.token,
  })
  const body = await expectResponse(verified, GoodRegisterV2)
  return {
    name,
    email,
    authToken: body.data.authToken as string,
    teamToken: body.data.teamToken as string,
  }
}

beforeAll(async () => {
  app = await getApp()
})

beforeEach(async () => {
  await clearDatabase()
  const redis = await createRedis()
  await redis.flushdb()
})

describe('password registration', () => {
  test('creates the account only once the emailed link is opened', async () => {
    const name = crypto.randomUUID()
    const email = `${crypto.randomUUID()}@password.test`
    const db = getDb()

    const res = await post('/api/v2/auth/register', {
      name,
      email,
      password: PASSWORD,
    })
    await expectResponse(res, GoodVerifySent)

    const beforeVerify = await db
      .select({ name: users.name })
      .from(users)
      .where(eq(users.name, name))
      .then(r => r[0])
    expect(beforeVerify).toBeUndefined()

    const mail = lastEmailTo(email)!
    expect(mail.path).toBe('verify')

    const verified = await post('/api/v2/auth/verify', {
      verifyToken: mail.token,
    })
    const body = await expectResponse(verified, GoodRegisterV2)

    const row = await db
      .select({ email: users.email, hash: users.passwordHash })
      .from(users)
      .where(eq(users.name, name))
      .then(r => r[0])

    expect(row?.email).toBe(email)
    expect(typeof row?.hash).toBe('string')
    expect(row?.hash).not.toBe(PASSWORD)

    const probe = await get('/api/v1/auth/test', body.data.authToken)
    await expectResponse(probe, GoodToken)
  })

  test('carries the hash through the pending row, not around it', async () => {
    // Three call sites build a user from that row. Missing the hash in any
    // of them produces an account with no password and no error anywhere.
    const { name } = await registerWithPassword()

    const login = await post('/api/v2/auth/login', {
      identifier: name,
      password: PASSWORD,
    })
    await expectResponse(login, GoodLogin)
  })

  test('rejects a password shorter than the minimum', async () => {
    const res = await post('/api/v2/auth/register', {
      name: crypto.randomUUID(),
      email: `${crypto.randomUUID()}@password.test`,
      password: 'short',
    })
    await expectResponse(res, BadPassword)
  })

  test('requires an email address', async () => {
    // badEmail, not badBody: badBody is not in the route's badResponses.
    const res = await post('/api/v2/auth/register', {
      name: crypto.randomUUID(),
      password: PASSWORD,
    })
    await expectResponse(res, BadEmail)
  })

  test('resends the live pending row rather than replacing it', async () => {
    // The upsert used to rewrite the token, killing the first link.
    const email = `${crypto.randomUUID()}@password.test`
    const firstName = crypto.randomUUID()

    const first = await post('/api/v2/auth/register', {
      name: firstName,
      email,
      password: PASSWORD,
    })
    await expectResponse(first, GoodVerifySent)
    const firstMail = lastEmailTo(email)!

    const second = await post('/api/v2/auth/register', {
      name: crypto.randomUUID(),
      email,
      password: `${PASSWORD}-other`,
    })
    await expectResponse(second, GoodVerifySent)
    expect(lastEmailTo(email)!.token).toBe(firstMail.token)

    const verified = await post('/api/v2/auth/verify', {
      verifyToken: firstMail.token,
    })
    await expectResponse(verified, GoodRegisterV2)

    const login = await post('/api/v2/auth/login', {
      identifier: firstName,
      password: PASSWORD,
    })
    await expectResponse(login, GoodLogin)
  })

  test('rejects a name another pending registration already holds', async () => {
    // Otherwise the second clicker hits badKnownName after the delete.
    const name = crypto.randomUUID()
    const first = await post('/api/v2/auth/register', {
      name,
      email: `${crypto.randomUUID()}@password.test`,
      password: PASSWORD,
    })
    await expectResponse(first, GoodVerifySent)

    const second = await post('/api/v2/auth/register', {
      name,
      email: `${crypto.randomUUID()}@password.test`,
      password: PASSWORD,
    })
    await expectResponse(second, BadKnownName)
  })

  test('keeps the pending row when the claim loses a name race', async () => {
    // The claim is a DELETE ... RETURNING: without a transaction the row is
    // gone before the failure is known.
    const db = getDb()
    const email = `${crypto.randomUUID()}@password.test`
    const name = crypto.randomUUID()

    const res = await post('/api/v2/auth/register', {
      name,
      email,
      password: PASSWORD,
    })
    await expectResponse(res, GoodVerifySent)
    const mail = lastEmailTo(email)!

    // Taken directly: the pre-check now rejects this collision at
    // registration, but the claim still has to survive the narrower race.
    await db.insert(users).values({
      id: crypto.randomUUID(),
      name,
      email: `${crypto.randomUUID()}@password.test`,
      division: Object.keys(config.divisions)[0]!,
      perms: 0,
    })

    const claimed = await post('/api/v2/auth/verify', {
      verifyToken: mail.token,
    })
    await expectResponse(claimed, BadKnownName)

    const survived = await db
      .select({ token: pendingUserVerifications.token })
      .from(pendingUserVerifications)
      .where(eq(pendingUserVerifications.email, email))
      .then(r => r[0])
    expect(survived?.token).toBe(mail.token)
  })

  test('applies division ACLs to the address it just proved', async () => {
    // acl.ts compiles ACLs once at module load, so the array has to be swapped
    // in place. Same technique as email-change-division.test.ts.
    const oldACLs = config.divisionACLs
    const savedCompiled = [...compiledACLs]

    config.divisionACLs = [
      { match: 'domain', value: 'college.test', divisions: ['college'] },
    ]
    compiledACLs.length = 0
    compiledACLs.push({
      check: (email: string | undefined) =>
        email?.endsWith('@college.test') ?? false,
      divisions: ['college'],
    })

    const name = crypto.randomUUID()
    const email = `${crypto.randomUUID()}@college.test`
    try {
      const res = await post('/api/v2/auth/register', {
        name,
        email,
        password: PASSWORD,
      })
      await expectResponse(res, GoodVerifySent)

      const verified = await post('/api/v2/auth/verify', {
        verifyToken: lastEmailTo(email)!.token,
      })
      await expectResponse(verified, GoodRegisterV2)
    } finally {
      config.divisionACLs = oldACLs
      compiledACLs.length = 0
      compiledACLs.push(...savedCompiled)
    }

    const db = getDb()
    const row = await db
      .select({ division: users.division })
      .from(users)
      .where(eq(users.name, name))
      .then(r => r[0])

    // The address is proven before the row exists, so no unverified value
    // reaches the ACLs and pinning to defaultDivision would be surprising.
    expect(row?.division).toBe('college')
    expect(row?.division).not.toBe(defaultDivision)
  })
})

describe('password login', () => {
  test('succeeds and returns a usable auth token', async () => {
    const { name } = await registerWithPassword()

    const res = await post('/api/v2/auth/login', {
      identifier: name,
      password: PASSWORD,
    })
    const body = await expectResponse(res, GoodLogin)

    const probe = await get('/api/v1/auth/test', body.data.authToken)
    await expectResponse(probe, GoodToken)
  })

  test('matches the name case-insensitively, like the citext column', async () => {
    const { name } = await registerWithPassword()

    const res = await post('/api/v2/auth/login', {
      identifier: name.toUpperCase(),
      password: PASSWORD,
    })
    await expectResponse(res, GoodLogin)
  })

  test('answers badCredentials for a wrong password', async () => {
    const { name } = await registerWithPassword()

    const res = await post('/api/v2/auth/login', {
      identifier: name,
      password: `${PASSWORD}-wrong`,
    })
    await expectResponse(res, BadCredentials)
  })

  test('answers badCredentials, not a 404, for an unknown name', async () => {
    const res = await post('/api/v2/auth/login', {
      identifier: crypto.randomUUID(),
      password: PASSWORD,
    })
    await expectResponse(res, BadCredentials)
  })

  test('answers badCredentials for an account with no password', async () => {
    const name = crypto.randomUUID()
    await withoutEmailProvider(async () => {
      const res = await post('/api/v2/auth/register', {
        name,
        email: `${crypto.randomUUID()}@example.com`,
      })
      await expectResponse(res, GoodRegisterV2)
    })

    const res = await post('/api/v2/auth/login', {
      identifier: name,
      password: PASSWORD,
    })
    await expectResponse(res, BadCredentials)
  })

  test('logs in with the account email', async () => {
    const email = `${crypto.randomUUID()}@example.com`
    const name = crypto.randomUUID()
    await withoutEmailProvider(async () => {
      const res = await post('/api/v2/auth/register', {
        name,
        email,
        password: PASSWORD,
      })
      await expectResponse(res, GoodRegisterV2)
    })

    const res = await post('/api/v2/auth/login', {
      identifier: email,
      password: PASSWORD,
    })
    await expectResponse(res, GoodLogin)
  })

  test('matches the email case-insensitively', async () => {
    const email = `${crypto.randomUUID()}@example.com`
    await withoutEmailProvider(async () => {
      const res = await post('/api/v2/auth/register', {
        name: crypto.randomUUID(),
        email,
        password: PASSWORD,
      })
      await expectResponse(res, GoodRegisterV2)
    })

    const res = await post('/api/v2/auth/login', {
      identifier: email.toUpperCase(),
      password: PASSWORD,
    })
    await expectResponse(res, GoodLogin)
  })

  test('the address owner wins when a team name is spelled like it', async () => {
    // Team names permit '@', and name and email are unique only within their
    // own column, so both rows can exist at once. The account that actually
    // holds the address has to win, or a squatter could shadow its login.
    const contested = `${crypto.randomUUID()}@example.com`
    const squatterPassword = `${PASSWORD}-squatter`

    const squatter = await withoutEmailProvider(async () => {
      const res = await post('/api/v2/auth/register', {
        name: contested,
        email: `${crypto.randomUUID()}@example.com`,
        password: squatterPassword,
      })
      return await expectResponse(res, GoodRegisterV2)
    })
    expect(squatter.data.authToken).toBeString()

    const ownerName = crypto.randomUUID()
    await withoutEmailProvider(async () => {
      const owner = await post('/api/v2/auth/register', {
        name: ownerName,
        email: contested,
        password: PASSWORD,
      })
      await expectResponse(owner, GoodRegisterV2)
    })

    const asOwner = await post('/api/v2/auth/login', {
      identifier: contested,
      password: PASSWORD,
    })
    const body = await expectResponse(asOwner, GoodLogin)

    const me = await get('/api/v2/users/me', body.data.authToken)
    const self = await expectResponse(me, GoodUserSelfDataV2)
    expect(self.data.name).toBe(ownerName)

    const asSquatter = await post('/api/v2/auth/login', {
      identifier: contested,
      password: squatterPassword,
    })
    await expectResponse(asSquatter, BadCredentials)
  })

  test('rate limits by name, case-folded so variants share one bucket', async () => {
    const { name } = await registerWithPassword()
    const wrong = { password: `${PASSWORD}-wrong` }

    // Drain the per-name bucket (burst 5), alternating the casing so the run
    // only trips if both spellings share one key. The drain itself is not
    // asserted on: the per-IP bucket is shared with every other test in the
    // process, so an individual attempt may come back rate-limited instead of
    // badCredentials.
    for (let i = 0; i < 5; i++) {
      await post('/api/v2/auth/login', {
        identifier: i % 2 === 0 ? name : name.toUpperCase(),
        ...wrong,
      })
    }

    const limited = await post('/api/v2/auth/login', {
      identifier: name.toUpperCase(),
      ...wrong,
    })
    await expectResponse(limited, BadRateLimit)
  })
})

describe('setting a password revokes existing tokens', () => {
  test('the auth token used to set it is replaced, not kept', async () => {
    const { name, authToken } = await registerWithPassword()

    const res = await send(
      'PUT',
      '/api/v2/users/me/auth/password',
      { password: `${PASSWORD}-new`, currentPassword: PASSWORD },
      authToken
    )
    const body = await expectResponse(res, GoodPasswordSet)
    expect(body.data.authToken).not.toBe(authToken)

    const stale = await get('/api/v1/auth/test', authToken)
    await expectResponse(stale, BadToken)

    const fresh = await get('/api/v1/auth/test', body.data.authToken)
    await expectResponse(fresh, GoodToken)

    const login = await post('/api/v2/auth/login', {
      identifier: name,
      password: `${PASSWORD}-new`,
    })
    await expectResponse(login, GoodLogin)
  })

  test('a team token issued earlier no longer buys an auth token', async () => {
    const { authToken, teamToken } = await registerWithPassword()

    const before = await post('/api/v2/auth/verify', {
      verifyToken: teamToken,
    })
    await expectResponse(before, GoodVerify)

    const res = await send(
      'PUT',
      '/api/v2/users/me/auth/password',
      { password: `${PASSWORD}-new`, currentPassword: PASSWORD },
      authToken
    )
    await expectResponse(res, GoodPasswordSet)

    const after = await post('/api/v2/auth/verify', { verifyToken: teamToken })
    await expectResponse(after, BadTokenVerification)

    const v1 = await post('/api/v1/auth/login', { teamToken })
    await expectResponse(v1, BadTokenVerification)
  })

  test('requires the current password when one is already set', async () => {
    const { authToken } = await registerWithPassword()

    const res = await send(
      'PUT',
      '/api/v2/users/me/auth/password',
      { password: `${PASSWORD}-new` },
      authToken
    )
    await expectResponse(res, BadCredentials)
  })
})

describe('removing a password', () => {
  test('refuses when it is the only credential left', async () => {
    // No longer reachable through the API, but it exists in databases that
    // predate the change, which is who the guard is for.
    const db = getDb()
    const id = crypto.randomUUID()
    await db.insert(users).values({
      id,
      name: crypto.randomUUID(),
      email: null,
      passwordHash: await hashPassword(PASSWORD),
      division: Object.keys(config.divisions)[0]!,
      perms: 0,
    })

    const res = await send(
      'DELETE',
      '/api/v2/users/me/auth/password',
      { currentPassword: PASSWORD },
      await generateAuthToken(id)
    )
    await expectResponse(res, BadZeroAuth)
  })

  test('succeeds when an email remains', async () => {
    const name = crypto.randomUUID()
    const authToken = await withoutEmailProvider(async () => {
      const res = await post('/api/v2/auth/register', {
        name,
        email: `${crypto.randomUUID()}@example.com`,
        password: PASSWORD,
      })
      const body = await expectResponse(res, GoodRegisterV2)
      return body.data.authToken as string
    })

    const res = await send(
      'DELETE',
      '/api/v2/users/me/auth/password',
      { currentPassword: PASSWORD },
      authToken
    )
    await expectResponse(res, GoodPasswordRemoved)

    const login = await post('/api/v2/auth/login', {
      identifier: name,
      password: PASSWORD,
    })
    await expectResponse(login, BadCredentials)
  })
})

describe('hasPassword', () => {
  test('is reported on the self route', async () => {
    const { authToken } = await registerWithPassword()

    const res = await get('/api/v2/users/me', authToken)
    const body = await expectResponse(res, GoodUserSelfDataV2)
    expect(body.data.hasPassword).toBe(true)
  })
})
