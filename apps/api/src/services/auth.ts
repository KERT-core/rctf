import { config } from '@rctf/config'
import type { DatabaseClient } from '@rctf/db'
import type {
  BadCompetitionNotAllowed,
  BadCtftimeToken,
  BadEndpoint,
  BadKnownCtftimeId,
  BadKnownEmail,
  BadKnownName,
  BadRateLimit,
  BadCredentials,
  BadRegistrationsDisabled,
  BadTokenVerification,
  BadUnknownUser,
  GoodLogin,
  GoodPasswordSet,
  GoodRegister,
  GoodRegisterV2,
  GoodVerifySent,
  ResponseHelpers,
} from '@rctf/types'
import type { TypedRedis } from '../cache/scripts'
import {
  createToken,
  isTokenRevoked,
  parseToken,
  parseTokenWithMultipleKinds,
  TokenKind,
} from '../lib/tokens'
import { allowedDivisions } from '../util/acl'
import { trySendVerificationEmail } from './emails'
import {
  checkPassword,
  getUserCredentialsById,
  getUserCredentialsByIdentifier,
  hashPassword,
  setUserPassword,
} from './passwords'
import {
  rateLimitLoginByIdentifier,
  rateLimitLoginByIp,
  rateLimitRecoverByEmail,
  rateLimitRecoverByIp,
  rateLimitRegisterByEmail,
  rateLimitRegisterByIp,
  rateLimitRegisterByName,
  rateLimitResetPasswordByEmail,
  rateLimitResetPasswordByIp,
  rateLimitResetPasswordConfirmByIp,
} from './rate-limit'
import {
  createPendingRegistrationVerification,
  getActivePendingByName,
} from './registration-verifications'
import {
  createUser,
  createUserV2,
  getUserByEmail,
  getUserByNameOrEmail,
  type UserToCreate,
} from './users'

type RegisterResponseHelpers = ResponseHelpers<
  [
    typeof BadRegistrationsDisabled,
    typeof BadEndpoint,
    typeof BadCompetitionNotAllowed,
    typeof BadKnownName,
    typeof BadKnownEmail,
    typeof BadKnownCtftimeId,
    typeof BadRateLimit,
    typeof GoodVerifySent,
    typeof BadCtftimeToken,
    typeof GoodRegister,
  ]
>

type RegisterV2ResponseHelpers = ResponseHelpers<
  [
    typeof BadRegistrationsDisabled,
    typeof BadEndpoint,
    typeof BadCompetitionNotAllowed,
    typeof BadKnownName,
    typeof BadKnownEmail,
    typeof BadKnownCtftimeId,
    typeof BadRateLimit,
    typeof GoodVerifySent,
    typeof BadCtftimeToken,
    typeof GoodRegisterV2,
  ]
>

type RegisterCommonResponseHelpers = ResponseHelpers<
  [
    typeof BadRegistrationsDisabled,
    typeof BadEndpoint,
    typeof BadCompetitionNotAllowed,
    typeof BadKnownName,
    typeof BadKnownEmail,
    typeof BadRateLimit,
    typeof GoodVerifySent,
    typeof BadCtftimeToken,
  ]
>

type RecoverResponseHelpers = ResponseHelpers<
  [typeof BadEndpoint, typeof BadRateLimit, typeof GoodVerifySent]
>

type ResetPasswordResponseHelpers = ResponseHelpers<
  [typeof BadEndpoint, typeof BadRateLimit, typeof GoodVerifySent]
>

type ConfirmPasswordResetResponseHelpers = ResponseHelpers<
  [
    typeof BadEndpoint,
    typeof BadRateLimit,
    typeof BadTokenVerification,
    typeof BadUnknownUser,
    typeof GoodPasswordSet,
  ]
>

type LoginPasswordResponseHelpers = ResponseHelpers<
  [typeof BadCredentials, typeof BadRateLimit, typeof GoodLogin]
>

type RegisterUserBody = {
  email?: string
  name: string
  ctftimeToken?: string
  password?: string
}
type RegisterResult = ReturnType<
  RegisterResponseHelpers[keyof RegisterResponseHelpers]
>
type RegisterV2Result = ReturnType<
  RegisterV2ResponseHelpers[keyof RegisterV2ResponseHelpers]
>
type RegisterCommonResult = ReturnType<
  RegisterCommonResponseHelpers[keyof RegisterCommonResponseHelpers]
>

type PrepareRegistrationResult =
  | { hasResult: true; response: RegisterCommonResult }
  | { hasResult: false; userToCreate: UserToCreate }

const prepareRegistration = async (
  res: RegisterCommonResponseHelpers,
  db: DatabaseClient,
  redis: TypedRedis,
  body: RegisterUserBody,
  ip: string
): Promise<PrepareRegistrationResult> => {
  if (!config.registrationsEnabled) {
    return { hasResult: true, response: res.badRegistrationsDisabled() }
  }

  if (body.ctftimeToken && !config.ctftime) {
    return { hasResult: true, response: res.badEndpoint() }
  }

  // Kept, unlike before, when a password is set. Dropping it was what stopped
  // an unproven address from being squatted, and the password path now earns
  // the address the same way every other path does: where a provider is
  // configured, the row below is pending until the emailed link is opened.
  const email = body.email ?? null

  const division = allowedDivisions({ email, defaultOnly: true })[0]
  if (!division) {
    return { hasResult: true, response: res.badCompetitionNotAllowed() }
  }

  // Before hashing, so a rejected request never pays for an argon2.
  const conflict = await getUserByNameOrEmail(db, {
    name: body.name,
    email: email ?? undefined,
  })
  if (conflict) {
    // users.name is citext, so this row can be a name collision that differs
    // only in case. Comparing case-sensitively would fall through and answer
    // badKnownEmail for what is plainly a name conflict.
    if (conflict.name.toLowerCase() === body.name.toLowerCase()) {
      return { hasResult: true, response: res.badKnownName() }
    }
    return { hasResult: true, response: res.badKnownEmail() }
  }

  // A pending row holds a name no user row carries yet. Without this the two
  // registrants race, and whoever opens their link second is told badKnownName
  // by a claim that has already deleted the row they would have retried with.
  // Only the name: a repeat submission of the same address has to fall through
  // to createPendingRegistrationVerification, which resends its live row.
  const pendingName = await getActivePendingByName(db, body.name)
  if (pendingName && pendingName.email !== email?.toLowerCase()) {
    return { hasResult: true, response: res.badKnownName() }
  }

  // Only the paths that cost something: a verification email, or an argon2.
  // Metering the paths v1 also serves makes this build answer badRateLimit
  // where v1 answers goodRegister, which is a real divergence for anyone
  // behind one NAT and not just for tests/test-against-v1.
  if ((config.email && email) || body.password) {
    const ipTimeLeft = await rateLimitRegisterByIp(redis, ip)
    if (ipTimeLeft) {
      return {
        hasResult: true,
        response: res.badRateLimit({ timeLeft: ipTimeLeft }),
      }
    }
  }

  if (config.email && email) {
    const emailTimeLeft = await rateLimitRegisterByEmail(redis, email)
    if (emailTimeLeft) {
      return {
        hasResult: true,
        response: res.badRateLimit({ timeLeft: emailTimeLeft }),
      }
    }
  }

  // Resolved before the hash so a bad token does not pay for an argon2.
  let ctftimeId: string | null = null
  if (body.ctftimeToken) {
    const ctftimeToken = await parseToken(
      TokenKind.CtftimeAuth,
      body.ctftimeToken
    )
    if (!ctftimeToken) {
      return { hasResult: true, response: res.badCtftimeToken() }
    }

    ctftimeId = ctftimeToken.ctftimeId
  }

  // Hashed after every gate, so a rejected request never pays for an argon2,
  // and before the branch below, which now has to store the hash rather than
  // create the account. rateLimitRegisterByName is the only guard on this
  // call, so it moved here with it.
  let passwordHash: string | null = null
  if (body.password) {
    const nameTimeLeft = await rateLimitRegisterByName(redis, body.name)
    if (nameTimeLeft) {
      return {
        hasResult: true,
        response: res.badRateLimit({ timeLeft: nameTimeLeft }),
      }
    }

    passwordHash = await hashPassword(body.password)
  }

  if (config.email && email) {
    const verification = await createPendingRegistrationVerification(db, {
      email,
      name: body.name,
      division: division,
      passwordHash,
    })

    await trySendVerificationEmail(
      db,
      email,
      'register',
      verification.token,
      redis
    )
    return { hasResult: true, response: res.goodVerifySent() }
  }

  // No provider to verify against, so the account is created immediately and
  // the address is stored as submitted. Everything that would trust it is
  // gated on the same config.email: recovery, reset, and the division ACLs.
  const userToCreate: UserToCreate = {
    division,
    email,
    name: body.name,
    ctftimeId,
    passwordHash,
  }

  return { hasResult: false, userToCreate }
}

export const registerUser = async (
  res: RegisterResponseHelpers,
  db: DatabaseClient,
  redis: TypedRedis,
  body: RegisterUserBody,
  ip: string
): Promise<RegisterResult> => {
  const prepared = await prepareRegistration(res, db, redis, body, ip)
  if (prepared.hasResult) {
    return prepared.response
  }

  return await createUser(res, db, prepared.userToCreate)
}

export const registerUserV2 = async (
  res: RegisterV2ResponseHelpers,
  db: DatabaseClient,
  redis: TypedRedis,
  body: RegisterUserBody,
  ip: string
): Promise<RegisterV2Result> => {
  const prepared = await prepareRegistration(res, db, redis, body, ip)
  if (prepared.hasResult) {
    return prepared.response
  }

  return await createUserV2(res, db, prepared.userToCreate)
}

export const loginWithPassword = async (
  res: LoginPasswordResponseHelpers,
  db: DatabaseClient,
  redis: TypedRedis,
  body: { identifier: string; password: string },
  ip: string
): Promise<
  ReturnType<LoginPasswordResponseHelpers[keyof LoginPasswordResponseHelpers]>
> => {
  // Captcha, when the deployment configures one, has already run in the
  // router. Both buckets are consumed before any argon2.
  const ipTimeLeft = await rateLimitLoginByIp(redis, ip)
  if (ipTimeLeft) {
    return res.badRateLimit({ timeLeft: ipTimeLeft })
  }

  const identifierTimeLeft = await rateLimitLoginByIdentifier(
    redis,
    body.identifier
  )
  if (identifierTimeLeft) {
    return res.badRateLimit({ timeLeft: identifierTimeLeft })
  }

  const credentials = await getUserCredentialsByIdentifier(db, body.identifier)
  const ok = await checkPassword(body.password, credentials?.passwordHash)
  if (!ok || !credentials) {
    return res.badCredentials()
  }

  const authToken = await createToken(TokenKind.Auth, credentials.id)
  return res.goodLogin({ authToken })
}

export const recoverUser = async (
  res: RecoverResponseHelpers,
  db: DatabaseClient,
  redis: TypedRedis,
  email: string,
  ip: string
): Promise<
  ReturnType<RecoverResponseHelpers[keyof RecoverResponseHelpers]>
> => {
  if (!config.email) {
    return res.badEndpoint()
  }

  const ipTimeLeft = await rateLimitRecoverByIp(redis, ip)
  if (ipTimeLeft) {
    return res.badRateLimit({ timeLeft: ipTimeLeft })
  }

  const emailTimeLeft = await rateLimitRecoverByEmail(redis, email)
  if (emailTimeLeft) {
    return res.badRateLimit({ timeLeft: emailTimeLeft })
  }

  const user = await getUserByEmail(db, email)
  if (user === undefined) {
    // Do not leak existence of user
    return res.goodVerifySent()
  }

  // v2 change: send team token, its lifetime is infinite
  const teamToken = await createToken(TokenKind.Team, user.id)

  await trySendVerificationEmail(db, email, 'recover', teamToken, redis)
  return res.goodVerifySent()
}

export const requestPasswordReset = async (
  res: ResetPasswordResponseHelpers,
  db: DatabaseClient,
  redis: TypedRedis,
  email: string,
  ip: string
): Promise<
  ReturnType<ResetPasswordResponseHelpers[keyof ResetPasswordResponseHelpers]>
> => {
  if (!config.email) {
    return res.badEndpoint()
  }

  const ipTimeLeft = await rateLimitResetPasswordByIp(redis, ip)
  if (ipTimeLeft) {
    return res.badRateLimit({ timeLeft: ipTimeLeft })
  }

  const emailTimeLeft = await rateLimitResetPasswordByEmail(redis, email)
  if (emailTimeLeft) {
    return res.badRateLimit({ timeLeft: emailTimeLeft })
  }

  const user = await getUserByEmail(db, email)
  if (user === undefined) {
    // Do not leak existence of user
    return res.goodVerifySent()
  }

  const resetToken = await createToken(TokenKind.PasswordReset, user.id)

  await trySendVerificationEmail(db, email, 'reset', resetToken, redis)
  return res.goodVerifySent()
}

export const confirmPasswordReset = async (
  res: ConfirmPasswordResetResponseHelpers,
  db: DatabaseClient,
  redis: TypedRedis,
  body: { resetToken: string; password: string },
  ip: string
): Promise<
  ReturnType<
    ConfirmPasswordResetResponseHelpers[keyof ConfirmPasswordResetResponseHelpers]
  >
> => {
  // Removing the provider revokes every credential derived from email, this
  // one included. A token stranded mid-flow expires within loginTimeout.
  if (!config.email) {
    return res.badEndpoint()
  }

  const ipTimeLeft = await rateLimitResetPasswordConfirmByIp(redis, ip)
  if (ipTimeLeft) {
    return res.badRateLimit({ timeLeft: ipTimeLeft })
  }

  const parsed = await parseTokenWithMultipleKinds(
    [TokenKind.PasswordReset],
    body.resetToken
  )
  if (!parsed) {
    return res.badTokenVerification()
  }

  const [, userId, createdAt] = parsed

  // Never getUser: the hash must not reach the User type or the Redis cache.
  const credentials = await getUserCredentialsById(db, userId)
  if (!credentials) {
    return res.badUnknownUser()
  }

  // This is also what makes the token single use. setUserPassword sets the
  // epoch to now, so the token that performed a reset fails the inclusive
  // comparison on its next use - as does any reset token minted before some
  // other credential change.
  if (isTokenRevoked(createdAt, credentials.tokenEpoch)) {
    return res.badTokenVerification()
  }

  // An account with no password may set one here. The authority is the
  // mailbox, which recoverUser already treats as enough for full access.
  const authToken = await setUserPassword(
    db,
    redis,
    credentials.id,
    await hashPassword(body.password)
  )
  if (!authToken) {
    return res.badUnknownUser()
  }

  return res.goodPasswordSet({ authToken })
}
