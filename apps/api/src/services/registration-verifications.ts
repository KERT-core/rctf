import { config } from '@rctf/config'
import type { DatabaseClient, DatabaseTx } from '@rctf/db'
import { pendingUserVerifications } from '@rctf/db'
import { takeUnique } from '@rctf/db/util'
import { and, desc, eq, gt, sql, type SQL } from 'drizzle-orm'
import { createUserInternal } from './users'

export type PendingRegistrationVerification =
  typeof pendingUserVerifications.$inferSelect

type PendingRegistrationInput = {
  name: string
  email: string
  division: string
  passwordHash?: string | null
}

const table = pendingUserVerifications
const notExpired = gt(table.expiresAt, sql`now()`)

const newToken = () =>
  Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url')

const findActive = (db: DatabaseClient, where: SQL) =>
  db
    .select()
    .from(table)
    .where(and(where, notExpired))
    .limit(1)
    .then(takeUnique)

export const createPendingRegistrationVerification = async (
  db: DatabaseClient,
  input: PendingRegistrationInput
): Promise<PendingRegistrationVerification> => {
  const email = input.email.toLowerCase()

  // Resend the live row rather than replacing it. The upsert below rewrites
  // the token, so a second signup to an address killed the link the first
  // person was about to click - and now it would overwrite their password
  // hash as well. Returning the existing row means someone else's submission
  // can neither invalidate nor rewrite a verification already in flight. The
  // cost is that a registrant who mistyped their name or password cannot
  // correct it until the row expires.
  const active = await findActive(db, eq(table.email, email))
  if (active) {
    return active
  }

  const row = {
    id: crypto.randomUUID(),
    token: newToken(),
    passwordHash: null,
    ...input,
    email,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + config.loginTimeout).toISOString(),
  }

  // Still an upsert: the conflicting row is expired, or was inserted between
  // the lookup above and here.
  const result = await db
    .insert(table)
    .values(row)
    .onConflictDoUpdate({ target: table.email, set: row })
    .returning()
    .then(takeUnique)

  return result!
}

export const getPendingRegistrationVerification = (
  db: DatabaseClient,
  id: string
) => findActive(db, eq(table.id, id))

export const getPendingRegistrationVerificationByToken = (
  db: DatabaseClient,
  token: string
) => findActive(db, eq(table.token, token))

// Takes a transaction so the caller can roll the delete back when the user
// row it feeds fails to insert. Without that, whichever of two same-name
// registrants clicks second loses their row - and its password hash - to a
// badKnownName that leaves nothing to retry with.
export const claimPendingRegistrationVerificationByToken = (
  db: DatabaseClient | DatabaseTx,
  token: string
): Promise<PendingRegistrationVerification | undefined> =>
  db
    .delete(table)
    .where(and(eq(table.token, token), notExpired))
    .returning()
    .then(takeUnique)

// A pending row holds a name and an address that no user row carries yet, so
// registration has to check here too or it races the verification it already
// sent someone else.
export const getActivePendingByName = (
  db: DatabaseClient,
  name: string
): Promise<PendingRegistrationVerification | undefined> =>
  findActive(db, eq(table.name, name))

export type ClaimPendingRegistrationResult =
  | { success: true; userId: string }
  | {
      success: false
      error: 'badToken' | 'badKnownCtftimeId' | 'badKnownEmail' | 'badKnownName'
    }

// Claim and create together, so a create that loses a name race does not take
// the pending row - and the password hash it now carries - down with it. The
// transaction is not optional either way: a failed insert aborts the Postgres
// transaction, so the claimed delete could never have been committed.
export const claimPendingRegistration = async (
  db: DatabaseClient,
  token: string
): Promise<ClaimPendingRegistrationResult> => {
  let failure: ClaimPendingRegistrationResult | undefined

  try {
    return await db.transaction(async tx => {
      const pending = await claimPendingRegistrationVerificationByToken(
        tx,
        token
      )
      if (!pending) {
        return { success: false, error: 'badToken' }
      }

      const created = await createUserInternal(tx, {
        division: pending.division,
        email: pending.email,
        name: pending.name,
        ctftimeId: null,
        passwordHash: pending.passwordHash,
      })
      if (created.success) {
        return { success: true, userId: created.userId }
      }

      failure = { success: false, error: created.error }
      tx.rollback()
      // Unreachable: rollback throws. Present so the callback's return type
      // stays ClaimPendingRegistrationResult rather than widening to include
      // undefined.
      return failure
    })
  } catch (error) {
    // Only the rollback above is ours; anything else is a real failure.
    if (failure) {
      return failure
    }
    throw error
  }
}

export const getPendingRegistrationVerifications = async (
  db: DatabaseClient
): Promise<PendingRegistrationVerification[]> => {
  await db.delete(table).where(sql`${table.expiresAt} <= now()`)
  return db
    .select()
    .from(table)
    .where(notExpired)
    .orderBy(desc(table.createdAt))
}

export const deletePendingRegistrationVerification = async (
  db: DatabaseClient,
  id: string
): Promise<void> => {
  await db.delete(table).where(eq(table.id, id))
}
