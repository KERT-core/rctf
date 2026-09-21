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

  // Resend the live row instead of replacing it: the upsert below rewrites
  // the token, so another submission would kill a link someone is about to
  // click and overwrite its hash. The cost is that a registrant who mistyped
  // their name or password must wait for the row to expire.
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

  // Still an upsert: any conflicting row is expired, or raced the lookup.
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

// Takes a transaction so a caller can roll the delete back when the insert it
// feeds fails.
export const claimPendingRegistrationVerificationByToken = (
  db: DatabaseClient | DatabaseTx,
  token: string
): Promise<PendingRegistrationVerification | undefined> =>
  db
    .delete(table)
    .where(and(eq(table.token, token), notExpired))
    .returning()
    .then(takeUnique)

// Registration has to check here too: a pending row holds a name no user row
// carries yet.
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
// the pending row down with it. The transaction is not optional either way: a
// failed insert aborts the Postgres transaction.
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
      // Unreachable: rollback throws. Keeps the callback's return type narrow.
      return failure
    })
  } catch (error) {
    // Only the rollback above is ours.
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
