import { getErrorConstraint } from '@rctf/db/util'
import { DeletePasswordRouteV2 } from '@rctf/types'
import {
  checkPassword,
  getUserCredentialsById,
  setUserPassword,
} from '../../../../services/passwords'
import { rateLimitSetPassword } from '../../../../services/rate-limit'
import usersGroup from '../group'

usersGroup.route(DeletePasswordRouteV2, async ({ ctx, res, body, user }) => {
  const timeLeft = await rateLimitSetPassword(ctx.var.redis, user.id)
  if (timeLeft) {
    return res.badRateLimit({ timeLeft })
  }

  const credentials = await getUserCredentialsById(ctx.var.db, user.id)
  if (!credentials) {
    return res.badUnknownUser()
  }

  // No dummy verify: this is the caller's own account and /v2/users/me already
  // tells them whether it has a password, so there is nothing to hide.
  if (!credentials.passwordHash) {
    return res.badCredentials()
  }

  if (!(await checkPassword(body.currentPassword, credentials.passwordHash))) {
    return res.badCredentials()
  }

  let authToken
  try {
    authToken = await setUserPassword(ctx.var.db, ctx.var.redis, user.id, null)
  } catch (error) {
    // Same constraint that removing the last email trips.
    if (getErrorConstraint(error) === 'require_email_or_ctftime_id') {
      return res.badZeroAuth()
    }
    throw error
  }

  if (!authToken) {
    return res.badUnknownUser()
  }

  return res.goodPasswordRemoved({ authToken })
})
