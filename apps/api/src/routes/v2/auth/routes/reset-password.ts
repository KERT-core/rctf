import { ResetPasswordRouteV2 } from '@rctf/types'
import { requestPasswordReset } from '../../../../services/auth'
import authGroup from '../group'

authGroup.route(ResetPasswordRouteV2, async ({ ctx, res, body }) => {
  return await requestPasswordReset(
    res,
    ctx.var.db,
    ctx.var.redis,
    body.email,
    ctx.var.ip
  )
})
