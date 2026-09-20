import { ConfirmPasswordResetRouteV2 } from '@rctf/types'
import { confirmPasswordReset } from '../../../../services/auth'
import authGroup from '../group'

authGroup.route(ConfirmPasswordResetRouteV2, async ({ ctx, res, body }) => {
  return await confirmPasswordReset(
    res,
    ctx.var.db,
    ctx.var.redis,
    { resetToken: body.resetToken, password: body.password },
    ctx.var.ip
  )
})
