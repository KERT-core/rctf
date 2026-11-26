import { response } from '../internal'

export const BadName = response('badName', {
  status: 400,
  message:
    'The name should only use English or Korean letters, numbers, and symbols.',
})
