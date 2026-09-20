// Shared by the settings form and the reset page. Cross-field rules zod
// cannot express, kept pure so they can be unit tested without a component.

export function passwordMismatchError(
  password: string | undefined,
  confirmPassword: string
): string | null {
  if (confirmPassword === '' || password === confirmPassword) {
    return null
  }
  return 'Passwords do not match'
}

export function canSubmitPassword(
  password: string | undefined,
  confirmPassword: string,
  currentPassword: string | undefined,
  hasPassword: boolean
): boolean {
  if ((password ?? '') === '' || password !== confirmPassword) {
    return false
  }
  return !hasPassword || (currentPassword ?? '') !== ''
}
