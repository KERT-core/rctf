<script lang="ts">
  import {
    ConfirmPasswordResetRouteV2,
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    ProtectedAction,
    ResetPasswordRouteV2,
  } from '@rctf/types'
  import { useQueryClient } from '@tanstack/svelte-query'
  import { goto } from '$app/navigation'
  import { page } from '$app/state'
  import { setToken } from '$lib/api'
  import ArchivedNotice from '$lib/components/archived-notice.svelte'
  import CaptchaNotice from '$lib/components/captcha-notice.svelte'
  import {
    canSubmitPassword,
    passwordMismatchError,
  } from '$lib/forms/password-logic'
  import { useApiForm } from '$lib/forms/use-api-form.svelte'
  import { useClientConfig } from '$lib/query/config'
  import { queryKeys } from '$lib/query/keys'
  import { toast } from '$lib/toast'
  import Button from '$lib/ui/button.svelte'
  import Card from '$lib/ui/card.svelte'
  import Field from '$lib/ui/field.svelte'
  import Input from '$lib/ui/input.svelte'
  import Spinner from '$lib/ui/spinner.svelte'
  import { onMount } from 'svelte'

  const queryClient = useQueryClient()
  const configQuery = useClientConfig()
  const clientConfig = $derived(configQuery.data)

  // Captured once, then scrubbed from the address bar the way the login page
  // scrubs its own token. Reading it reactively would lose it on the scrub.
  let resetToken = $state<string | null>(null)
  let tokenRead = $state(false)
  let emailSent = $state(false)
  let confirmPassword = $state('')

  const requestForm = useApiForm(ResetPasswordRouteV2, {
    defaults: { email: '' },
    onSuccess: () => {
      emailSent = true
      toast.success('Reset email sent!')
    },
  })

  const confirmForm = useApiForm(ConfirmPasswordResetRouteV2, {
    defaults: { password: '' },
    onSuccess: response => {
      setToken(response.data.authToken)
      toast.success('Password updated. You are now logged in.')
      queryClient.invalidateQueries({ queryKey: queryKeys.userSelf })
      goto('/profile')
    },
  })

  const passwordMismatch = $derived(
    passwordMismatchError(confirmForm.data.password, confirmPassword)
  )
  const canSubmit = $derived(
    canSubmitPassword(
      confirmForm.data.password,
      confirmPassword,
      undefined,
      false
    )
  )

  function submitConfirm(event: SubmitEvent) {
    event.preventDefault()
    if (!resetToken) return
    confirmForm.setData({ resetToken })
    confirmForm.submit()
  }

  onMount(() => {
    const cleanUrl = new URL(page.url)
    const token = cleanUrl.searchParams.get('token')
    tokenRead = true
    if (token === null) return

    cleanUrl.searchParams.delete('token')
    window.history.replaceState(
      window.history.state,
      '',
      `${cleanUrl.pathname}${cleanUrl.search}${cleanUrl.hash}`
    )
    if (!token) return

    resetToken = token
  })
</script>

<svelte:head>
  {#if clientConfig}
    <title>Reset password | {clientConfig.ctfName}</title>
  {/if}
</svelte:head>

{#if clientConfig?.isArchived}
  <ArchivedNotice message="Password reset is not available." />
{:else if resetToken}
  <Card title="Set a new password" description="Choose a new password">
    <auth-page>
      <form onsubmit={submitConfirm}>
        <Field
          label="New password"
          description="{MIN_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH} characters."
          error={confirmForm.errors.password ?? confirmForm.errors._form}
        >
          {#snippet children({ id, describedBy })}
            <Input
              {id}
              name="password"
              type="password"
              placeholder="Enter a new password"
              autocomplete="new-password"
              minlength={MIN_PASSWORD_LENGTH}
              maxlength={MAX_PASSWORD_LENGTH}
              required
              aria-describedby={describedBy}
              aria-invalid={!!confirmForm.errors.password || undefined}
              bind:value={confirmForm.data.password}
              oninput={() => confirmForm.validateField('password')}
            />
          {/snippet}
        </Field>
        <Field label="Confirm new password" error={passwordMismatch}>
          {#snippet children({ id, describedBy })}
            <Input
              {id}
              name="confirmPassword"
              type="password"
              placeholder="Repeat your new password"
              autocomplete="new-password"
              minlength={MIN_PASSWORD_LENGTH}
              maxlength={MAX_PASSWORD_LENGTH}
              required
              aria-describedby={describedBy}
              aria-invalid={!!passwordMismatch || undefined}
              bind:value={confirmPassword}
            />
          {/snippet}
        </Field>
        <Button type="submit" disabled={confirmForm.submitting || !canSubmit}>
          {#if confirmForm.submitting}
            <Spinner />
          {/if}
          Set password
        </Button>
      </form>
      <footer-note
        >Setting a password signs out your other sessions, including anyone
        holding your team token.</footer-note
      >
    </auth-page>
  </Card>
{:else if emailSent}
  <Card title="Reset email sent" description="Check your inbox for the link">
    <auth-page>
      <p>
        If an account exists for <strong>{requestForm.data.email}</strong>,
        we've sent a link to set a new password. If you didn't receive it, check
        your spam folder or
        <button type="button" onclick={() => (emailSent = false)}
          >try again</button
        >.
      </p>
    </auth-page>
  </Card>
{:else if tokenRead}
  <Card
    title="Reset password"
    description="Get a password reset link sent to your email"
  >
    <auth-page>
      <form onsubmit={requestForm.submit}>
        <Field
          label="Email"
          error={requestForm.errors.email ?? requestForm.errors._form}
        >
          {#snippet children({ id, describedBy })}
            <Input
              {id}
              name="email"
              type="email"
              placeholder="Enter your email"
              autocomplete="email"
              required
              aria-describedby={describedBy}
              aria-invalid={!!requestForm.errors.email ||
                !!requestForm.errors._form ||
                undefined}
              bind:value={requestForm.data.email}
            />
          {/snippet}
        </Field>
        <Button type="submit" disabled={requestForm.submitting}>
          {#if requestForm.submitting}
            <Spinner />
          {/if}
          Send reset link
        </Button>
      </form>
      <footer-note
        >Remembered it? <a href="/login">Login here</a>. An account with no
        email address can only be reset by an organizer.</footer-note
      >
      <CaptchaNotice config={clientConfig} action={ProtectedAction.Recover} />
    </auth-page>
  </Card>
{/if}
