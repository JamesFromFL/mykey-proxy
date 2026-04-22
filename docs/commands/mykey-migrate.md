# `mykey-migrate`

## Purpose

`mykey-migrate` owns Secret Service provider handoff.

This command is the supported boundary for:

- enrolling into MyKey Secret Service ownership
- restoring the previous provider

## Commands

```bash
mykey-migrate --enroll
mykey-migrate --unenroll
```

## `--enroll`

`--enroll` should:

- detect the current Secret Service provider
- ensure the old provider is still readable
- copy secrets into MyKey
- stop or replace the old provider only after migration is safe
- enable and start `mykey-secrets` when takeover is complete

This is why users should not be told to enable `mykey-secrets` first by hand.

## `--unenroll`

`--unenroll` should:

- restore the previous provider
- move secrets back where appropriate
- only leave MyKey out of the provider path after the old provider is ready

## Packaging Rule

Package install and uninstall should not try to replace this workflow.

Good package behavior:

- install files
- print setup guidance
- preserve MyKey state on removal

Bad package behavior:

- auto-running provider takeover
- auto-running unenroll on package removal
- deleting user secret state during package uninstall

## Recovery Rule

If a user removes MyKey without unenrolling first, recovery should still be
possible by reinstalling and then running:

```bash
mykey-migrate --unenroll
```
