# `mykey-secrets`

## Purpose

`mykey-secrets` is MyKey’s Secret Service provider.

It runs in the user session and claims `org.freedesktop.secrets` when MyKey is
the active provider.

## What It Does

It provides:

- collections
- items
- aliases
- Secret Service D-Bus methods for desktop clients

It is backed by MyKey’s daemon and storage model rather than a plain
software-only keyring design.

## Ownership Model

The important split is:

- provider/session state belongs in a user-owned data path
- secret protection still relies on MyKey’s daemon-owned security model

This is why `mykey-secrets` should be treated as a user-session service, not a
system daemon.

## Activation Rule

Do not tell users to enable `mykey-secrets` directly as the first setup step.

The intended handoff is:

```bash
mykey-migrate --enroll
```

That command is responsible for:

- detecting the current provider
- copying secrets safely
- stopping the old provider at the right point
- enabling and starting `mykey-secrets` only after takeover is safe

## Current State

Recent fixes in this area include:

- coherent runtime create/replace/delete behavior
- atomic on-disk writes
- user-path ownership cleanup
- opt-in logging instead of default `/tmp` logs

## Unenroll Rule

Provider restoration is owned by:

```bash
mykey-migrate --unenroll
```

Package removal should not try to replace that workflow.
