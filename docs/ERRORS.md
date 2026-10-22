# Error Codes

Every contract exposes a `#[contracterror]` enum. Soroban returns the numeric
`u32` code in the `Error(Contract, #N)` result, so callers should match on the
code rather than the variant name. This file is the canonical reference for
those codes.

When you add, remove, or rename a variant in any `#[contracterror]` enum, update
the matching table below. `scripts/check_error_docs.py` fails CI if a variant is
missing from this file.

## payment (`contracts/payment`)

| Code | Variant | Meaning |
| ---- | ------- | ------- |
| 1 | `AlreadyInitialized` | `initialize` was called more than once. |
| 2 | `NotInitialized` | The contract has not been initialized yet. |
| 3 | `Unauthorized` | Caller is not the admin/owner for this operation. |
| 4 | `Paused` | The contract is paused; mutating calls are rejected. |
| 5 | `NotFound` | The referenced payment does not exist. |
| 6 | `InvalidAmount` | Amount is zero or otherwise invalid. |
| 7 | `AlreadyRefunded` | The payment has already been refunded. |
| 8 | `AlreadyVoided` | The payment has already been voided. |
| 9 | `Voided` | The payment was voided; the operation is not allowed. |

## treasury (`contracts/treasury`)

| Code | Variant | Meaning |
| ---- | ------- | ------- |
| 1 | `AlreadyInitialized` | `initialize` was called more than once. |
| 2 | `NotInitialized` | The contract has not been initialized yet. |
| 3 | `Unauthorized` | Caller is not the admin/owner for this operation. |
| 4 | `Paused` | The contract is paused; mutating calls are rejected. |
| 5 | `NotFound` | The referenced treasury entry does not exist. |
| 6 | `InvalidAmount` | Amount is zero or otherwise invalid. |
| 7 | `InsufficientFunds` | The treasury does not hold enough funds. |
| 8 | `InvalidSigner` | A signer address is invalid. |
| 9 | `NotASigner` | The address is not a registered signer. |
| 10 | `AlreadySigned` | This signer has already signed the proposal. |
| 11 | `InvalidThreshold` | The signer threshold is invalid. |
| 12 | `DuplicateSigner` | `initialize` was given the same signer address twice. |

## channel (`contracts/channel`)

| Code | Variant | Trigger |
|---|---|---|
| 1 | `AlreadyInitialized` | `initialize` called after the contract was already set up. |
| 2 | `NotInitialized` | A call that needs stored config (admin, challenge period) made before `initialize`. |
| 3 | `Unauthorized` | `top_up` by someone other than the channel's payer, or `initiate_close` by someone other than the payer or payee. |
| 4 | `Paused` | `open_channel` or `top_up` while paused. `checkpoint`, `initiate_close` and `finalize_close` are never blocked by pause. |
| 5 | `NotFound` | Any call with a channel id that does not exist. |
| 6 | `NotOpen` | `top_up` or `initiate_close` on a channel that is not `Open`; `checkpoint` on a `Closed` channel. |
| 7 | `StaleClaim` | `checkpoint` with a `nonce` not greater than the stored one, or a `cumulative_amount` not greater than what was already claimed. |
| 8 | `ExceedsDeposit` | `checkpoint` with a `cumulative_amount` greater than the channel's deposit. |
| 9 | `ChallengeNotElapsed` | `finalize_close` before `closing_at + challenge period`. |
| 10 | `NotClosing` | `finalize_close` on a channel that is not `Closing`. |
| 11 | `Held` | `checkpoint` on a channel that is `Held` by admin. |
| 12 | `ZeroDeposit` | `open_channel` or `top_up` with an amount `<= 0`. |
| 13 | `NotHeld` | `release_hold` on a channel that is not `Held` (e.g. `Open`, `Closing` or `Closed`). |

## compliance (`contracts/compliance`)

| Code | Variant | Meaning |
| ---- | ------- | ------- |
| 1 | `AlreadyInitialized` | `initialize` was called more than once. |
| 2 | `NotInitialized` | The contract has not been initialized yet. |
| 3 | `Unauthorized` | Caller is not the admin/owner for this operation. |
| 4 | `NotFound` | The referenced compliance record does not exist. |
