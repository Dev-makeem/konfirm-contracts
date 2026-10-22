# Architecture

Four Soroban contracts plus a shared helper crate, one Cargo workspace. Each contract is an independent deployment with its own address and its own `initialize` call. The contracts do not call each other: there are no cross-contract invocations in this repo. The only external calls are to a SEP-41 token contract (`treasury` and `channel`). Anything that connects the four (for example, checking `compliance` before recording a `payment`) happens in the off-chain caller, `konfirm-backend`, not on-chain.

## The four contracts

| Contract | Holds funds? | Who can mutate it | What it's for |
|---|---|---|---|
| [`compliance`](../contracts/compliance/src/lib.rs) | No | Admin | Address screening. Default-allow: an address is permitted unless it is explicitly blocked. |
| [`payment`](../contracts/payment/src/lib.rs) | No | Admin | Attestation. Records that a payment happened and whether it was refunded. It is not an escrow and moves no tokens. |
| [`treasury`](../contracts/treasury/src/lib.rs) | Yes | Signers (propose, approve); anyone (execute, once the threshold is met) | 2-of-3 multisig settlement. Propose, then approve, then execute. Execution transfers the settlement token from the treasury's own balance. |
| [`channel`](../contracts/channel/src/lib.rs) | Yes | Payer opens and tops up; payer or payee starts a close; admin holds and releases; anyone finalizes a close after the challenge period | Escrow-backed off-chain payment channels. The payer locks funds on open. The payee is paid by submitting signed cumulative checkpoints. A close starts a challenge period, and anyone can finalize it once that period has elapsed, refunding the unclaimed remainder to the payer. |

Each contract also has an `initialize` entry point (one-shot, rejects a second call) and a `pause` / `unpause` pair. Pausing blocks mutations. `is_allowed` (compliance) and `checkpoint` (channel) are documented exceptions to the pause rule. See `CONTRIBUTING.md` for the authorization convention.

## The shared helper crate

[`contracts/common`](../contracts/common/src/lib.rs) (`konfirm-common`) is a library crate, not a deployable contract. It centralizes the admin and pause plumbing that all four contracts share:

- `require_admin` — checks the stored admin and rejects unauthorized callers.
- `require_not_paused` — rejects mutations while the contract is paused.
- `set_paused` — flips the stored pause flag.

Error types still differ per contract. `konfirm-common` defines its own `CommonError`, and each contract maps it into its own error enum via `From<CommonError>`. That keeps each contract's public error surface stable and self-describing while sharing the implementation of the checks.

## How they relate

```
                 konfirm-backend (off-chain)
                 ├── is_allowed?  ──────────────► compliance
                 ├── record_payment / mark_refunded ─► payment
                 ├── propose / approve / execute ───► treasury ──(token transfer)──► payee
                 └── open / top_up / checkpoint /
                     close ────────────────────────► channel    ──(token transfer)──► payee / payer
```

- **Compliance gates payments, but only off-chain.** The payment-preparation path in `konfirm-backend` calls `is_allowed` before it builds a payment. No contract checks it. A payment that skips the check will still be recorded and settled on-chain.
- **Payment is a record, not a rail.** `payment` stores the attestation and refund state for a payment. Value moves through classic Stellar payments today, or through `treasury` or `channel` once those are wired in.
- **Treasury holds settlement funds.** Settlements are paid out of the treasury contract's balance. Funding the treasury is an ordinary token transfer to the contract address. The contract does not check the source of funds.
- **Channel is the high-frequency path.** Two parties exchange signed cumulative claims off-chain. The chain only sees the open, any top-ups, the latest checkpoint, and the close. Checkpoints are signed with the domain tag `KONFIRM_CHAN_V1`, so a signature cannot be replayed against another contract.

## Current status

None of the four contracts is called by the live checkout or cash-out flow yet. Today's pilot moves value with plain Stellar classic payments. See the README's "Known limitations".

## Cross-contract calls require a same-Env integration test

Today no contract calls another contract's address, and that is correct for the current phase. This is a forward-looking tripwire, not a current gap: a channel-backed netting engine will likely wire `channel` / `treasury` (and possibly `compliance` gating) together on-chain, at which point cross-contract behavior becomes a real surface that must be tested before it ships.

**Rule:** when any contract gains a call into another contract's address, a same-Env, two-contract integration test must land in the same PR. The test must deploy both contracts into one `Env` and assert the cross-contract call path behaves correctly, including the failure path (for example, what happens if the called contract is paused or panics mid-call). Do not add cross-contract dependencies to a `Cargo.toml` or invent cross-contract calls ahead of that work.

## Things to know before changing anything

- **Deploy and initialize are separate steps.** The contracts have no constructor. A deployed but uninitialized contract rejects admin calls with `NotInitialized`. See the README's deploy section.
- **The challenge period is a deployment parameter.** `channel` takes `challenge_period_secs` at `initialize` and does not hard-code it. The deployed Testnet instance uses 86400 seconds. The contract rejects `0` with `InvalidChallengePeriod`. With `0`, `finalize_close` succeeds in the same ledger as `initiate_close`, so the payee gets no window to checkpoint a higher claim.
- **Treasury threshold is fixed at initialization.** The Testnet instance is 2-of-3. Changing it means a new deployment.

## Design decisions

- **`record_payment` keeps five flat scalar parameters (declined: input struct).** `record_payment` takes its five fields as flat scalars rather than a single input struct, even though they map field-for-field to the `PaymentRecord` it builds. The only caller is `konfirm-backend`'s reconciler, which lives in a separate repository and invokes the contract through generated client bindings; those bindings, and raw Soroban CLI invocation, are both more ergonomic with flat scalar arguments than with a nested struct. A struct parameter would therefore add signature sprawl without any practical benefit at the call site, so the flat signature is intentional and should not be re-raised as a cleanup item.
