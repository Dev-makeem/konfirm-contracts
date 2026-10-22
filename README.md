# konfirm-contracts

Four Soroban smart contracts backing [Konfirm](https://github.com/Konfirm-xyz/konfirm-backend), a non-custodial payment processor on Stellar. All four are deployed to Testnet (addresses below); none are currently called by the live checkout or cash-out flow in `konfirm-backend` — today's pilot moves value with plain Stellar classic payments, and these contracts are the on-chain layer that path is built toward.

> Redeploying? See [RUNBOOK.md](RUNBOOK.md) for the full procedure, including what happens to in-flight treasury/channel state at cutover.

## Branch protection

`main` is protected. The rule is declared in [`.github/branch-protection.json`](.github/branch-protection.json) and applied with:

```bash
gh api -X PUT repos/Konfirm-xyz/konfirm-contracts/branches/main/protection \
  --input .github/branch-protection.json
```

It requires pull requests with at least one approving review, requires the CI `test` and `audit` status checks to be green (and up to date with `main`), and blocks force-pushes and branch deletion. Verify with `gh api repos/Konfirm-xyz/konfirm-contracts/branches/main/protection` (expects 200).

## Contracts

| Contract | Purpose |
|---|---|
| `compliance` | Default-allow address screening with an explicit deny/allow list, pausable |
| `payment` | Attestation layer — records that a payment happened and its refund state; not an escrow |
| `treasury` | 2-of-3 multisig settlement: propose → approve → execute |
| `channel` | Escrow-backed payment channels with checkpointing, a configurable challenge period, and unilateral close |

Every contract follows the same shape: an `initialize` entry point and a `pause`/`unpause` pair. Most mutations check the pause flag before touching state, but pause-gating is not uniform — `channel` deliberately exempts its checkpoint, hold/release, and close lifecycle from pause (see the `channel` section below).

### Upgradeability

All four contracts are **immutable by design**: none exposes `update_current_contract_wasm` or any other upgrade mechanism, even though the pinned `soroban-sdk` supports it. This is a deliberate trust-minimization choice — no admin key, multisig, or timelock can swap the code under a deployed instance. The operational consequence is that a bug found after deployment cannot be patched in place; it can only be fixed by shipping a whole new contract instance and migrating every open channel and pending settlement to it. The redeploy and migration mechanics are covered in #57.

### `compliance`

| Function | Signature |
|---|---|
| `initialize` | `(admin: Address)` |
| `is_allowed` | `(addr: Address) -> bool` |
| `block_address` / `allow_address` / `clear_address` | `(addr: Address)` |
| `set_admin` | `(current_admin: Address, new_admin: Address)` — both must authorize; not pause-gated |
| `pause` / `unpause` | `()` |

Default-allow: an address is permitted unless explicitly blocked. `clear_address` restores the default rather than leaving an explicit "allowed" entry.

**Advisory, not enforced on-chain.** `compliance` is consulted off-chain by `konfirm-backend` (`isAllowedOnChain`) before it calls `payment::record_payment` or proposes a `treasury` settlement. The `payment`, `treasury`, and `channel` contracts never call `compliance`, so a blocked address is not rejected by them. Treat `compliance` as the screening source of truth for the backend, not as a hard on-chain gate. Wiring it in as a gate would mean passing the compliance contract ID into `payment` and `treasury` at initialization and checking `is_allowed` in `record_payment`, `propose_settlement`, and `execute_settlement`.

### `payment`

| Function | Signature |
|---|---|
| `initialize` | `(admin: Address)` |
| `record_payment` | see `lib.rs` — writes a payment record |
| `mark_refunded` | `(payment_id: u64)` — rejects a second refund on the same ID |
| `get_payment` | `(payment_id: u64) -> PaymentRecord` |
| `set_admin` | `(current_admin: Address, new_admin: Address)` — both must authorize; not pause-gated |
| `pause` / `unpause` | `()` |

### `treasury`

| Function | Signature |
|---|---|
| `initialize` | signer set + threshold |
| `propose_settlement` | creates a pending settlement |
| `approve_settlement` | `(signer: Address, settlement_id: u64)` — rejects non-signers and double-approval |
| `execute_settlement` | `(caller: Address, settlement_id: u64)` — caller must be a signer; only once threshold is met; rejects double-execution |
| `get_settlement` | `(settlement_id: u64) -> Settlement` |
| `pause` / `unpause` | `()` — gated by the signer threshold, not a single admin key |

Deployed with a 2-of-3 threshold (see [Deployed addresses](#deployed-addresses-testnet)).

**Pause is signer-threshold-gated.** Unlike `compliance`, `payment`, and `channel` — whose `pause`/`unpause` are single-admin-key operations — `treasury`'s `pause`/`unpause` require the same signer threshold used for settlements. A single admin key cannot unilaterally freeze the treasury; pausing requires the same N-of-M signer approval as a settlement. This closes the single-key pause-DoS surface on the treasury contract.

### `channel`

| Function | Signature |
|---|---|
| `initialize` | `(admin: Address, challenge_period_secs: u64)` — challenge period is a deployment-time parameter, not hardcoded |
| `open_channel` | opens an escrow-backed channel |
| `top_up` | `(payer: Address, channel_id: u64, amount: i128)` |
| `checkpoint` | signed state update; rejects stale nonces |
| `initiate_close` / `finalize_close` | unilateral close, respecting the challenge period; refunds the remainder once it elapses |
| `hold_channel` / `release_hold` | freezes/unfreezes checkpointing without closing |
| `get_channel_info` | `(channel_id: u64) -> Channel` |
| `set_admin` | `(current_admin: Address, new_admin: Address)` — both must authorize; not pause-gated |
| `pause` / `unpause` | `()` |

**Pause scope.** Pause exists to stop new exposure, not to freeze funds someone can already prove is owed to them. Only `open_channel` and `top_up` check the pause flag. `checkpoint`, `hold_channel`, `release_hold`, `initiate_close`, and `finalize_close` are deliberately not pause-gated — pausing must never block a withdrawal or close that a party can already prove is owed. This matches the module doc in `contracts/channel/src/lib.rs`.

Signed checkpoint messages are domain-separated with `DOMAIN_TAG = b"KONFIRM_CHAN_V1"` (15 bytes) prefixed onto the signing payload. The full payload is `DOMAIN_TAG || channel_id (u64 BE) || nonce (u64 BE) || cumulative_amount (i128 BE)` — it does **not** include the contract's own address. Because `DOMAIN_TAG` is a compile-time constant identical across every deployment of the same source, this prevents replay across `(channel_id, nonce, cumulative_amount)` within a single deployed instance, but it does **not** prevent replay of a signature against a different deployment of the same contract. Binding `env.current_contract_address()` into the payload would close that gap; that change is tracked separately.

The deployed instance uses `challenge_period_secs = 86400` (24 hours). Shorter/longer periods for lower/higher-value channels are a deployment decision, not a contract feature. The contract enforces one constraint only: the value must be greater than zero. `initialize` returns `InvalidChallengePeriod` for `0`. A zero period would let `finalize_close` succeed in the same ledger as `initiate_close`, which leaves the payee no window to checkpoint a higher claim.

**Intentionally unused by the current pilot:** `top_up`, `hold_channel`, and `release_hold` are not called by `konfirm-backend` or `konfirm-frontend` today — the pilot's happy path only needs `open_channel`/`checkpoint`/`initiate_close`/`finalize_close`/`get_channel_info`. They stay in the deployed contract as the on-chain surface for features that will need them: `top_up` when a channel must accept additional deposit capacity beyond its opening balance, and `hold_channel`/`release_hold` when dispute or hold semantics (freezing checkpointing without closing) land in the backend. Wire them up at that point rather than removing them now.

## Deployed addresses (Testnet)

This table is the **single source of truth** for deployed contract addresses. Any other file that records a deployed address (e.g. a local `artifacts/addresses.json`) is non-authoritative and is checked against this table by `scripts/check_deployed_addresses.py` in CI — a mismatch fails the build.

| Contract | Address |
|---|---|
| Compliance | `CDDVLE2DZQAYFY3Z2Z74TUNNPC4ROUACSBXOB2P64IT75EZFAQXSRSXY` |
| Payment | `CCYRA6JT2L4NS5FG4B5TP52JPCGCPYSP7M6LUDUY2QA37V5UBXWJBRHV` |
| Treasury | `CD77HPVBGIRYQGXC4JVCEO35X6FKFFJ2C4EZ63EQCOXGR6OL4TVEPZ2T` |
| Channel | `CDS2Y4CQMQWFLCG5GHVKX7UIXHYPM6IJDJZTEXSASSHGHLESGLGLNPL6` |

Deployer: `GAEMG5TVLEIQYCY3XB4EJT742DIE3FQO53RSESSYJQUZIWZOJQIZATJS`

Treasury signers (2-of-3 threshold): `GAEMG5TVLEIQYCY3XB4EJT742DIE3FQO53RSESSYJQUZIWZOJQIZATJS`, `GBRUR4UZHKPQ76S4S7X7INENL6QJ4UGNFIQ3F6VAYJQZRO3F4XBZAIND`, `GCP57AJNZIVVTPPSD4MJ2SQDMTN4QEAUP64U2OZ4HXSAU4O4A6NOWY2Z`

### Recording provenance on redeploy

Whenever a contract is redeployed, record the commit it was built from so the mapping above never rots:

1. Note the short SHA of `HEAD` at deploy time: `git rev-parse --short HEAD`.
2. Update the **Commit** column for the redeployed contract(s) in the table above.
3. Update the matching `commit` field next to that network's addresses in `artifacts/addresses.json`.
4. Optionally tag the deploy (`git tag testnet-deploy-YYYY-MM-DD`) so the exact build is also reachable by tag.

## Tech stack

- Rust, `soroban-sdk 27.0.5`
- `#![no_std]` contracts — no heap allocation, no std library
- 27 unit tests across the four contracts using `soroban-sdk`'s `testutils`

## Prerequisites

- Rust — the exact toolchain is pinned in `rust-toolchain.toml` (`channel = "1.82.0"`). `rustup` installs it automatically on a fresh checkout; no manual override is needed.
- The `wasm32v1-none` target — **not** `wasm32-unknown-unknown`. `soroban-sdk 27` rejects `wasm32-unknown-unknown` on Rust 1.82+, so `rust-toolchain.toml` declares `wasm32v1-none` and `rustup` installs it for you. If you manage toolchains manually:

  ```bash
  rustup target add wasm32v1-none
  ```
- [Stellar CLI](https://developers.stellar.org/docs/tools/developer-tools/cli/stellar-cli) (`stellar` on `$PATH`) for building and deploying

## Build & test

```bash
cargo test --all --features testutils
```

The `testutils` feature must be enabled. Plain `cargo test` fails to compile, because the test code imports `soroban_sdk::testutils`. CI runs the command above.

```bash
stellar contract build
```

Current `stellar-cli` (27.x) bakes in the `wasm32v1-none` target for `contract build` and rejects a `--target` flag, so no target argument is needed.

Deploy, then initialize. These contracts have **no constructor**: passing `-- --admin ...` at deploy time does not set them up. The `initialize` call is separate. The `channel` example:

```bash
stellar contract deploy \
  --wasm target/wasm32v1-none/release/konfirm_channel.wasm \
  --source deployer --network testnet
# -> prints the contract id, <CONTRACT_ID>

stellar contract invoke --id <CONTRACT_ID> \
  --source deployer --network testnet \
  -- initialize --admin <admin_address> --challenge_period_secs 86400
```

Each contract's `initialize` takes its own arguments: `compliance` and `payment` take `--admin`; `treasury` takes `--admin --token --signers --threshold`; `channel` takes `--admin --challenge_period_secs`. Calling it twice fails with `AlreadyInitialized`, which is the protection.

### `treasury` deploy + initialize

`treasury::initialize(env, admin: Address, token: Address, signers: Vec<Address>, threshold: u32)` takes a `Vec<Address>` for `signers`. The Stellar CLI parses that as a **JSON array of quoted addresses** — a bare space-separated list will not work:

```bash
stellar contract deploy \
  --wasm target/wasm32v1-none/release/konfirm_treasury.wasm \
  --source deployer --network testnet
# -> prints the contract id, <CONTRACT_ID>

```
contracts/
  compliance/   allow/deny-list screening
  payment/      payment attestation + refund tracking
  treasury/     multisig settlement
  channel/      escrow-backed payment channels
artifacts/      local deployment output (gitignored — contains only public addresses, kept local to avoid churn on every redeploy).
                NOT authoritative: it is never regenerated automatically and can go stale. The Deployed addresses table above is the source of truth;
                scripts/check_deployed_addresses.py fails CI if any tracked file disagrees with it.
scripts/        repo checks (pub fn auth, deployed-address consistency)
```
