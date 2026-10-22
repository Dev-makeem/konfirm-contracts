# Contributing

Thanks for working on the Konfirm contracts. Read [`docs/architecture.md`](docs/architecture.md) first for what each of the four contracts does and how they relate, plus the shared `konfirm-common` helper crate they all depend on. The README covers the contract interfaces and deployed addresses.

## Running the tests

The four contracts and the shared `konfirm-common` crate are a single Cargo workspace. Run everything the way CI does:

```bash
cargo test --all --features testutils
```

`testutils` is required. Without it the test code does not compile, because it imports `soroban_sdk::testutils`. Each contract declares that feature in its own `Cargo.toml`.

To run one contract's tests, use its package name:

```bash
cargo test -p konfirm-compliance --features testutils
cargo test -p konfirm-payment --features testutils
cargo test -p konfirm-treasury --features testutils
cargo test -p konfirm-channel --features testutils
cargo test -p konfirm-common --features testutils
```

Tests run against an in-process Soroban environment, not a live RPC endpoint.

Building the WASM artifacts, and the wasm target you need, are covered in the README's "Build & test" section.

## Deploying: deploy, then initialize

These contracts have **no constructor**. Deploying a contract does not set it up. You must call `initialize` as a separate transaction afterwards. Passing `--admin` to `deploy` does nothing.

1. Deploy the WASM. Note the contract ID it prints.
2. Call `initialize` with that contract's arguments.

Until step 2 runs, every admin call on the contract fails with `NotInitialized`. Calling `initialize` a second time fails with `AlreadyInitialized`, which is the protection against re-initialization. The README has a full `channel` example.

This is easy to get wrong once. If a freshly deployed contract rejects every admin call, check that you ran `initialize` before debugging anything else.

## Authorization convention

Every `pub fn` in a contract must fall into one of these categories:

1. **Requires auth from a specific party.** The function calls `require_auth()` on an address, directly or through a helper such as `require_admin` or `require_signer`. Examples: `pause`, `block_address`, `approve_settlement`, `open_channel`, `initiate_close`.
2. **Authorized by signature.** The caller is unrestricted, but the function verifies a signed message. Example: `checkpoint`, which verifies a signature from the payer.
3. **Permissionless.** Anyone can call it. The doc comment must say so, starting with the word `Permissionless`, for example `/// Permissionless — anyone can trigger this once the challenge window has elapsed.` `finalize_close` is the model.

Read-only getters (`get_*`, `is_allowed`) are permissionless by nature. Mark them with a doc comment too, so a reviewer doesn't have to work out whether the absence of `require_auth` is deliberate.

Why this convention exists: `treasury` and `channel` custody real tokens, so a missing or wrong auth check on a state-changing function moves funds. Issue #1 is the reasoning behind the authorization model, and the regression-guard issue is the reasoning behind checking it explicitly. When you add or change a `pub fn`, decide which category it is in and say so in the doc comment.

### Known gaps

The convention is not yet fully applied. These functions are permissionless or signature-authorized but lack the marker the rule asks for:

- `treasury::execute_settlement`: permissionless. Its only gate is the signature threshold. It has no doc comment.
- `treasury::get_settlement`, `payment::get_payment`, `channel::get_channel_info`: read-only, no marker.
- `compliance::is_allowed`: read-only. Its doc comment explains the pause exemption but does not use the category wording.
- `channel::checkpoint`: signature-authorized. Its doc comment says "Never pausable" but does not state its authorization model.

Fixing these is a documentation change. If you touch one of these functions, bring its doc comment up to the convention in the same change.

## Cross-contract calls

Today no contract calls into another contract's address, and no contract's `Cargo.toml` depends on another. That is correct for the current pilot, which moves value with plain Stellar classic payments. Do not add a cross-contract dependency or call speculatively.

**Tripwire (issue #62):** the moment any contract gains a call into another contract's address, a same-Env integration test must land in the same PR. The test must deploy both contracts into one `Env` and assert the cross-contract call path behaves correctly, including the failure path — for example, what happens when the called contract is paused or panics mid-call. A cross-contract call without that test is not mergeable.

## Pull requests

- Keep changes focused on one contract or one concern.
- Run `cargo test --all --features testutils` before you open a PR. CI runs the same command, along with a RustSec audit.
- Any change to authorization, pause behaviour, or fund movement needs a test that exercises the rejected path, not only the success path.
- Any change that introduces a cross-contract call needs a same-Env, two-contract integration test covering both the success and failure paths (see "Cross-contract calls").
