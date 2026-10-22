# Redeploy Runbook

This is the authoritative procedure for redeploying the Konfirm Soroban contracts. It lives here, in the repo that owns the contracts, so it does not drift from the code. The backend's `docs/specs/03-deployer-admin.md` is a consumer-side note, not the source of truth.

Each of the four contracts (`compliance`, `payment`, `treasury`, `channel`) is an independent deployment with its own address and its own one-shot `initialize`. A redeploy means new addresses for every contract you redeploy, and every place that embeds an address must be updated.

## 1. Pre-redeploy checklist (in-flight state)

A redeploy does **not** migrate state. The new instances start empty. Before you cut over, decide explicitly what happens to each of the following and record the decision in the PR that does the redeploy:

- **Pending treasury settlements.** `treasury` settlements that are proposed/approved but not yet executed live only in the old instance. Either execute or resolve them on the old instance before cutover, or state in the PR that they are abandoned. Funds held by the old treasury contract stay at the old address; sweep them with a final settlement or a token transfer before abandoning it.
- **Open channel balances.** `channel` escrows payer funds on open. Channels that are open (or in their challenge period) at cutover are stranded on the old instance. Either let them close and finalize on the old instance first, or state that they are abandoned and that the escrowed funds are forfeit. Do not cut over with channels mid-challenge unless you have decided this.
- **Compliance block/allow list.** `compliance` is default-allow and stores its block list in the old instance. The new instance starts with an empty block list. Re-apply every currently blocked address to the new instance before cutover, or state that the list is intentionally reset. This is a compliance decision, not a formality.
- **Pause state.** Pausing is per-instance. A paused old contract does not pause the new one. Confirm the intended pause state of each new instance after `initialize`.

If any of the above is left unresolved, the redeploy is not ready to cut over.

## 2. Deploy and initialize

For each contract being redeployed:

1. Build the optimized wasm (see the README deploy section).
2. Deploy the wasm to get a new contract address.
3. Call `initialize` exactly once with the intended parameters. Deploy and initialize are separate steps; a deployed-but-uninitialized contract rejects admin calls with `NotInitialized`.
   - `treasury`: set the signer set and threshold. The threshold is fixed at initialization; changing it later means another redeploy.
   - `channel`: set `challenge_period_secs` (the Testnet instance uses 86400). It is a deployment parameter, not hard-coded.
   - `compliance` / `payment`: set the admin.
4. Re-apply the compliance block list (see section 1) if you redeployed `compliance`.

## 3. Files and repos that embed a contract address

Cross-check this list with a grep at write time rather than trusting it blindly:

```
grep -rniE "C[A-Z2-7]{55}" --include='*.rs' --include='*.md' --include='*.toml' --include='*.ts' --include='*.js' --include='*.json' .
```

Known locations to update (verify each still exists and add any new ones the grep finds):

- **konfirm-contracts** (this repo): `README.md` deploy section, and any example/config that pins an address.
- **konfirm-backend**: the compliance client, the reconciler, and the hardcoded address copy in the backend itself (see the companion backend issue). Also `docs/specs/03-deployer-admin.md` if it quotes addresses.
- **konfirm-frontend** (or any other consumer): any environment/config file that pins a contract address.

Update every hit in the same change window as the cutover. A stale address in any one of them points a live caller at the old instance.

## 4. Verify before cutover

Read back each new instance's storage and confirm it matches intent before pointing any caller at it:

- `treasury`: signer set and threshold match the intended configuration.
- `channel`: `challenge_period_secs` matches intent.
- `compliance`: admin is correct and the block list has been re-applied.
- `payment`: admin is correct.

Only after the read-back matches intent should you update the addresses in section 3 and cut over. If the read-back does not match, redeploy rather than trying to patch a mis-initialized instance (initialize is one-shot).
