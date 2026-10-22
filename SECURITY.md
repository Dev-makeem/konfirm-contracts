# Security Policy

This repository holds the Soroban contracts that sit on Konfirm's payment and settlement path. If you find a security issue, please report it privately rather than opening a public issue or pull request.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the **Security** tab of this repository and choose **Report a vulnerability**. Include the affected contract, the steps to reproduce, and the impact you expect. Please do not disclose the issue publicly until we have had a chance to respond.

## Scope

In scope:

- Authorization and access control in the `compliance`, `payment`, `treasury`, and `channel` contracts (admin checks, multisig signer and threshold logic, pause handling, `initialize` guards).
- Fund safety: escrow handling and refunds in `channel`, settlement execution in `treasury`, and double-spend or double-refund paths in `payment`.
- Signature verification and replay protection, including the `KONFIRM_CHAN_V1` domain separation and nonce checks in `channel`.
- Key handling for the deployer and treasury signer keys. The operational key procedures are documented in `konfirm-backend/docs/KEYS.md`.

Out of scope:

- Issues that require control of the admin, deployer, or treasury signer keys without a flaw in the contract logic.
- Findings against Stellar or Soroban itself; report those to the upstream projects.
- Deployment parameter choices, such as the challenge period value, which are documented as operational decisions rather than contract guarantees.

## Response

We aim to acknowledge reports within 5 business days. This is a small, actively developed project, so response and fix times may vary. We will keep you informed of progress and credit reporters who want to be credited.

## Repository secret scanning

This is a public repository that also holds deploy address files, so an accidentally committed key or token would be world-visible. GitHub-side secret scanning and push protection must stay enabled as a backstop. These are repository settings toggled by an org admin (Settings → Code security, or the API); they are not configured from code in this repo.

Required state:

- `secret_scanning.status == "enabled"`
- `secret_scanning_push_protection.status == "enabled"`

Verify with:

```
gh api repos/Konfirm-xyz/konfirm-contracts --jq '.security_and_analysis'
```

A quick pass/fail check that fails loudly if either is disabled:

```
gh api repos/Konfirm-xyz/konfirm-contracts \
  --jq 'if (.security_and_analysis.secret_scanning.status == "enabled" and .security_and_analysis.secret_scanning_push_protection.status == "enabled") then "ok" else error("secret scanning and/or push protection disabled") end'
```

Recommended rollout: enable secret scanning first (free for public repos), then enable push protection once any legitimate testnet/test fixture patterns that trigger false positives have been allow-listed in the push protection settings.

## Code scanning (CodeQL) — tracked gap, revisit by 2026-06-30

There is currently no CodeQL or other code-scanning workflow in this repo (`.github/workflows/` contains only `ci.yml`), and `code-scanning/alerts` returns `404 "no analysis found"`:

```
$ gh api repos/Konfirm-xyz/konfirm-contracts/code-scanning/alerts -i
HTTP/2.0 404 Not Found
{"message":"no analysis found", ...}
```

This is a deliberate, tooling-maturity-justified gap rather than an oversight. CodeQL's Rust support is comparatively immature (no default-setup/autobuild parity with mature languages), and `soroban-sdk`'s heavy macro use is a known weak spot for dataflow-based analyzers. We are tracking it here so it gets revisited instead of forgotten.

**Revisit by: 2026-06-30.** At that point, re-evaluate and pick one of:

- Add CodeQL with the `rust` language in beta mode and accept noisy/incomplete results as better than nothing.
- Adopt a lighter-weight static analyzer instead, e.g. `cargo-geiger` for unsafe-usage auditing, or clippy's security-focused lints (partially covered already).
- Keep deferring, with an updated revisit date and rationale.

Until then, no code-scanning workflow is added intentionally.
