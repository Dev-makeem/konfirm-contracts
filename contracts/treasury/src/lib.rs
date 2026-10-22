#![no_std]

use konfirm_common::{require_not_paused, set_paused, CommonError};
use soroban_sdk::{contract, contractclient, contracterror, contractimpl, contracttype, symbol_short, token, vec, Address, Env, Vec};

const TTL_THRESHOLD: u32 = 100;
const TTL_EXTEND_TO: u32 = 5_000_000;

/// Maximum lifetime (in ledgers) a settlement may stay `Pending` before it
/// becomes eligible for permissionless cleanup via `sweep_expired_settlement`.
const MAX_PENDING_LIFETIME: u64 = 17_280; // ~1 day at 5s/ledger

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SettlementStatus {
    Pending,
    Executed,
    Cancelled,
}

#[contracttype]
#[derive(Clone)]
pub struct Settlement {
    pub merchant: Address,
    pub amount: i128,
    pub approvals: Vec<Address>,
    // Parallel to `approvals`: approved_at[i] is the ledger timestamp at which approvals[i] signed.
    pub approved_at: Vec<u64>,
    pub status: SettlementStatus,
    // Ledger timestamp at which the settlement was proposed; used for expiry.
    pub proposed_at: u64,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Token,
    Paused,
    Signers,
    Threshold,
    NextId,
    Settlement(u64),
    Compliance,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum TreasuryError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    /// Never returned: admin/signer gates use `require_auth()`, which traps at the host before this can be produced. Code 3 stays reserved for ABI stability.
    Unauthorized = 3,
    Paused = 4,
    NotFound = 5,
    ZeroAmount = 6,
    NotSigner = 7,
    AlreadyApproved = 8,
    ThresholdNotMet = 9,
    NotPending = 10,
    InvalidThreshold = 11,
    DuplicateSigner = 12,
    NotExpired = 13,
}

impl From<CommonError> for TreasuryError {
    fn from(err: CommonError) -> Self {
        match err {
            CommonError::NotInitialized => TreasuryError::NotInitialized,
            CommonError::Paused => TreasuryError::Paused,
        }
    }
}

#[contract]
pub struct TreasuryContract;

#[contractimpl]
impl TreasuryContract {
    /// One-time setup. Requires the admin's auth; not pause-gated. Stores the
    /// admin, the payout token, the signer set and the approval threshold —
    /// the number of distinct signer approvals a settlement needs before it
    /// can execute. Fails with `AlreadyInitialized` on a second call,
    /// `InvalidThreshold` unless `1 <= threshold <= signers.len()`, and
    /// `DuplicateSigner` if an address appears twice in `signers`. The
    /// contract holds no funds until it is funded separately;
    /// `execute_settlement` pays out of its balance.
    pub fn initialize(
        env: Env,
        admin: Address,
        token: Address,
        signers: Vec<Address>,
        threshold: u32,
    ) -> Result<(), TreasuryError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(TreasuryError::AlreadyInitialized);
        }
        if threshold == 0 || threshold > signers.len() {
            return Err(TreasuryError::InvalidThreshold);
        }
        for (i, signer) in signers.iter().enumerate() {
            if signers.iter().skip(i + 1).any(|other| other == signer) {
                return Err(TreasuryError::DuplicateSigner);
            }
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Token, &token);
        env.storage().instance().set(&DataKey::Paused, &false);
        env.storage().instance().set(&DataKey::Signers, &signers);
        env.storage().instance().set(&DataKey::Threshold, &threshold);
        env.storage().instance().set(&DataKey::NextId, &1u64);
        env.events().publish((symbol_short!("init"),), admin);
        Ok(())
    }

    /// Admin-only. Sets the compliance contract consulted by
    /// `propose_settlement` and `execute_settlement` to reject blocked
    /// addresses before funds move. Fails with `NotInitialized` before
    /// `initialize`.
    pub fn set_compliance(env: Env, compliance: Address) -> Result<(), TreasuryError> {
        Self::require_admin(&env)?;
        env.storage().instance().set(&DataKey::Compliance, &compliance);
        env.events().publish((symbol_short!("compliance"),), compliance);
        Ok(())
    }

    // Requires `who`'s auth and that `who` is in the signer set (`NotSigner`).
    fn require_signer(env: &Env, who: &Address) -> Result<(), TreasuryError> {
        who.require_auth();
        let signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .ok_or(TreasuryError::NotInitialized)?;
        if !signers.contains(who) {
            return Err(TreasuryError::NotSigner);
        }
        Ok(())
    }

    // Requires the stored admin's auth; `NotInitialized` before `initialize`.
    // Delegates to the shared `konfirm_common::require_admin` helper.
    fn require_admin(env: &Env) -> Result<(), TreasuryError> {
        require_admin(env, &DataKey::Admin)?;
        Ok(())
    }

    // Rejects `who` if the configured compliance contract reports it blocked.
    // No-op when no compliance contract has been configured.
    fn require_allowed(env: &Env, who: &Address) -> Result<(), TreasuryError> {
        if let Some(compliance) = env.storage().instance().get::<DataKey, Address>(&DataKey::Compliance) {
            let client = ComplianceClient::new(env, &compliance);
            if !client.is_allowed(who) {
                return Err(TreasuryError::ComplianceBlocked);
            }
        }
        Ok(())
    }

    // Persists a Settlement and bumps its persistent-entry TTL, mirroring
    // `channel::save_channel`. Every Settlement write must go through here so
    // a settlement that sits `Pending` through a slow multisig review is never
    // archived out from under `approve_settlement`/`execute_settlement`.
    //
    // TTL horizon: `TTL_EXTEND_TO` (5_000_000 ledgers) is the same horizon the
    // channel contract uses. At ~5s per ledger that is roughly 9 months, far
    // longer than any realistic approval cycle (days to weeks), so a Pending
    // settlement stays live across the whole review window without an
    // off-chain restore op.
    fn save_settlement(env: &Env, id: u64, settlement: &Settlement) {
        env.storage().persistent().set(&DataKey::Settlement(id), settlement);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::Settlement(id), TTL_THRESHOLD, TTL_EXTEND_TO);
    }

    // Current token balance held by this contract.
    fn token_balance(env: &Env) -> i128 {
        let token: Address = match env.storage().instance().get(&DataKey::Token) {
            Some(t) => t,
            None => return 0,
        };
        token::Client::new(env, &token).balance(&env.current_contract_address())
    }

    // Sum of `amount` across every still-`Pending` settlement. These have
    // first claim on the treasury balance ahead of any newly-approved
    // settlement, so signers should treat this as committed funds.
    fn pending_committed(env: &Env) -> i128 {
        let next_id: u64 = env.storage().instance().get(&DataKey::NextId).unwrap_or(1);
        let mut total: i128 = 0;
        let mut id: u64 = 1;
        while id < next_id {
            if let Some(settlement) = env
                .storage()
                .persistent()
                .get::<DataKey, Settlement>(&DataKey::Settlement(id))
            {
                if settlement.status == SettlementStatus::Pending {
                    total += settlement.amount;
                }
            }
            id += 1;
        }
        total
    }

    /// Signer-only, pause-gated. Opens a new `Pending` settlement paying
    /// `amount` to `merchant` and returns its id. The proposer's approval
    /// counts as the first of the `threshold` required. Does not move funds.
    /// Fails with `NotSigner`, `ZeroAmount` if `amount <= 0`, and `Paused`
    /// while paused.
    ///
    /// Deliberate choice: this does NOT reject a proposal that would
    /// over-commit the treasury. Over-commitment is allowed and surfaces at
    /// `execute_settlement` time (which traps rather than falsely succeeding).
    /// Signers should consult `available_balance` / `is_settlement_payable`
    /// before approving to avoid committing to a settlement that cannot be
    /// paid in full.
    pub fn propose_settlement(
        env: Env,
        proposer: Address,
        merchant: Address,
        amount: i128,
    ) -> Result<u64, TreasuryError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        Self::require_signer(&env, &proposer)?;
        require_not_paused(&env, &DataKey::Paused)?;
        if amount <= 0 {
            return Err(TreasuryError::ZeroAmount);
        }
        Self::require_allowed(&env, &merchant)?;

        let id: u64 = env.storage().instance().get(&DataKey::NextId).unwrap_or(1);
        env.storage().instance().set(&DataKey::NextId, &(id + 1));

        let settlement = Settlement {
            merchant: merchant.clone(),
            amount,
            approvals: vec![&env, proposer],
            approved_at: vec![&env, env.ledger().timestamp()],
            status: SettlementStatus::Pending,
            proposed_at: env.ledger().timestamp(),
        };
        Self::save_settlement(&env, id, &settlement);
        env.events().publish((symbol_short!("proposed"), merchant), (id, amount));
        Ok(id)
    }

    /// Signer-only, pause-gated. Adds `signer`'s approval to a `Pending`
    /// settlement. Each signer may approve a given settlement once
    /// (`AlreadyApproved`), so the approval count is the number of distinct
    /// signers. Reaching the threshold does not execute the settlement; that
    /// takes a separate `execute_settlement` call. Fails with `NotSigner`,
    /// `NotFound`, `NotPending`, and `Paused` while paused.
    pub fn approve_settlement(env: Env, signer: Address, settlement_id: u64) -> Result<(), TreasuryError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        Self::require_signer(&env, &signer)?;
        require_not_paused(&env, &DataKey::Paused)?;

        let mut settlement: Settlement = env
            .storage()
            .persistent()
            .get(&DataKey::Settlement(settlement_id))
            .ok_or(TreasuryError::NotFound)?;
        if settlement.status != SettlementStatus::Pending {
            return Err(TreasuryError::NotPending);
        }
        if settlement.approvals.contains(&signer) {
            return Err(TreasuryError::AlreadyApproved);
        }
        settlement.approvals.push_back(signer);
        settlement.approved_at.push_back(env.ledger().timestamp());
        Self::save_settlement(&env, settlement_id, &settlement);
        env.events().publish((symbol_short!("approved"),), settlement_id);
        Ok(())
    }

    /// Read-only view. Returns the treasury's current token balance minus the
    /// sum of `amount` across every still-`Pending` settlement. This is the
    /// balance available to a newly-approved settlement after already-pending
    /// settlements' first claim. A negative result means the treasury is
    /// over-committed: some pending settlements cannot be paid in full even
    /// if all of them execute. Signers/tooling should check this before
    /// approving a settlement.
    pub fn available_balance(env: Env) -> i128 {
        Self::token_balance(&env) - Self::pending_committed(&env)
    }

    /// Read-only view. Returns the total amount committed to still-`Pending`
    /// settlements (their first claim on the treasury balance).
    pub fn committed_balance(env: Env) -> i128 {
        Self::pending_committed(&env)
    }

    /// Read-only view. Reports whether `settlement_id` is currently payable in
    /// full given the treasury balance and the first claim of all *other*
    /// still-`Pending` settlements. Returns `false` for a missing or
    /// non-`Pending` settlement. This is a proactive signal: `execute_settlement`
    /// traps rather than falsely succeeding when a settlement is underfunded,
    /// so callers should consult this before relying on a settlement being
    /// payable.
    pub fn is_settlement_payable(env: Env, settlement_id: u64) -> bool {
        let settlement: Settlement = match env
            .storage()
            .persistent()
            .get(&DataKey::Settlement(settlement_id))
        {
            Some(s) => s,
            None => return false,
        };
        if settlement.status != SettlementStatus::Pending {
            return false;
        }
        let others = Self::pending_committed(&env) - settlement.amount;
        Self::token_balance(&env) - others >= settlement.amount
    }

    /// Signer-onl

/* … truncated 1642 chars — edit only what you need near the top … */
