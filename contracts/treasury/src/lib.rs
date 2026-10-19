#![no_std]

use konfirm_common::{require_not_paused, set_paused, CommonError};
use soroban_sdk::{contract, contracterror, contractimpl, contracttype, symbol_short, token, vec, Address, Env, Vec};

const TTL_THRESHOLD: u32 = 100;
const TTL_EXTEND_TO: u32 = 5_000_000;

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
    fn require_admin(env: &Env) -> Result<(), TreasuryError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(TreasuryError::NotInitialized)?;
        admin.require_auth();
        Ok(())
    }

    /// Signer-only, pause-gated. Opens a new `Pending` settlement paying
    /// `amount` to `merchant` and returns its id. The proposer's approval
    /// counts as the first of the `threshold` required. Does not move funds.
    /// Fails with `NotSigner`, `ZeroAmount` if `amount <= 0`, and `Paused`
    /// while paused.
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

        let id: u64 = env.storage().instance().get(&DataKey::NextId).unwrap_or(1);
        env.storage().instance().set(&DataKey::NextId, &(id + 1));

        let settlement = Settlement {
            merchant: merchant.clone(),
            amount,
            approvals: vec![&env, proposer],
            approved_at: vec![&env, env.ledger().timestamp()],
            status: SettlementStatus::Pending,
        };
        env.storage().persistent().set(&DataKey::Settlement(id), &settlement);
        env.storage().persistent().extend_ttl(&DataKey::Settlement(id), TTL_THRESHOLD, TTL_EXTEND_TO);
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
        settlement.approvals.push_back(signer.clone());
        settlement.approved_at.push_back(env.ledger().timestamp());
        env.storage().persistent().set(&DataKey::Settlement(settlement_id), &settlement);
        env.storage().persistent().extend_ttl(&DataKey::Settlement(settlement_id), TTL_THRESHOLD, TTL_EXTEND_TO);
        env.events().publish((symbol_short!("approved"), signer), settlement_id);
        Ok(())
    }

    /// Signer-only, pause-gated. Any one signer (`caller`) can execute once the
    /// settlement's approval count reaches the threshold; fails with
    /// `ThresholdNotMet` before then. Executing does not count as an approval.
    /// Transfers `amount` of the payout token from the treasury to the
    /// merchant, then marks the settlement `Executed`. If the transfer traps,
    /// the whole call reverts and the settlement stays `Pending`. Also fails
    /// with `NotSigner`, `NotFound`, `NotPending`, and `Paused` while paused.
    pub fn execute_settlement(env: Env, caller: Address, settlement_id: u64) -> Result<(), TreasuryError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        Self::require_signer(&env, &caller)?;
        require_not_paused(&env, &DataKey::Paused)?;
        let threshold: u32 = env
            .storage()
            .instance()
            .get(&DataKey::Threshold)
            .ok_or(TreasuryError::NotInitialized)?;

        let mut settlement: Settlement = env
            .storage()
            .persistent()
            .get(&DataKey::Settlement(settlement_id))
            .ok_or(TreasuryError::NotFound)?;
        if settlement.status != SettlementStatus::Pending {
            return Err(TreasuryError::NotPending);
        }
        if settlement.approvals.len() < threshold {
            return Err(TreasuryError::ThresholdNotMet);
        }
        // Transfer before marking Executed, same order-of-operations
        // channel::checkpoint already uses — if the transfer traps (e.g.
        // this contract's own balance is somehow short), the whole call
        // reverts and the settlement stays Pending rather than being
        // marked paid out when it wasn't.
        let token: Address = env
            .storage()
            .instance()
            .get(&DataKey::Token)
            .ok_or(TreasuryError::NotInitialized)?;
        token::TokenClient::new(&env, &token).transfer(
            &env.current_contract_address(),
            &settlement.merchant,
            &settlement.amount,
        );

        settlement.status = SettlementStatus::Executed;
        env.storage().persistent().set(&DataKey::Settlement(settlement_id), &settlement);
        env.storage().persistent().extend_ttl(&DataKey::Settlement(settlement_id), TTL_THRESHOLD, TTL_EXTEND_TO);
        env.events().publish((symbol_short!("executed"),), settlement_id);
        Ok(())
    }

    /// Permissionless. Read-only and not pause-gated. Returns the settlement,
    /// or `NotFound` for an unknown id.
    pub fn get_settlement(env: Env, settlement_id: u64) -> Result<Settlement, TreasuryError> {
        env.storage()
            .persistent()
            .get(&DataKey::Settlement(settlement_id))
            .ok_or(TreasuryError::NotFound)
    }

    /// Admin-only. Blocks `propose_settlement`, `approve_settlement` and
    /// `execute_settlement` until unpaused. Reads keep working while paused.
    pub fn pause(env: Env) -> Result<(), TreasuryError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        Self::require_admin(&env)?;
        env.storage().instance().set(&DataKey::Paused, &true);
        Ok(())
    }

    /// Admin-only. Lifts a pause set by `pause`. Callable while paused.
    pub fn unpause(env: Env) -> Result<(), TreasuryError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        Self::require_admin(&env)?;
        env.storage().instance().set(&DataKey::Paused, &false);
        Ok(())
    }

    /// Permissionless. Read-only. Returns whether the contract is paused.
    pub fn is_paused(env: Env) -> bool {
        env.storage().instance().get(&DataKey::Paused).unwrap_or(false)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    fn setup(env: &Env) -> (TreasuryContractClient<'_>, Address, Vec<Address>, Address) {
        let admin = Address::generate(env);
        let token_admin = Address::generate(env);
        let sac = env.register_stellar_asset_contract_v2(token_admin);
        let token_id = sac.address();
        let signers = vec![
            env,
            Address::generate(env),
            Address::generate(env),
            Address::generate(env),
        ];
        let contract_id = env.register(TreasuryContract, ());
        let client = TreasuryContractClient::new(env, &contract_id);
        client.initialize(&admin, &token_id, &signers, &2u32);
        // Fund the treasury itself so execute_settlement's real transfer has
        // something to pay out. Existing tests below only ever assert on
        // Settlement.status, not balances, so a flat generous funding
        // amount here keeps them passing unchanged now that
        // execute_settlement actually moves funds instead of being a
        // no-op status flip.
        token::StellarAssetClient::new(env, &token_id).mint(&contract_id, &100_000_0000i128);
        (client, admin, signers, token_id)
    }

    #[test]
    fn threshold_not_met_below_two_signatures() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, signers, _token) = setup(&env);
        let merchant = Address::generate(&env);

        let id = client.propose_settlement(&signers.get(0).unwrap(), &merchant, &1_000_0000i128);
        let res = client.try_execute_settlement(&signers.get(0).unwrap(), &id);
        assert_eq!(res, Err(Ok(TreasuryError::ThresholdNotMet)));
    }

    #[test]
    fn executes_once_threshold_met() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, signers, _token) = setup(&env);
        let merchant = Address::generate(&env);

        let id = client.propose_settlement(&signers.get(0).unwrap(), &merchant, &1_000_0000i128);
        client.approve_settlement(&signers.get(1).unwrap(), &id);
        client.execute_settlement(&signers.get(0).unwrap(), &id);
        let settlement = client.get_settlement(&id);
        assert_eq!(settlement.status, SettlementStatus::Executed);
    }

    #[test]
    fn non_signer_cannot_approve() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, signers, _token) = setup(&env);
        let merchant = Address::generate(&env);
        let outsider = Address::generate(&env);

        let id = client.propose_settlement(&signers.get(0).unwrap(), &merchant, &1_000_0000i128);
        let res = client.try_approve_settlement(&outsider, &id);
        assert_eq!(res, Err(Ok(TreasuryError::NotSigner)));
    }

    #[test]
    fn double_approval_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, signers, _token) = setup(&env);
        let merchant = Address::generate(&env);

        let id = client.propose_settlement(&signers.get(0).unwrap(), &merchant, &1_000_0000i128);
        let res = client.try_approve_settlement(&signers.get(0).unwrap(), &id);
        assert_eq!(res, Err(Ok(TreasuryError::AlreadyApproved)));
    }

    #[test]
    fn double_execution_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, signers, _token) = setup(&env);
        let merchant = Address::generate(&env);

        let id = client.propose_settlement(&signers.get(0).unwrap(), &merchant, &1_000_0000i128);
        client.approve_settlement(&signers.get(1).unwrap(), &id);
        client.execute_settlement(&signers.get(0).unwrap(), &id);
        let res = client.try_execute_settlement(&signers.get(0).unwrap(), &id);
        assert_eq!(res, Err(Ok(TreasuryError::NotPending)));
    }

    #[test]
    fn invalid_threshold_rejected_at_init() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token = Address::generate(&env);
        let signers = vec![&env, Address::generate(&env)];
        let contract_id = env.register(TreasuryContract, ());
        let client = TreasuryContractClient::new(&env, &contract_id);
        let res = client.try_initialize(&admin, &token, &signers, &5u32);
        assert_eq!(res, Err(Ok(TreasuryError::InvalidThreshold)));
    }

    #[test]
    fn zero_threshold_rejected_at_init() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token = Address::generate(&env);
        let signers = vec![&env, Address::generate(&env)];
        let contract_id = env.register(TreasuryContract, ());
        let client = TreasuryContractClient::new(&env, &contract_id);
        let res = client.try_initialize(&admin, &token, &signers, &0u32);
        assert_eq!(res, Err(Ok(TreasuryError::InvalidThreshold)));
    }

    #[test]
    fn execute_settlement_actually_transfers_the_real_token_balance() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, signers, token_id) = setup(&env);
        let merchant = Address::generate(&env);
        let token_client = token::TokenClient::new(&env, &token_id);

        let contract_balance_before = token_client.balance(&client.address);
        let merchant_balance_before = token_client.balance(&merchant);
        assert_eq!(merchant_balance_before, 0);

        let id = client.propose_settlement(&signers.get(0).unwrap(), &merchant, &1_000_0000i128);
        client.approve_settlement(&signers.get(1).unwrap(), &id);
        client.execute_settlement(&signers.get(0).unwrap(), &id);

        // The actual gap this whole fix closes: before it, execute_settlement
        // only flipped a status flag and neither balance below would have
        // moved at all.
        assert_eq!(token_client.balance(&merchant), 1_000_0000i128);
        assert_eq!(token_client.balance(&client.address), contract_balance_before - 1_000_0000i128);
    }

    #[test]
    fn execute_settlement_traps_and_settlement_stays_pending_if_treasury_is_short() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let sac = env.register_stellar_asset_contract_v2(token_admin);
        let token_id = sac.address();
        let signers = vec![
            &env,
            Address::generate(&env),
            Address::generate(&env),
            Address::generate(&env),
        ];
        let contract_id = env.register(TreasuryContract, ());
        let client = TreasuryContractClient::new(&env, &contract_id);
        client.initialize(&admin, &token_id, &signers, &2u32);
        // Deliberately NOT funded — this is the one test in this module
        // that doesn't use setup()'s generous mint, specifically to prove
        // an underfunded treasury can't silently mark a settlement
        // Executed without the money actually moving.
        let merchant = Address::generate(&env);

        let id = client.propose_settlement(&signers.get(0).unwrap(), &merchant, &1_000_0000i128);
        client.approve_settlement(&signers.get(1).unwrap(), &id);
        let res = client.try_execute_settlement(&signers.get(0).unwrap(), &id);
        assert!(res.is_err(), "an underfunded transfer should trap, not silently succeed");

        let settlement = client.get_settlement(&id);
        assert_eq!(settlement.status, SettlementStatus::Pending, "a reverted execute must leave the settlement Pending, not Executed");
    }

    #[test]
    fn approve_settlement_event_records_approving_signer() {
        use soroban_sdk::testutils::Events as _;
        use soroban_sdk::{IntoVal, Val};
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, signers, _token) = setup(&env);
        let merchant = Address::generate(&env);

        let id = client.propose_settlement(&signers.get(0).unwrap(), &merchant, &1_000_0000i128);
        let approver = signers.get(1).unwrap();
        client.approve_settlement(&approver, &id);

        let topics: soroban_sdk::Vec<Val> = (symbol_short!("approved"), approver.clone()).into_val(&env);
        let data: Val = id.into_val(&env);
        assert_eq!(env.events().all(), vec![&env, (client.address.clone(), topics, data)]);
    }
}
