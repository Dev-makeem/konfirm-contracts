#![no_std]

use konfirm_common::{require_admin, require_not_paused, set_paused, CommonError};
use soroban_sdk::{contract, contracterror, contractevent, contractimpl, contracttype, symbol_short, Address, BytesN, Env};

// This contract is an attestation layer, not an escrow. Funds for a checkout
// payment move directly payer -> merchant muxed address via a classic
// Stellar payment operation; this contract never holds them. record_payment
// is called by the reconciler only *after* it has independently observed and
// verified that transfer on Horizon — the on-chain record exists because the
// payment already happened, never before.

const TTL_THRESHOLD: u32 = 100;
const TTL_EXTEND_TO: u32 = 5_000_000;

// Minimal cross-contract client for the compliance contract's `is_allowed`.
// The compliance contract address is supplied by the admin at initialize time
// so this contract can consult the blocklist before recording a payment.
#[contractclient(name = "ComplianceClient")]
pub trait ComplianceInterface {
    fn is_allowed(env: Env, address: Address) -> bool;
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct PaymentRecord {
    /// Address that received the funds.
    pub merchant: Address,
    /// Address the funds came from.
    pub payer: Address,
    /// Off-chain payment link this payment settles.
    pub link_id: u64,
    /// Transferred amount in the asset's base units; always `> 0`.
    pub amount: i128,
    /// Hash of the Stellar transaction that moved the funds. Each hash can be
    /// recorded once; used to dedupe attestations.
    pub tx_hash: BytesN<32>,
    /// Set by `mark_refunded` once the refund has been flagged. Bookkeeping
    /// only — the refund transfer itself is not made by this contract.
    pub refunded: bool,
}

#[contractevent]
#[derive(Clone, Debug, PartialEq)]
pub struct InitEvent {
    #[topic]
    pub admin: Address,
}

#[contractevent]
#[derive(Clone, Debug, PartialEq)]
pub struct PaymentRecordedEvent {
    #[topic]
    pub merchant: Address,
    pub id: u64,
    pub link_id: u64,
    pub amount: i128,
}

#[contractevent]
#[derive(Clone, Debug, PartialEq)]
pub struct PaymentRefundedEvent {
    pub payment_id: u64,
}

#[contractevent]
#[derive(Clone, Debug, PartialEq)]
pub struct PaymentVoidedEvent {
    pub payment_id: u64,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Paused,
    NextId,
    Payment(u64),
    Voided(u64),
    Refunded(u64),
    ByTxHash(BytesN<32>),
    Compliance,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum PaymentError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    /// Never returned: admin gates use `require_auth()`, which traps at the host before this can be produced. Code 3 stays reserved for ABI stability.
    Unauthorized = 3,
    Paused = 4,
    NotFound = 5,
    InvalidAmount = 6,
    AlreadyRefunded = 7,
    AlreadyVoided = 8,
    Voided = 9,
    DuplicateTxHash = 10,
    ComplianceBlocked = 11,
}

#[contract]
pub struct PaymentContract;

#[contractimpl]
impl PaymentContract {
    /// One-time setup. Sets the admin, starts unpaused, and sets the first
    /// payment id to 1. Requires the admin's auth; not pause-gated (there is
    /// no pause state yet). Fails with `AlreadyInitialized` on a second call.
    /// See `docs/ERRORS.md`.
    pub fn initialize(env: Env, admin: Address) -> Result<(), PaymentError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(PaymentError::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Paused, &false);
        env.storage().instance().set(&DataKey::NextId, &1u64);
        InitEvent { admin: admin.clone() }.publish(&env);
        Ok(())
    }

    /// Admin-only. Points this contract at the compliance contract consulted
    /// by `record_payment`. Fails with `NotInitialized` before `initialize`.
    pub fn set_compliance(env: Env, compliance: Address) -> Result<(), PaymentError> {
        Self::require_admin(&env)?;
        env.storage().instance().set(&DataKey::Compliance, &compliance);
        env.events().publish((symbol_short!("compliance"),), compliance);
        Ok(())
    }

    // Requires the stored admin's auth; `NotInitialized` before `initialize`.
    fn require_admin(env: &Env) -> Result<Address, PaymentError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(PaymentError::NotInitialized)?;
        admin.require_auth();
        Ok(admin)
    }

    // Fails with `Paused` while the contract is paused.
    fn require_not_paused(env: &Env) -> Result<(), PaymentError> {
        let paused: bool = env.storage().instance().get(&DataKey::Paused).unwrap_or(false);
        if paused {
            return Err(PaymentError::Paused);
        }
        Ok(())
    }

    // Consults the configured compliance contract for both parties. If no
    // compliance contract is configured, enforcement is skipped (advisory
    // mode) so existing deployments keep working until the admin opts in.
    fn require_allowed(env: &Env, merchant: &Address, payer: &Address) -> Result<(), PaymentError> {
        let compliance: Address = match env.storage().instance().get(&DataKey::Compliance) {
            Some(addr) => addr,
            None => return Ok(()),
        };
        let client = ComplianceClient::new(env, &compliance);
        if !client.is_allowed(&merchant.clone()) || !client.is_allowed(&payer.clone()) {
            return Err(PaymentError::ComplianceBlocked);
        }
        Ok(())
    }

    /// Admin-only, pause-gated. Writes an attestation that a payer -> merchant
    /// transfer already happened, and returns the new payment id. Does not
    /// move funds. The reconciler calls this only after verifying the transfer
    /// on Horizon.
    ///
    /// - `merchant`: the address that received the funds.
    /// - `payer`: the address the funds came from.
    /// - `link_id`: the off-chain payment link this payment settles.
    /// - `amount`: the transferred amount in the asset's base units; must be `> 0`.
    /// - `tx_hash`: hash of the Stellar transaction that moved the funds. Each
    ///   hash can be recorded once.
    ///
    /// Fails with `InvalidAmount` if `amount <= 0`, `DuplicateTxHash` if
    /// `tx_hash` was already recorded, and `Paused` while paused.
    ///
    /// Signature note (issue #47): the five flat scalar params are kept
    /// deliberately rather than collapsed into an input struct. The only
    /// caller is konfirm-backend's reconciler, which invokes this through
    /// generated client bindings; flat scalars are also the more ergonomic
    /// shape for Soroban CLI invocation. A struct param would add nesting
    /// with no practical benefit, so this is a recorded decision — do not
    /// re-raise without a concrete caller that would gain from it.
    pub fn record_payment(
        env: Env,
        merchant: Address,
        payer: Address,
        link_id: u64,
        amount: i128,
        tx_hash: BytesN<32>,
    ) -> Result<u64, PaymentError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        Self::require_admin(&env)?;
        Self::require_not_paused(&env)?;
        if amount <= 0 {
            return Err(PaymentError::InvalidAmount);
        }
        Self::require_allowed(&env, &merchant, &payer)?;
        if env.storage().persistent().has(&DataKey::ByTxHash(tx_hash.clone())) {
            return Err(PaymentError::DuplicateTxHash);
        }

        let id: u64 = env.storage().instance().get(&DataKey::NextId).unwrap_or(1);
        env.storage().instance().set(&DataKey::NextId, &(id + 1));

        let record = PaymentRecord {
            merchant: merchant.clone(),
            payer,
            link_id,
            amount,
            tx_hash: tx_hash.clone(),
            refunded: false,
        };
        env.storage().persistent().set(&DataKey::Payment(id), &record);
        env.storage().persistent().extend_ttl(&DataKey::Payment(id), TTL_THRESHOLD, TTL_EXTEND_TO);
        env.storage().persistent().set(&DataKey::ByTxHash(tx_hash.clone()), &id);
        env.storage().persistent().extend_ttl(&DataKey::ByTxHash(tx_hash), TTL_THRESHOLD, TTL_EXTEND_TO);
        PaymentRecordedEvent { merchant: merchant.clone(), id, link_id, amount }.publish(&env);
        Ok(id)
    }

    /// Admin-only, pause-gated. Flags an existing payment as refunded.
    /// Bookkeeping only: the refund transfer itself is not made by this
    /// contract. Fails with `NotFound` for an unknown id, `AlreadyRefunded` if
    /// already flagged, `Voided` if the payment was voided, and `Paused` while
    /// paused.
    ///
    /// The refund flag lives under its own key (`DataKey::Refunded`) so this
    /// only writes the changed bit instead of re-serializing the whole
    /// `PaymentRecord`.
    pub fn mark_refunded(env: Env, payment_id: u64) -> Result<(), PaymentError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        let admin = Self::require_admin(&env)?;
        Self::require_not_paused(&env)?;
        if !env.storage().persistent().has(&DataKey::Payment(payment_id)) {
            return Err(PaymentError::NotFound);
        }
        if Self::is_refunded_flag(&env, payment_id) {
            return Err(PaymentError::AlreadyRefunded);
        }
        if Self::is_voided_flag(&env, payment_id) {
            return Err(PaymentError::Voided);
        }
        record.refunded = true;
        env.storage().persistent().set(&DataKey::Payment(payment_id), &record);
        env.storage().persistent().extend_ttl(&DataKey::Payment(payment_id), TTL_THRESHOLD, TTL_EXTEND_TO);
        env.events().publish((symbol_short!("refunded"), admin), (payment_id, record.amount));
        Ok(())
    }

    /// Admin-only, pause-gated. Marks a record as mis-recorded: no money moved,
    /// so nothing is reversed on the ledger. The record itself is never
    /// rewritten; the voided flag sits alongside it and consumers must check
    /// `is_voided` before trusting it. Fails with `NotFound`, `AlreadyVoided`,
    /// `AlreadyRefunded`, or `Paused` while paused.
    pub fn void_payment(env: Env, payment_id: u64) -> Result<(), PaymentError> {
        let admin = Self::require_admin(&env)?;
        Self::require_not_paused(&env)?;
        if !env.storage().persistent().has(&DataKey::Payment(payment_id)) {
            return Err(PaymentError::NotFound);
        }
        if Self::is_voided_flag(&env, payment_id) {
            return Err(PaymentError::AlreadyVoided);
        }
        if Self::is_refunded_flag(&env, payment_id) {
            return Err(PaymentError::AlreadyRefunded);
        }
        env.storage().persistent().set(&DataKey::Voided(payment_id), &true);
        env.events().publish((symbol_short!("voided"), admin), (payment_id, record.amount));
        Ok(())
    }

    // Raw voided flag; `false` for unknown ids. Callers check existence first.
    fn is_voided_flag(env: &Env, payment_id: u64) -> bool {
        env.storage().persistent().get(&DataKey::Voided(payment_id)).unwrap_or(false)
    }

    // Raw refunded flag; `false` for unknown ids. Callers check existence first.
    fn is_refunded_flag(env: &Env, payment_id: u64) -> bool {
        env.storage().persistent().get(&DataKey::Refunded(payment_id)).unwrap_or(false)
    }

    /// Rotates the admin key. Requires auth from both the current admin and
    /// the incoming one, so a handoff can't strand the contract on an address
    /// nobody holds. Deliberately not pause-gated: rotating away from a
    /// suspected key must still work during an incident.
    ///
    /// This does NOT defend against a leaked current key on its own — that key
    /// can still rotate to an attacker-held address. Quorum-based control
    /// (treasury's 2-of-3 model) or a multisig deployer account is what closes
    /// that gap; see docs/KEYS.md.
    pub fn set_admin(env: Env, current_admin: Address, new_admin: Address) -> Result<(), PaymentError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(PaymentError::NotInitialized)?;
        if current_admin != admin {
            return Err(PaymentError::Unauthorized);
        }
        current_admin.require_auth();
        new_admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.events().publish((symbol_short!("admin"), current_admin), new_admin);
        Ok(())
    }

    /// Admin-only. Blocks `record_payment`, `mark_refunded` and `void_payment`
    /// until unpaused. Reads and `set_admin` keep working while paused.
    pub fn pause(env: Env) -> Result<(), PaymentError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        Self::require_admin(&env)?;
        env.storage().instance().set(&DataKey::Paused, &true);
        Ok(())
    }

    /// Admin-only. Lifts a pause set by `pause`. Callable while paused.
    pub fn unpause(env: Env) -> Result<(), PaymentError> {
        let admin = Self::require_admin(&env)?;
        env.storage().instance().set(&DataKey::Paused, &false);
        env.events().publish((symbol_short!("unpaused"), admin), ());
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
    use soroban_sdk::testutils::{Address as _, Events as _, MockAuth, MockAuthInvoke};
    use soroban_sdk::IntoVal;

    fn setup(env: &Env) -> (PaymentContractClient<'_>, Address) {
        let admin = Address::generate(env);
        let contract_id = env.register(PaymentContract, ());
        let client = PaymentContractClient::new(env, &contract_id);
        client.initialize(&admin);
        (client, admin)
    }

    #[test]
    fn record_and_fetch_payment() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin) = setup(&env);
        let merchant = Address::generate(&env);
        let payer = Address::generate(&env);
        let tx_hash = BytesN::from_array(&env, &[7u8; 32]);

        let id = client.record_payment(&merchant, &payer, &42u64, &1_000_0000i128, &tx_hash);
        let rec = client.get_payment(&id);
        assert_eq!(rec.merchant, merchant);
        assert_eq!(rec.link_id, 42u64);
        assert_eq!(rec.amount, 1_000_0000i128);
        assert!(!rec.refunded);
    }

    #[test]
    fn zero_amount_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin) = setup(&env);
        let merchant = Address::generate(&env);
        let payer = Address::generate(&env);
        let tx_hash = BytesN::from_array(&env, &[0u8; 32]);

        let res = client.try_record_payment(&merchant, &payer, &1u64, &0i128, &tx_hash);
        assert_eq!(res, Err(Ok(PaymentError::InvalidAmount)));
    }

    #[test]
    fn double_refund_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin) = setup(&env);
        let merchant = Address::generate(&env);
        let payer = Address::generate(&env);
        let tx_hash = BytesN::from_array(&env, &[1u8; 32]);

        let id = client.record_payment(&merchant, &payer, &1u64, &500_0000i128, &tx_hash);
        client.mark_refunded(&id);
        let res = client.try_mark_refunded(&id);
        assert_eq!(res, Err(Ok(PaymentError::AlreadyRefunded)));
    }

    #[test]
    fn unknown_payment_not_found() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin) = setup(&env);
        let res = client.try_get_payment(&999u64);
        assert_eq!(res, Err(Ok(PaymentError::NotFound)));
    }

    #[test]
    fn paused_blocks_recording() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin) = setup(&env);
        let merchant = Address::generate(&env);
        let payer = Address::generate(&env);
        let tx_hash = BytesN::from_array(&env, &[2u8; 32]);

        let id = client.record_payment(&merchant, &payer, &1u64, &100_0000i128, &tx_hash);
        client.pause();
        let res = client.try_record_payment(&merchant, &payer, &2u64, &100_0000i128, &tx_hash);
        assert_eq!(res, Err(Ok(PaymentError::Paused)));
        let res = client.try_mark_refunded(&id);
        assert_eq!(res, Err(Ok(PaymentError::Paused)));
    }

    #[test]
    fn non_admin_signer_cannot_call_admin_function() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin) = setup(&env);
        let non_admin = Address::generate(&env);
        let merchant = Address::generate(&env);
        let payer = Address::generate(&env);
        let tx_hash = BytesN::from_array(&env, &[3u8; 32]);

        // Only a non-admin address authorizes the call; the admin's
        // require_auth() must therefore fail.
        env.mock_auths(&[MockAuth {
            address: &non_admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "record_payment",
                args: (merchant.clone(), payer.clone(), 1u64, 100_0000i128, tx_hash.clone())
                    .into_val(&env),
                sub_invokes: &[],
            },
        }]);
        let res = client.try_record_payment(&merchant, &payer, &1u64, &100_0000i128, &tx_hash);
        assert!(res.is_err());
        assert_eq!(client.try_get_payment(&1u64), Err(Ok(PaymentError::NotFound)));
    }

    #[test]
    fn set_admin_event_records_outgoing_and_incoming_admin() {
        use soroban_sdk::testutils::Events as _;
        use soroban_sdk::{vec, IntoVal, Val};
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin) = setup(&env);
        let new_admin = Address::generate(&env);

        client.set_admin(&admin, &new_admin);

        let topics: soroban_sdk::Vec<Val> = (symbol_short!("admin"), admin.clone()).into_val(&env);
        let data: Val = new_admin.clone().into_val(&env);
        assert_eq!(env.events().all(), vec![&env, (client.address.clone(), topics, data)]);
    }
}
