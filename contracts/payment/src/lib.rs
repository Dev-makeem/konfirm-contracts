#![no_std]

use konfirm_common::{require_admin, require_not_paused, set_paused, CommonError};
use soroban_sdk::{contract, contracterror, contractimpl, contracttype, symbol_short, Address, BytesN, Env};

// This contract is an attestation layer, not an escrow. Funds for a checkout
// payment move directly payer -> merchant muxed address via a classic
// Stellar payment operation; this contract never holds them. record_payment
// is called by the reconciler only *after* it has independently observed and
// verified that transfer on Horizon — the on-chain record exists because the
// payment already happened, never before.

const TTL_THRESHOLD: u32 = 100;
const TTL_EXTEND_TO: u32 = 5_000_000;

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct PaymentRecord {
    pub merchant: Address,
    pub payer: Address,
    pub link_id: u64,
    pub amount: i128,
    pub tx_hash: BytesN<32>,
    pub refunded: bool,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Paused,
    NextId,
    Payment(u64),
    Voided(u64),
    ByTxHash(BytesN<32>),
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
        env.events().publish((symbol_short!("init"),), admin);
        Ok(())
    }

    // Requires the stored admin's auth; `NotInitialized` before `initialize`.
    fn require_admin(env: &Env) -> Result<(), PaymentError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(PaymentError::NotInitialized)?;
        admin.require_auth();
        Ok(())
    }

    // Fails with `Paused` while the contract is paused.
    fn require_not_paused(env: &Env) -> Result<(), PaymentError> {
        let paused: bool = env.storage().instance().get(&DataKey::Paused).unwrap_or(false);
        if paused {
            return Err(PaymentError::Paused);
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
        env.events().publish((symbol_short!("recorded"), merchant), (id, link_id, amount));
        Ok(id)
    }

    /// Admin-only, pause-gated. Flags an existing payment as refunded.
    /// Bookkeeping only: the refund transfer itself is not made by this
    /// contract. Fails with `NotFound` for an unknown id, `AlreadyRefunded` if
    /// already flagged, `Voided` if the payment was voided, and `Paused` while
    /// paused.
    pub fn mark_refunded(env: Env, payment_id: u64) -> Result<(), PaymentError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        Self::require_admin(&env)?;
        Self::require_not_paused(&env)?;
        let mut record: PaymentRecord = env
            .storage()
            .persistent()
            .get(&DataKey::Payment(payment_id))
            .ok_or(PaymentError::NotFound)?;
        if record.refunded {
            return Err(PaymentError::AlreadyRefunded);
        }
        if Self::is_voided_flag(&env, payment_id) {
            return Err(PaymentError::Voided);
        }
        record.refunded = true;
        env.storage().persistent().set(&DataKey::Payment(payment_id), &record);
        env.storage().persistent().extend_ttl(&DataKey::Payment(payment_id), TTL_THRESHOLD, TTL_EXTEND_TO);
        env.events().publish((symbol_short!("refunded"),), payment_id);
        Ok(())
    }

    /// Admin-only, pause-gated. Marks a record as mis-recorded: no money moved,
    /// so nothing is reversed on the ledger. The record itself is never
    /// rewritten; the voided flag sits alongside it and consumers must check
    /// `is_voided` before trusting it. Fails with `NotFound`, `AlreadyVoided`,
    /// `AlreadyRefunded`, or `Paused` while paused.
    pub fn void_payment(env: Env, payment_id: u64) -> Result<(), PaymentError> {
        Self::require_admin(&env)?;
        Self::require_not_paused(&env)?;
        let record: PaymentRecord = env
            .storage()
            .persistent()
            .get(&DataKey::Payment(payment_id))
            .ok_or(PaymentError::NotFound)?;
        if Self::is_voided_flag(&env, payment_id) {
            return Err(PaymentError::AlreadyVoided);
        }
        if record.refunded {
            return Err(PaymentError::AlreadyRefunded);
        }
        env.storage().persistent().set(&DataKey::Voided(payment_id), &true);
        env.events().publish((symbol_short!("voided"),), payment_id);
        Ok(())
    }

    // Raw voided flag; `false` for unknown ids. Callers check existence first.
    fn is_voided_flag(env: &Env, payment_id: u64) -> bool {
        env.storage().persistent().get(&DataKey::Voided(payment_id)).unwrap_or(false)
    }

    /// Permissionless. Read-only and not pause-gated. Returns whether the
    /// payment was voided, or `NotFound` for an unknown id.
    pub fn is_voided(env: Env, payment_id: u64) -> Result<bool, PaymentError> {
        if !env.storage().persistent().has(&DataKey::Payment(payment_id)) {
            return Err(PaymentError::NotFound);
        }
        Ok(Self::is_voided_flag(&env, payment_id))
    }

    /// Permissionless. Read-only and not pause-gated. Returns the stored
    /// record, or `NotFound` for an unknown id. Does not reflect `is_voided`.
    pub fn get_payment(env: Env, payment_id: u64) -> Result<PaymentRecord, PaymentError> {
        env.storage()
            .persistent()
            .get(&DataKey::Payment(payment_id))
            .ok_or(PaymentError::NotFound)
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
        Self::require_admin(&env)?;
        env.storage().instance().set(&DataKey::Paused, &false);
        env.events().publish((symbol_short!("unpaused"),), ());
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
    use soroban_sdk::testutils::{Address as _, MockAuth, MockAuthInvoke};
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
