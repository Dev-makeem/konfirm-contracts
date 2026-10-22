#![no_std]

use konfirm_common::{require_admin, require_not_paused, set_paused, CommonError};
use soroban_sdk::{contract, contracterror, contractevent, contractimpl, contracttype, Address, Env};

const TTL_THRESHOLD: u32 = 100;
const TTL_EXTEND_TO: u32 = 5_000_000;

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Paused,
    Status(Address),
}

// An address is either blocked, explicitly cleared (audit record), or has no
// record at all. The last state is represented by the absence of the key.
#[contracttype]
#[derive(Clone, Copy, PartialEq, Eq)]
enum ComplianceStatus {
    Blocked,
    Cleared,
}

#[contractevent]
#[derive(Clone)]
pub struct InitEvent {
    #[topic]
    pub admin: Address,
}

#[contractevent]
#[derive(Clone)]
pub struct BlockedEvent {
    #[topic]
    pub addr: Address,
}

#[contractevent]
#[derive(Clone)]
pub struct AllowedEvent {
    #[topic]
    pub addr: Address,
}

#[contractevent]
#[derive(Clone)]
pub struct ClearedEvent {
    #[topic]
    pub addr: Address,
}

#[contractevent]
#[derive(Clone)]
pub struct AdminChangedEvent {
    #[topic]
    pub new_admin: Address,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ComplianceError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    /// Returned by `set_admin` when `current_admin` does not match the stored
    /// admin. Admin gates elsewhere use `require_auth()`, which traps at the
    /// host before this can be produced. Code 3 stays reserved for ABI stability.
    Unauthorized = 3,
    Paused = 4,
}

impl From<CommonError> for ComplianceError {
    fn from(err: CommonError) -> Self {
        match err {
            CommonError::NotInitialized => ComplianceError::NotInitialized,
            CommonError::Paused => ComplianceError::Paused,
        }
    }
}

#[contract]
pub struct ComplianceContract;

// Default-allow, deny-list model: an address is screened out only if it has
// been explicitly blocked. This matches how sanctions screening actually
// works in practice (absence from a list means cleared) rather than
// requiring every legitimate address to be pre-enrolled.
#[contractimpl]
impl ComplianceContract {
    /// One-time setup. Requires auth from `admin` and rejects a second call
    /// with `AlreadyInitialized`; also seeds `Paused = false`.
    pub fn initialize(env: Env, admin: Address) -> Result<(), ComplianceError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(ComplianceError::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Paused, &false);
        InitEvent { admin }.publish(&env);
        Ok(())
    }

    /// Admin-only (auth via `require_admin`). Fails with `NotInitialized` if
    /// the contract has no admin set.
    fn require_admin(env: &Env) -> Result<(), ComplianceError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(ComplianceError::NotInitialized)?;
        admin.require_auth();
        Ok(())
    }

    /// Returns `Paused` if the contract is paused; used to gate mutations.
    fn require_not_paused(env: &Env) -> Result<(), ComplianceError> {
        let paused: bool = env.storage().instance().get(&DataKey::Paused).unwrap_or(false);
        if paused {
            return Err(ComplianceError::Paused);
        }
        Ok(())
    }

    /// Permissionless. Read-only, and deliberately callable even while paused — pausing the
    /// contract must never be able to brick checkout by blocking the one
    /// query the payment-preparation path depends on.
    ///
    /// Fails closed on a contract that was never initialized: with no admin set, screening
    /// is not running, so nothing is cleared (unlike the paused case, which still screens).
    pub fn is_allowed(env: Env, addr: Address) -> bool {
        if !env.storage().instance().has(&DataKey::Admin) {
            return false;
        }
        let key = DataKey::Status(addr);
        if env.storage().persistent().get(&key) == Some(ComplianceStatus::Blocked) {
            // Keeps a live block from archiving, which would silently flip the
            // address back to "allowed" without anyone clearing it.
            env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND_TO);
            return false;
        }
        true
    }

    /// Admin-only and pause-sensitive. Records `Blocked` for `addr` so
    /// `is_allowed` returns false. The single `Status` write is the only
    /// state change; there is no separate `Allowed` flag to keep in sync.
    pub fn block_address(env: Env, addr: Address) -> Result<(), ComplianceError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        Self::require_admin(&env)?;
        Self::require_not_paused(&env)?;
        let key = DataKey::Status(addr.clone());
        env.storage().persistent().set(&key, &ComplianceStatus::Blocked);
        env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND_TO);
        BlockedEvent { addr }.publish(&env);
        Ok(())
    }

    /// Explicitly clears a block (e.g. after manual review) and leaves an
    /// audit record distinct from an address that was simply never flagged.
    pub fn allow_address(env: Env, addr: Address) -> Result<(), ComplianceError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        Self::require_admin(&env)?;
        Self::require_not_paused(&env)?;
        let key = DataKey::Status(addr.clone());
        env.storage().persistent().set(&key, &ComplianceStatus::Cleared);
        env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND_TO);
        AllowedEvent { addr }.publish(&env);
        Ok(())
    }

    /// Admin-only and pause-sensitive. Removes any `Status` record for `addr`,
    /// restoring the default-allow state (no record at all).
    pub fn clear_address(env: Env, addr: Address) -> Result<(), ComplianceError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        Self::require_admin(&env)?;
        Self::require_not_paused(&env)?;
        env.storage().persistent().remove(&DataKey::Status(addr.clone()));
        ClearedEvent { addr }.publish(&env);
        Ok(())
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
    pub fn set_admin(env: Env, current_admin: Address, new_admin: Address) -> Result<(), ComplianceError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(ComplianceError::NotInitialized)?;
        if current_admin != admin {
            return Err(ComplianceError::Unauthorized);
        }
        current_admin.require_auth();
        new_admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.events().publish((symbol_short!("admin"), current_admin), new_admin);
        Ok(())
    }

    /// Admin-only. Sets `Paused = true`, which makes `block_address`,
    /// `allow_address`, and `clear_address` return `Paused`. Reads
    /// (`is_allowed`, `is_paused`) remain available.
    pub fn pause(env: Env) -> Result<(), ComplianceError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        Self::require_admin(&env)?;
        env.storage().instance().set(&DataKey::Paused, &true);
        env.events().publish((symbol_short!("paused"),), ());
        Ok(())
    }

    /// Admin-only. Clears `Paused`, re-enabling the pause-gated mutations.
    pub fn unpause(env: Env) -> Result<(), ComplianceError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        Self::require_admin(&env)?;
        env.storage().instance().set(&DataKey::Paused, &false);
        env.events().publish((symbol_short!("unpaused"),), ());
        Ok(())
    }

    /// Permissionless. Read-only.
    pub fn is_paused(env: Env) -> bool {
        env.storage().instance().get(&DataKey::Paused).unwrap_or(false)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::{Address as _, MockAuth, MockAuthInvoke};
    use soroban_sdk::IntoVal;

    fn setup(env: &Env) -> (ComplianceContractClient<'_>, Address) {
        let admin = Address::generate(env);
        le

    #[test]
    fn clear_restores_default_allow() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin) = setup(&env);
        let addr = Address::generate(&env);

        client.block_address(&addr);
        assert!(!client.is_allowed(&addr));
        client.allow_address(&addr);
        assert!(client.is_allowed(&addr));
        client.clear_address(&addr);
        assert!(client.is_allowed(&ad

        client.block_address(&addr);
        client.pause();
        // must not panic / must not require unpausing to read
        assert!(!client.is_allowed(&addr));
    }

    #[test]
    fn mutations_rejected_while_paused() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin) = setup(&env);
        let addr = Address::generate(&env);

        client.pause();
        let res = client.try_block_address(&addr);
        assert_eq!(res, Err(Ok(ComplianceError::Paused)));
        let res = client.try_allow_address(&addr);
        assert_eq!(res, Err(Ok(ComplianceError::Paused)));
        let res = client.try_clear_address(&addr);
        assert_eq!(res, Err(Ok(ComplianceError::Paused)));
    }

    #[test]
    fn double_initialize_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin) = setup(&env);
        let res = client.try_initialize(&admin);
        assert_eq!(res, Err(Ok(ComplianceError::AlreadyInitialized)));
    }

    #[test]
    fn non_admin_signer_cannot_call_admin_function() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin) = setup(&env);
        let non_admin = Address::generate(&env);
        let addr = Address::generate(&env);

        // Only a non-admin address authorizes the call; the admin's
        // require_auth() must therefore fail.
        env.mock_auths(&[MockAuth {
            address: &non_admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "block_address",
                args: (addr.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        assert!(client.try_block_address(&addr).is_err());
        assert!(client.is_allowed(&addr));
    }

    #[test]
    fn set_admin_event_records_outgoing_and_incoming_admin() {
        use soroban_sdk::testutils::Events as _;
        use soroban_sdk::{vec, Val};
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
