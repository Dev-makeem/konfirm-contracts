#![no_std]

use konfirm_common::{require_not_paused, CommonError};
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, token, Address, Bytes,
    BytesN, Env,
};

// One escrow-backed unidirectional payment channel per (payer, payee, token).
// Off-chain, the payer signs monotonically-increasing cumulative-amount
// messages; anyone holding the latest one can call checkpoint() to claim it —
// deliberately not gated to an admin key, so the payee can always recover
// funds they can prove they're owed even if Konfirm's relay disappears.
//
// checkpoint() is the one mutating entry point that is never pausable: pause
// exists to stop *new* exposure (open_channel, top_up), never to freeze a
// withdrawal someone can already prove is owed to them.


//
// checkpoint() is the one mutating entry point that is never pausable: pause
// exists to stop *new* exposure (open_channel, top_up), never to freeze a
// withdrawal someone can already prove is owed to them.

const DOMAIN_TAG: &[u8; 15] = b"KONFIRM_CHAN_V1";
const TTL_THRESHOLD: u32 = 100;
const TTL_EXTEND_TO: u32 = 5_000_000;

// Cap on channels a single payer can have that aren't yet Closed. Each open
// channel is persistent storage the operator pays to keep alive, so this
// bounds how much any one account can make the protocol carry for free.
const MAX_OPEN_CHANNELS_PER_PAYER: u32 = 20;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelStatus {
    Open,
    Closing,
    Closed,
    Held,
}

#[contracttype]
#[derive(Clone)]
pub struct Channel {
    pub payer: Address,
    pub payee: Address,
    pub token: Address,
    pub payer_pubkey: BytesN<32>,
    pub delegated_closer: Option<Address>,
    pub deposited: i128,
    pub claimed: i128,
    pub nonce: u64,
    pub status: ChannelStatus,
    pub closing_at: u64,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Paused,
    ChallengePeriod,
    NextId,
    Channel(u64),
    HeldFrom(u64),
    AllowedToken(Address),
    OpenCount(Address),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ChannelError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    Paused = 4,
    NotFound = 5,
    NotOpen = 6,
    StaleClaim = 7,
    ExceedsDeposit = 8,
    ChallengeNotElapsed = 9,
    NotClosing = 10,
    Held = 11,
    ZeroDeposit = 12,
    TokenNotAllowed = 13,
    TooManyOpenChannels = 14,
    InvalidChallengePeriod = 15,
}

impl From<CommonError> for ChannelError {
    fn from(err: CommonError) -> Self {
        match err {
            CommonError::NotInitialized => ChannelError::NotInitialized,
            CommonError::Paused => ChannelError::Paused,
        }
    }
}

#[contract]
pub struct ChannelContract;

#[contractimpl]
impl ChannelContract {
    pub fn initialize(env: Env, admin: Address, challenge_period_secs: u64) -> Result<(), ChannelError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(ChannelError::AlreadyInitialized);
        }
        // A zero period makes finalize_close succeed in the same ledger as
        // initiate_close: `timestamp() < closing_at + 0` is false the moment
        // closing_at is set. The period is frozen for the life of the instance,
        // so a bad deploy has no recovery path. Reject it before any write.
        if challenge_period_secs == 0 {
            return Err(ChannelError::InvalidChallengePeriod);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Paused, &false);
        env.storage().instance().set(&DataKey::ChallengePeriod, &challenge_period_secs);
        env.storage().instance().set(&DataKey::NextId, &1u64);
        env.events().publish((symbol_short!("init"),), admin);
        Ok(())
    }

    fn require_admin(env: &Env) -> Result<(), ChannelError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(ChannelError::NotInitialized)?;
        admin.require_auth();
        Ok(())
    }

    fn is_token_allowed(env: &Env, token: &Address) -> bool {
        env.storage().persistent().get(&DataKey::AllowedToken(token.clone())).unwrap_or(false)
    }

    fn get_channel(env: &Env, id: u64) -> Result<Channel, ChannelError> {
        env.storage()
            .persistent()
            .get(&DataKey::Channel(id))
            .ok_or(ChannelError::NotFound)
    }

    fn save_channel(env: &Env, id: u64, ch: &Channel) {
        env.storage().persistent().set(&DataKey::Channel(id), ch);
        env.storage().persistent().extend_ttl(&DataKey::Channel(id), TTL_THRESHOLD, TTL_EXTEND_TO);
    }

    fn save_open_count(env: &Env, payer: &Address, count: u32) {
        let key = DataKey::OpenCount(payer.clone());
        env.storage().persistent().set(&key, &count);
        env.storage().persistent().extend_ttl(&key, 100, 5_000_000);
    }

    fn get_open_count(env: &Env, payer: &Address) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::OpenCount(payer.clone()))
            .unwrap_or(0)
    }

    /// The message a payer signs off-chain to authorize a cumulative amount.
    /// Fixed-width, domain-tagged encoding — never string concatenation,
    /// which is how signatures end up ambiguous across field boundaries.
    /// The contract's own address (a 56-char strkey) binds the signature to
    /// this deployment: contract IDs derive from the network, deployer and
    /// salt, so identical code deployed elsewhere yields a different ID.
    fn claim_payload(
        env: &Env,
        contract: &Address,
        channel_id: u64,
        nonce: u64,
        cumulative_amount: i128,
    ) -> Bytes {
        let mut contract_strkey = [0u8; 56];
        contract.to_string().copy_into_slice(&mut contract_strkey);
        let mut payload = Bytes::from_array(env, DOMAIN_TAG);
        payload.append(&Bytes::from_array(env, &contract_strkey));
        payload.append(&Bytes::from_array(env, &channel_id.to_be_bytes()));
        payload.append(&Bytes::from_array(env, &nonce.to_be_bytes()));
        payload.append(&Bytes::from_array(env, &cumulative_amount.to_be_bytes()));
        payload
    }

    pub fn open_channel(
        env: Env,
        payer: Address,
        payee: Address,
        token: Address,
        payer_pubkey: BytesN<32>,
        deposit: i128,
        delegated_closer: Option<Address>,
    ) -> Result<u64, ChannelError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        payer.require_auth();
        require_not_paused(&env, &DataKey::Paused)?;
        if deposit <= 0 {
            return Err(ChannelError::ZeroDeposit);
        }
        if !Self::is_token_allowed(&env, &token) {
            return Err(ChannelError::TokenNotAllowed);
        }
        let open_count = Self::get_open_count(&env, &payer);
        if open_count >= MAX_OPEN_CHANNELS_PER_PAYER {
            return Err(ChannelError::TooManyOpenChannels);
        }

        token::TokenClient::new(&env, &token).transfer(&payer, env.current_contract_address(), &deposit);

        let id: u64 = env.storage().instance().get(&DataKey::NextId).unwrap_or(1);
        env.storage().instance().set(&DataKey::NextId, &(id + 1));

        let channel = Channel {
            payer: payer.clone(),
            payee: payee.clone(),
            token,
            payer_pubkey,
            delegated_closer,
            deposited: deposit,
            claimed: 0,
            nonce: 0,
            status: ChannelStatus::Open,
            closing_at: 0,
        };
        Self::save_channel(&env, id, &channel);
        Self::save_open_count(&env, &payer, open_count + 1);
        env.events().publish((symbol_short!("opened"), payer, payee), (id, deposit));
        Ok(id)
    }

    pub fn top_up(env: Env, payer: Address, channel_id: u64, amount: i128) -> Result<(), ChannelError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        payer.require_auth();
        require_not_paused(&env, &DataKey::Paused)?;
        let mut ch = Self::get_channel(&env, channel_id)?;
        if ch.payer != payer {
            return Err(ChannelError::Unauthorized);
        }
        if ch.status != ChannelStatus::Open {
            return Err(ChannelError::NotOpen);
        }
        if amount <= 0 {
            return Err(ChannelError::ZeroDeposit);
        }
        token::TokenClient::new(&env, &ch.token).transfer(&payer, env.current_contract_address(), &amount);
        ch.deposited += amount;
        Self::save_channel(&env, channel_id, &ch);
        env.events().publish((symbol_short!("topup"),), (channel_id, amount, ch.deposited));
        Ok(())
    }

    /// Permissionless — authorized by the payer's signature, not an address. Never pausable. See module docs.
    pub fn checkpoint(
        env: Env,
        channel_id: u64,
        cumulative_amount: i128,
        nonce: u64,
        signature: BytesN<64>,
    ) -> Result<(), ChannelError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        let mut ch = Self::get_channel(&env, channel_id)?;
        if ch.status == ChannelStatus::Held {
            return Err(ChannelError::Held);
        }
        if ch.status == ChannelStatus::Closed {
            return Err(ChannelError::NotOpen);
        }
        if nonce <= ch.nonce || cumulative_amount <= ch.claimed {
            return Err(ChannelError::StaleClaim);
        }
        if cumulative_amount > ch.deposited {
            return Err(ChannelError::ExceedsDeposit);
        }

        let payload = Self::claim_payload(
            &env,
            &env.current_contract_address(),
            channel_id,
            nonce,
            cumulative_amount,
        );
        // Traps the whole invocation on a bad signature rather than returning
        // an error value — a real property of the host function, not a choice
        // this contract makes.
        env.crypto().ed25519_verify(&ch.payer_pubkey, &payload, &signature);

        let delta = cumulative_amount - ch.claimed;
        token::TokenClient::new(&env, &ch.token).transfer(&env.current_contract_address(), &ch.payee, &delta);

        ch.claimed = cumulative_amount;
        ch.nonce = nonce;
        Self::save_channel(&env, channel_id, &ch);
        env.events().publish((symbol_short!("checkpt"),), (channel_id, delta, cumulative_amount));
        Ok(())
    }

    pub fn initiate_close(env: Env, caller: Address, channel_id: u64) -> Result<(), ChannelError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        caller.require_auth();
        let mut ch = Self::get_channel(&env, channel_id)?;
        // The delegated closer lets a third party (e.g. the facilitator) start
        // the challenge window on an idle channel where neither party will.
        // It can only start a close — funds still go to the payer on finalize.
        if caller != ch.payer && caller != ch.payee && ch.delegated_closer.as_ref() != Some(&caller) {
            return Err(ChannelError::Unauthorized);
        }
        if ch.status != ChannelStatus::Open {
            return Err(ChannelError::NotOpen);
        }
        ch.status = ChannelStatus::Closing;
        ch.closing_at = env.ledger().timestamp();
        Self::save_channel(&env, channel_id, &ch);
        env.events().publish((symbol_short!("closing"),), channel_id);
        Ok(())
    }

    /// Permissionless — anyone can trigger this once the challenge window has
    /// elapsed. Pays the unclaimed remainder back to the payer.
    pub fn finalize_close(env: Env, channel_id: u64) -> Result<(), ChannelError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        let mut ch = Self::get_channel(&env, channel_id)?;
        if ch.status != ChannelStatus::Closing {
            return Err(ChannelError::NotClosing);
        }
        let period: u64 = env
            .storage()
            .instance()
            .get(&DataKey::ChallengePeriod)
            .ok_or(ChannelError::NotInitialized)?;
        if env.ledger().timestamp() < ch.closing_at + period {
            return Err(ChannelError::ChallengeNotElapsed);
        }
        let remainder = ch.deposited - ch.claimed;
        if remainder > 0 {
            token::TokenClient::new(&env, &ch.token).transfer(
                &env.current_contract_address(),
                &ch.payer,
                &remainder,
            );
        }
        ch.status = ChannelStatus::Closed;
        ch.deposited = ch.claimed;
        Self::save_channel(&env, channel_id, &ch);
        let open_count = Self::get_open_count(&env, &ch.payer);
        Self::save_open_count(&env, &ch.payer, open_count.saturating_sub(1));
        env.events().publish((symbol_short!("closed"), ch.payer.clone()), (channel_id, remainder, ch.claimed));
        Ok(())
    }

    /// Only Open or Closing channels can be held. Closing is included so an
    /// admin can freeze a suspect exit; release_hold restores whichever of the
    /// two it was in, so a unilateral exit is never silently reopened.
    pub fn hold_channel(env: Env, channel_id: u64) -> Result<(), ChannelError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        Self::require_admin(&env)?;
        let mut ch = Self::get_channel(&env, channel_id)?;
        if ch.status != ChannelStatus::Open && ch.status != ChannelStatus::Closing {
            return Err(ChannelError::NotOpen);
        }
        env.storage().persistent().set(&DataKey::HeldFrom(channel_id), &ch.status);
        ch.status = ChannelStatus::Held;
        Self::save_channel(&env, channel_id, &ch);
        env.events().publish((symbol_short!("held"),), channel_id);
        Ok(())
    }

    pub fn release_hold(env: Env, channel_id: u64) -> Result<(), ChannelError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        Self::require_admin(&env)?;
        let mut ch = Self::get_channel(&env, channel_id)?;
        if ch.status != ChannelStatus::Held {
            return Err(ChannelError::NotOpen);
        }
        let prior: ChannelStatus = env
            .storage()
            .persistent()
            .get(&DataKey::HeldFrom(channel_id))
            .ok_or(ChannelError::NotOpen)?;
        env.storage().persistent().remove(&DataKey::HeldFrom(channel_id));
        ch.status = prior;
        Self::save_channel(&env, channel_id, &ch);
        env.events().publish((symbol_short!("release"),), channel_id);
        Ok(())
    }

    /// Permissionless. Read-only.
    pub fn get_channel_info(env: Env, channel_id: u64) -> Result<Channel, ChannelError> {
        Self::get_channel(&env, channel_id)
    }

    /// Admin-gated allowlist of token contracts that open_channel accepts.
    /// Default-deny: a token is unusable until explicitly allowed here.
    pub fn set_token_allowed(env: Env, token: Address, allowed: bool) -> Result<(), ChannelError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        Self::require_admin(&env)?;
        let key = DataKey::AllowedToken(token.clone());
        env.storage().persistent().set(&key, &allowed);
        env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND_TO);
        env.events().publish((symbol_short!("tokenok"),), (token, allowed));
        Ok(())
    }

    /// Rotates the admin key. Requires auth from both the current admin and
    /// the incoming one, so a handoff can't strand the contract on an address
    /// nobody holds. Deliberately not pause-gated: rotating away from a
    /// suspected key must still work during an incident. Has no effect on
    /// checkpoint(), which is permissionless and never admin-gated.
    ///
    /// This does NOT defend against a leaked current key on its own — that key
    /// can still rotate to an attacker-held address. Quorum-based control
    /// (treasury's 2-of-3 model) or a multisig deployer account is what closes
    /// that gap; see docs/KEYS.md.
    pub fn set_admin(env: Env, current_admin: Address, new_admin: Address) -> Result<(), ChannelError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(ChannelError::NotInitialized)?;
        if current_admin != admin {
            return Err(ChannelError::Unauthorized);
        }
        current_admin.require_auth();
        new_admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.events().publish((symbol_short!("admin"),), new_admin);
        Ok(())
    }

    pub fn pause(env: Env) -> Result<(), ChannelError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        Self::require_admin(&env)?;
        env.storage().instance().set(&DataKey::Paused, &true);
        Ok(())
    }

    pub fn unpause(env: Env) -> Result<(), ChannelError> {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        Self::require_admin(&env)?;
        env.storage().instance().set(&DataKey::Paused, &false);
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
    use ed25519_dalek::{Signer, SigningKey};
    use soroban_sdk::testutils::{Address as _, Events as _, Ledger};
    use soroban_sdk::IntoVal;

    fn setup_token(env: &Env, admin: &Address) -> Address {
        // Stellar Asset Contract test token, provided by soroban-sdk testutils.
        let sac = env.register_stellar_asset_contract_v2(admin.clone());
        sac.address()
    }

    // claim_payload's exact length: 15-byte domain tag + 56-byte contract
    // strkey + 8-byte channel_id + 8-byte nonce + 16-byte cumulative_amount.
    // Bytes::to_alloc_vec() would be simpler but needs soroban-sdk's `alloc`
    // feature, which isn't enabled here — copy_into_slice into a fixed buffer
    // needs no new feature and the length is fixed anyway.
    fn payload_bytes(payload: &Bytes) -> [u8; 103] {
        let mut buf = [0u8; 103];
        payload.copy_into_slice(&mut buf);
        buf
    }

    #[test]
    fn open_and_checkpoint_transfers_funds() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token_id = setup_token(&env, &token_admin);
        let token_admin_client = token::StellarAssetClient::new(&env, &token_id);

        let payer = Address::generate(&env);
        let payee = Address::generate(&env);
        token_admin_client.mint(&payer, &1_000_0000i128);

        let contract_id = env.register(ChannelContract, ());
        let client = ChannelContractClient::new(&env, &contract_id);
        client.initialize(&admin, &86_400u64);
        client.set_token_allowed(&token_id, &true);

        // In production the payer's real Ed25519 keypair signs off-chain; the
        // test harness here only exercises the accounting and TTL logic, not
        // signature generation (that lives in the reconciler/client SDK).
        let payer_pubkey = BytesN::from_array(&env, &[9u8; 32]);
        let id = client.open_channel(&payer, &payee, &token_id, &payer_pubkey, &500_0000i128, &None);

        let ch = client.get_channel_info(&id);
        assert_eq!(ch.deposited, 500_0000i128);
        assert_eq!(ch.status, ChannelStatus::Open);

        let token_client = token::TokenClient::new(&env, &token_id);
        assert_eq!(token_client.balance(&contract_id), 500_0000i128);
    }

    #[test]
    fn finalize_close_before_challenge_elapses_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token_id = setup_token(&env, &token_admin);
        let token_admin_client = token::StellarAssetClient::new(&env, &token_id);

        let payer = Address::generate(&env);
        let payee = Address::generate(&env);
        token_admin_client.mint(&payer, &1_000_0000i128);

        let contract_id = env.register(ChannelContract, ());
        let client = ChannelContractClient::new(&env, &contract_id);
        client.initialize(&admin, &86_400u64);
        client.set_token_allowed(&token_id, &true);
        let payer_pubkey = BytesN::from_array(&env, &[9u8; 32]);
        let id = client.open_channel(&payer, &payee, &token_id, &payer_pubkey, &500_0000i128, &None);

        client.initiate_close(&payer, &id);
        let res = client.try_finalize_close(&id);
        assert_eq!(res, Err(Ok(ChannelError::ChallengeNotElapsed)));
    }

    #[test]
    fn finalize_close_refunds_remainder_after_challenge_period() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token_id = setup_token(&env, &token_admin);
        let token_admin_client = token::StellarAssetClient::new(&env, &token_id);

        let payer = Address::generate(&env);
        let payee = Address::generate(&env);
        token_admin_client.mint(&payer, &1_000_0000i128);

        let contract_id = env.register(ChannelContract, ());
        let client = ChannelContractClient::new(&env, &contract_id);
        client.initialize(&admin, &3_600u64);
        client.set_token_allowed(&token_id, &true);
        let payer_pubkey = BytesN::from_array(&env, &[9u8; 32]);
        let id = client.open_channel(&payer, &payee, &token_id, &payer_pubkey, &500_0000i128, &None);

        client.initiate_close(&payer, &id);
        env.ledger().with_mut(|l| l.timestamp += 3_601);
        client.finalize_close(&id);

        let token_client = token::TokenClient::new(&env, &token_id);
        assert_eq!(token_client.balance(&payer), 1_000_0000i128);
        assert_eq!(token_client.balance(&contract_id), 0i128);
        assert_eq!(
            env.events().all().filter_by_contract(&contract_id),
            soroban_sdk::vec![
                &env,
                (
                    contract_id.clone(),
                    (symbol_short!("closed"), payer.clone()).into_val(&env),
                    (id, 500_0000i128, 0i128).into_val(&env)
                )
            ]
        );
    }

    #[test]
    fn finalize_close_succeeds_at_exact_challenge_boundary() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token_id = setup_token(&env, &token_admin);
        let token_admin_client = token::StellarAssetClient::new(&env, &token_id);

        let payer = Address::generate(&env);
        let payee = Address::generate(&env);
        token_admin_client.mint(&payer, &1_000_0000i128);

        let contract_id = env.register(ChannelContract, ());
        let client = ChannelContractClient::new(&env, &contract_id);
        client.initialize(&admin, &3_600u64);
        client.set_token_allowed(&token_id, &true);
        let payer_pubkey = BytesN::from_array(&env, &[9u8; 32]);
        let id = client.open_channel(&payer, &payee, &token_id, &payer_pubkey, &500_0000i128, &None);

        client.initiate_close(&payer, &id);

        // One second short of the boundary still fails.
        env.ledger().with_mut(|l| l.timestamp += 3_599);
        let res = client.try_finalize_close(&id);
        assert_eq!(res, Err(Ok(ChannelError::ChallengeNotElapsed)));

        // timestamp == closing_at + period succeeds.
        env.ledger().with_mut(|l| l.timestamp += 1);
        client.finalize_close(&id);

        let token_client = token::TokenClient::new(&env, &token_id);
        assert_eq!(token_client.balance(&payer), 1_000_0000i128);
        assert_eq!(token_client.balance(&contract_id), 0i128);
    }

    #[test]
    fn initialize_rejects_zero_challenge_period() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);

        let contract_id = env.register(ChannelContract, ());
        let client = ChannelContractClient::new(&env, &contract_id);

        let res = client.try_initialize(&admin, &0u64);
        assert_eq!(res, Err(Ok(ChannelError::InvalidChallengePeriod)));

        // The rejection happens before any write, so the contract is still
        // uninitialized and a later call with a valid period succeeds.
        client.initialize(&admin, &3_600u64);
    }

    #[test]
    fn finalize_close_cannot_succeed_in_the_same_ledger_as_initiate_close() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token_id = setup_token(&env, &token_admin);
        let token_admin_client = token::StellarAssetClient::new(&env, &token_id);

        let payer = Address::generate(&env);
        let payee = Address::generate(&env);
        token_admin_client.mint(&payer, &1_000_0000i128);

        let contract_id = env.register(ChannelContract, ());
        let client = ChannelContractClient::new(&env, &contract_id);

        // 1 is the shortest period the contract accepts after this change.
        client.initialize(&admin, &1u64);
        client.set_token_allowed(&token_id, &true);
        let payer_pubkey = BytesN::from_array(&env, &[9u8; 32]);
        let id = client.open_channel(&payer, &payee, &token_id, &payer_pubkey, &500_0000i128, &None);

        client.initiate_close(&payer, &id);

        // No time advance at all. Under a zero period this call would succeed
        // and refund the full deposit in the same ledger.
        let res = client.try_finalize_close(&id);
        assert_eq!(res, Err(Ok(ChannelError::ChallengeNotElapsed)));

        let token_client = token::TokenClient::new(&env, &token_id);
        assert_eq!(token_client.balance(&contract_id), 500_0000i128);
    }

    #[test]
    fn checkpoint_rejects_stale_nonce() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token_id = setup_token(&env, &token_admin);
        let token_admin_client = token::StellarAssetClient::new(&env, &token_admin);
        let _ = token_admin_client; // silence unused in this path

        let payer = Address::generate(&env);
        let payee = Address::generate(&env);
        token::StellarAssetClient::new(&env, &token_id).mint(&payer, &1_000_0000i128);

        let contract_id = env.register(ChannelContract, ());
        let client = ChannelContractClient::new(&env, &contract_id);
        client.initialize(&admin, &86_400u64);
        client.set_token_allowed(&token_id, &true);
        let payer_pubkey = BytesN::from_array(&env, &[9u8; 32]);
        let id = client.open_channel(&payer, &payee, &token_id, &payer_pubkey, &500_0000i128, &None);

        let bogus_sig = BytesN::from_array(&env, &[0u8; 64]);
        let res = client.try_checkpoint(&id, &0i128, &0u64, &bogus_sig);
        assert_eq!(res, Err(Ok(ChannelError::StaleClaim)));
    }

    #[test]
    fn held_channel_rejects_checkpoint() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token_id = setup_token(&env, &token_admin);
        token::StellarAssetClient::new(&env, &token_id).mint(&Address::generate(&env), &0i128);

        let payer = Address::generate(&env);
        let payee = Address::generate(&env);
        token::StellarAssetClient::new(&env, &token_id).mint(&payer, &1_000_0000i128);

        let contract_id = env.register(ChannelContract, ());
        let client = ChannelContractClient::new(&env, &contract_id);
        client.initialize(&admin, &86_400u64);
        client.set_token_allowed(&token_id, &true);
        let payer_pubkey = BytesN::from_array(&env, &[9u8; 32]);
        let id = client.open_channel(&payer, &payee, &token_id, &payer_pubkey, &500_0000i128, &None);

        client.hold_channel(&id);
        let bogus_sig = BytesN::from_array(&env, &[0u8; 64]);
        let res = client.try_checkpoint(&id, &100_0000i128, &1u64, &bogus_sig);
        assert_eq!(res, Err(Ok(ChannelError::Held)));
    }

    // Every prior checkpoint test used a placeholder pubkey and a bogus
    // signature, short-circuiting on a stale-nonce or held-channel check
    // before ed25519_verify ever ran — meaning the contract's actual core
    // mechanism (accepting a genuine payer-signed claim and paying it out)
    // had zero coverage. This is the first test to sign for real.
    #[test]
    fn checkpoint_accepts_a_real_signed_claim() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token_id = setup_token(&env, &token_admin);
        let token_admin_client = token::StellarAssetClient::new(&env, &token_id);

        let payer = Address::generate(&env);
        let payee = Address::generate(&env);
        token_admin_client.mint(&payer, &1_000_0000i128);

        let contract_id = env.register(ChannelContract, ());
        let client = ChannelContractClient::new(&env, &contract_id);
        client.initialize(&admin, &86_400u64);
        client.set_token_allowed(&token_id, &true);

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let payer_pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());
        let id = client.open_channel(&payer, &payee, &token_id, &payer_pubkey, &500_0000i128, &None);

        let cumulative_amount: i128 = 100_0000;
        let nonce: u64 = 1;
        // claim_payload is private, called directly rather than
        // reimplemented — a test that built its own byte layout could pass
        // for the wrong reason if it silently drifted from what
        // checkpoint() actually verifies.
        let payload = ChannelContract::claim_payload(&env, &contract_id, id, nonce, cumulative_amount);
        let signature = BytesN::from_array(&env, &signing_key.sign(&payload_bytes(&payload)).to_bytes());

        client.checkpoint(&id, &cumulative_amount, &nonce, &signature);

        let ch = client.get_channel_info(&id);
        assert_eq!(ch.claimed, cumulative_amount);
        assert_eq!(ch.nonce, nonce);

        let token_client = token::TokenClient::new(&env, &token_id);
        assert_eq!(token_client.balance(&payee), cumulative_amount);
        assert_eq!(token_client.balance(&contract_id), 500_0000i128 - cumulative_amount);
    }

    // The dispute mechanism has no dedicated function — it *is* an ordinary
    // checkpoint() call, just one that happens to land after Closing has
    // started. No existing test exercised checkpoint() in the Closing
    // state at all, so this path — the literal reason a challenge period
    // exists — had zero coverage before this.
    #[test]
    fn checkpoint_accepts_higher_nonce_claim_during_closing() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token_id = setup_token(&env, &token_admin);
        let token_admin_client = token::StellarAssetClient::new(&env, &token_id);

        let payer = Address::generate(&env);
        let payee = Address::generate(&env);
        token_admin_client.mint(&payer, &1_000_0000i128);

        let contract_id = env.register(ChannelContract, ());
        let client = ChannelContractClient::new(&env, &contract_id);
        client.initialize(&admin, &3_600u64);
        client.set_token_allowed(&token_id, &true);

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let payer_pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());
        let id = client.open_channel(&payer, &payee, &token_id, &payer_pubkey, &500_0000i128, &None);

        let sign_claim = |nonce: u64, amount: i128| -> BytesN<64> {
            let payload = ChannelContract::claim_payload(&env, &contract_id, id, nonce, amount);
            BytesN::from_array(&env, &signing_key.sign(&payload_bytes(&payload)).to_bytes())
        };

        // An early, small checkpoint — standing in for whatever the last
        // on-chain-recorded state was before a close attempt started.
        client.checkpoint(&id, &50_0000i128, &1u64, &sign_claim(1, 50_0000));
        client.initiate_close(&payer, &id);

        let ch = client.get_channel_info(&id);
        assert_eq!(ch.status, ChannelStatus::Closing);

        // The better, higher-nonce claim — submitted during the challenge
        // window, after Closing has already started. This is the actual
        // dispute: proving checkpoint() still accepts it here, not just
        // while Open.
        client.checkpoint(&id, &300_0000i128, &2u64, &sign_claim(2, 300_0000));

        let ch = client.get_channel_info(&id);
        assert_eq!(ch.claimed, 300_0000i128);
        assert_eq!(ch.nonce, 2u64);

        env.ledger().with_mut(|l| l.timestamp += 3_601);
        client.finalize_close(&id);

        let token_client = token::TokenClient::new(&env, &token_id);
        assert_eq!(token_client.balance(&payee), 300_0000i128);
        // Remainder is 500 - 300, not 500 - 50 — proves finalize_close
        // respects the dispute's outcome, not the pre-dispute state.
        assert_eq!(token_client.balance(&payer), 1_000_0000i128 - 300_0000i128);
        assert_eq!(token_client.balance(&contract_id), 0i128);
    }

    #[test]
    fn checkpoint_rejects_amount_exceeding_deposit() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token_id = setup_token(&env, &token_admin);
        let token_admin_client = token::StellarAssetClient::new(&env, &token_id);

        let payer = Address::generate(&env);
        let payee = Address::generate(&env);
        token_admin_client.mint(&payer, &1_000_0000i128);

        let contract_id = env.register(ChannelContract, ());
        let client = ChannelContractClient::new(&env, &contract_id);
        client.initialize(&admin, &86_400u64);
        client.set_token_allowed(&token_id, &true);

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let payer_pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());
        let id = client.open_channel(&payer, &payee, &token_id, &payer_pubkey, &500_0000i128, &None);

        // A validly-signed claim for more than was ever deposited — must be
        // rejected on the deposit check, not accepted just because the
        // signature is genuine.
        let cumulative_amount: i128 = 600_0000;
        let nonce: u64 = 1;
        let payload = ChannelContract::claim_payload(&env, &contract_id, id, nonce, cumulative_amount);
        let signature = BytesN::from_array(&env, &signing_key.sign(&payload_bytes(&payload)).to_bytes());

        let res = client.try_checkpoint(&id, &cumulative_amount, &nonce, &signature);
        assert_eq!(res, Err(Ok(ChannelError::ExceedsDeposit)));
    }

    #[test]
    fn top_up_increases_deposited_capacity() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token_id = setup_token(&env, &token_admin);
        let token_admin_client = token::StellarAssetClient::new(&env, &token_id);

        let payer = Address::generate(&env);
        let payee = Address::generate(&env);
        token_admin_client.mint(&payer, &1_000_0000i128);

        let contract_id = env.register(ChannelContract, ());
        let client = ChannelContractClient::new(&env, &contract_id);
        client.initialize(&admin, &86_400u64);
        client.set_token_allowed(&token_id, &true);
        let payer_pubkey = BytesN::from_array(&env, &[9u8; 32]);
        let id = client.open_channel(&payer, &payee, &token_id, &payer_pubkey, &500_0000i128, &None);

        client.top_up(&payer, &id, &200_0000i128);

        let ch = client.get_channel_info(&id);
        assert_eq!(ch.deposited, 700_0000i128);
        assert_eq!(
            env.events().all().filter_by_contract(&contract_id),
            soroban_sdk::vec![
                &env,
                (
                    contract_id.clone(),
                    (symbol_short!("topup"),).into_val(&env),
                    (id, 200_0000i128, 700_0000i128).into_val(&env)
                )
            ]
        );
        client.top_up(&payer, &id, &100_0000i128);
        assert_eq!(client.get_channel_info(&id).deposited, 800_0000i128);
        assert_eq!(
            env.events().all().filter_by_contract(&contract_id),
            soroban_sdk::vec![
                &env,
                (
                    contract_id.clone(),
                    (symbol_short!("topup"),).into_val(&env),
                    (id, 100_0000i128, 800_0000i128).into_val(&env)
                )
            ]
        );

        let token_client = token::TokenClient::new(&env, &token_id);
        assert_eq!(token_client.balance(&contract_id), 700_0000i128);
        assert_eq!(token_client.balance(&payer), 1_000_0000i128 - 700_0000i128);
    }

    #[test]
    fn release_hold_restores_open_and_resumes_checkpoint_and_top_up() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token_id = setup_token(&env, &token_admin);
        let token_admin_client = token::StellarAssetClient::new(&env, &token_id);

        let payer = Address::generate(&env);
        let payee = Address::generate(&env);
        token_admin_client.mint(&payer, &1_000_0000i128);

        let contract_id = env.register(ChannelContract, ());
        let client = ChannelContractClient::new(&env, &contract_id);
        client.initialize(&admin, &86_400u64);
        client.set_token_allowed(&token_id, &true);

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let payer_pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());
        let id = client.open_channel(&payer, &payee, &token_id, &payer_pubkey, &500_0000i128, &None);

        client.hold_channel(&id);
        assert_eq!(client.get_channel_info(&id).status, ChannelStatus::Held);
        assert_eq!(
            client.try_top_up(&payer, &id, &100_0000i128),
            Err(Ok(ChannelError::NotOpen))
        );

        client.release_hold(&id);
        assert_eq!(client.get_channel_info(&id).status, ChannelStatus::Open);

        client.top_up(&payer, &id, &100_0000i128);
        assert_eq!(client.get_channel_info(&id).deposited, 600_0000i128);

        let cumulative_amount: i128 = 100_0000;
        let nonce: u64 = 1;
        let payload = ChannelContract::claim_payload(&env, &contract_id, id, nonce, cumulative_amount);
        let signature = BytesN::from_array(&env, &signing_key.sign(&payload_bytes(&payload)).to_bytes());
        client.checkpoint(&id, &cumulative_amount, &nonce, &signature);

        let ch = client.get_channel_info(&id);
        assert_eq!(ch.claimed, cumulative_amount);
        assert_eq!(token::TokenClient::new(&env, &token_id).balance(&payee), cumulative_amount);
    }

    #[test]
    fn release_hold_rejects_non_held_channel() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token_id = setup_token(&env, &token_admin);
        let token_admin_client = token::StellarAssetClient::new(&env, &token_id);

        let payer = Address::generate(&env);
        let payee = Address::generate(&env);
        token_admin_client.mint(&payer, &1_000_0000i128);

        let contract_id = env.register(ChannelContract, ());
        let client = ChannelContractClient::new(&env, &contract_id);
        client.initialize(&admin, &86_400u64);
        client.set_token_allowed(&token_id, &true);
        let payer_pubkey = BytesN::from_array(&env, &[9u8; 32]);
        let id = client.open_channel(&payer, &payee, &token_id, &payer_pubkey, &500_0000i128, &None);

        // Open channel: nothing to release.
        assert_eq!(client.try_release_hold(&id), Err(Ok(ChannelError::NotOpen)));
        assert_eq!(client.get_channel_info(&id).status, ChannelStatus::Open);

        // Closing channel: also not Held.
        client.initiate_close(&payer, &id);
        assert_eq!(client.try_release_hold(&id), Err(Ok(ChannelError::NotOpen)));
        assert_eq!(client.get_channel_info(&id).status, ChannelStatus::Closing);
    }

    // Every other initiate_close call site uses the payer, so the payee half
    // of the payer-or-payee guard had no coverage: flipping it would reject a
    // legitimate payee close and admit an unrelated caller.
    #[test]
    fn initiate_close_by_payee_succeeds() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token_id = setup_token(&env, &token_admin);
        let token_admin_client = token::StellarAssetClient::new(&env, &token_id);

        let payer = Address::generate(&env);
        let payee = Address::generate(&env);
        token_admin_client.mint(&payer, &1_000_0000i128);

        let contract_id = env.register(ChannelContract, ());
        let client = ChannelContractClient::new(&env, &contract_id);
        client.initialize(&admin, &86_400u64);
        client.set_token_allowed(&token_id, &true);
        let payer_pubkey = BytesN::from_array(&env, &[9u8; 32]);
        let id = client.open_channel(&payer, &payee, &token_id, &payer_pubkey, &500_0000i128, &None);

        client.initiate_close(&payee, &id);

        let ch = client.get_channel_info(&id);
        assert_eq!(ch.status, ChannelStatus::Closing);
        assert_eq!(ch.closing_at, env.ledger().timestamp());
    }

    #[test]
    fn initiate_close_by_unrelated_address_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token_id = setup_token(&env, &token_admin);
        let token_admin_client = token::StellarAssetClient::new(&env, &token_id);

        let payer = Address::generate(&env);
        let payee = Address::generate(&env);
        let outsider = Address::generate(&env);
        token_admin_client.mint(&payer, &1_000_0000i128);

        let contract_id = env.register(ChannelContract, ());
        let client = ChannelContractClient::new(&env, &contract_id);
        client.initialize(&admin, &86_400u64);
        client.set_token_allowed(&token_id, &true);
        let payer_pubkey = BytesN::from_array(&env, &[9u8; 32]);
        let id = client.open_channel(&payer, &payee, &token_id, &payer_pubkey, &500_0000i128, &None);

        let res = client.try_initiate_close(&outsider, &id);
        assert_eq!(res, Err(Ok(ChannelError::Unauthorized)));
        assert_eq!(client.get_channel_info(&id).status, ChannelStatus::Open);
    }

    // When the payee has already claimed the full deposit, finalize_close has
    // nothing to refund and must skip the payer transfer entirely rather than
    // issue a zero-amount one.
    #[test]
    fn finalize_close_skips_transfer_when_deposit_fully_claimed() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token_id = setup_token(&env, &token_admin);
        let token_admin_client = token::StellarAssetClient::new(&env, &token_id);

        let payer = Address::generate(&env);
        let payee = Address::generate(&env);
        token_admin_client.mint(&payer, &1_000_0000i128);

        let contract_id = env.register(ChannelContract, ());
        let client = ChannelContractClient::new(&env, &contract_id);
        client.initialize(&admin, &3_600u64);
        client.set_token_allowed(&token_id, &true);

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let payer_pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());
        let deposit: i128 = 500_0000;
        let id = client.open_channel(&payer, &payee, &token_id, &payer_pubkey, &deposit, &None);

        let nonce: u64 = 1;
        let payload = ChannelContract::claim_payload(&env, &contract_id, id, nonce, deposit);
        let signature = BytesN::from_array(&env, &signing_key.sign(&payload_bytes(&payload)).to_bytes());
        client.checkpoint(&id, &deposit, &nonce, &signature);

        client.initiate_close(&payer, &id);
        env.ledger().with_mut(|l| l.timestamp += 3_601);
        client.finalize_close(&id);

        // The SAC accepts a zero-amount transfer, so balances alone can't
        // tell a skipped transfer from a zero one — the token contract's
        // event log can. finalize_close's own event is the only one expected.
        let token_events = env.events().all().filter_by_contract(&token_id);
        assert_eq!(token_events.events().len(), 0);

        let ch = client.get_channel_info(&id);
        assert_eq!(ch.status, ChannelStatus::Closed);
        assert_eq!(ch.claimed, deposit);

        let token_client = token::TokenClient::new(&env, &token_id);
        assert_eq!(token_client.balance(&payee), deposit);
        assert_eq!(token_client.balance(&payer), 1_000_0000i128 - deposit);
        assert_eq!(token_client.balance(&contract_id), 0i128);
    }
}
