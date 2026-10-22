use super::*;
use soroban_sdk::{
    testutils::{Address as _, Events as _},
    token::{StellarAssetClient, TokenClient},
    Address, Env, IntoVal, Symbol, Val, Vec,
};

fn setup() -> (Env, TreasuryContractClient<'static>, Address, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let signer_a = Address::generate(&env);
    let signer_b = Address::generate(&env);
    let merchant = Address::generate(&env);

    let token_admin = Address::generate(&env);
    let sac = env.register_stellar_asset_contract_v2(token_admin.clone());
    let token_addr = sac.address();

    let contract_id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &contract_id);

    let mut signers = Vec::new(&env);
    signers.push_back(signer_a.clone());
    signers.push_back(signer_b.clone());
    client.initialize(&admin, &token_addr, &signers, &2u32);

    // Fund the treasury so it can pay out.
    let asset_admin = StellarAssetClient::new(&env, &token_addr);
    asset_admin.mint(&contract_id, &1_000i128);

    (env, client, signer_a, signer_b, merchant, token_addr)
}

#[test]
fn executed_event_carries_amount_and_merchant() {
    let (env, client, signer_a, signer_b, merchant, token_addr) = setup();
    let amount: i128 = 250;

    let id = client.propose_settlement(&signer_a, &merchant, &amount);
    client.approve_settlement(&signer_b, &id);
    client.execute_settlement(&signer_a, &id);

    // The merchant actually received the funds.
    let token = TokenClient::new(&env, &token_addr);
    assert_eq!(token.balance(&merchant), amount);

    // Find the `executed` event and assert its topic/data match the payout.
    let executed_topic = Symbol::new(&env, "executed");
    let mut found = false;
    for (contract, topics, data) in env.events().all().iter() {
        if contract != client.address {
            continue;
        }
        let topics_vec: Vec<Val> = topics;
        if topics_vec.len() != 2 {
            continue;
        }
        let topic0: Symbol = topics_vec.get(0).unwrap().into_val(&env);
        if topic0 != executed_topic {
            continue;
        }
        let topic_merchant: Address = topics_vec.get(1).unwrap().into_val(&env);
        assert_eq!(topic_merchant, merchant);

        let (event_id, event_amount): (u64, i128) = data.into_val(&env);
        assert_eq!(event_id, id);
        assert_eq!(event_amount, amount);
        found = true;
    }
    assert!(found, "executed event was not emitted");
}
