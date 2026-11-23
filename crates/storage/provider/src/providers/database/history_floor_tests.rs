use crate::{
    test_utils::{blocks::BlockchainTestData, create_test_provider_factory, MockNodeTypesWithDB},
    BlockBodyIndicesProvider, BlockReader, BlockSource, BlockWriter, OriginalValuesKnown,
    ProviderFactory, ReceiptProvider, StaticFileProviderFactory, TransactionVariant,
    TransactionsProvider, TransactionsProviderExt,
};
use alloy_consensus::transaction::TxHashRef as _;
use alloy_primitives::{BlockNumber, TxNumber};
use reth_primitives_traits::BlockBody as _;
use reth_storage_api::StateWriteConfig;
use reth_storage_errors::provider::{ProviderError, ProviderResult};
use std::fmt::Debug;

fn assert_expired<T: Debug>(
    result: ProviderResult<T>,
    requested: BlockNumber,
    earliest_available: BlockNumber,
) {
    match result {
        Err(ProviderError::BlockExpired { requested: got, earliest_available: earliest }) => {
            assert_eq!(got, requested);
            assert_eq!(earliest, earliest_available);
        }
        other => panic!("expected expired block {requested} before {earliest_available}: {other:?}"),
    }
}

fn populated_factory() -> (ProviderFactory<MockNodeTypesWithDB>, BlockchainTestData) {
    let factory = create_test_provider_factory();
    let data = BlockchainTestData::default();
    let provider = factory.provider_rw().unwrap();

    provider.insert_block(&data.genesis.clone().try_recover().unwrap()).unwrap();
    provider
        .write_state(
            &crate::ExecutionOutcome {
                first_block: 0,
                receipts: vec![vec![]],
                ..Default::default()
            },
            OriginalValuesKnown::No,
            StateWriteConfig::default(),
        )
        .unwrap();
    for (block, outcome) in &data.blocks[..3] {
        provider.insert_block(block).unwrap();
        provider
            .write_state(outcome, OriginalValuesKnown::No, StateWriteConfig::default())
            .unwrap();
    }
    provider.commit().unwrap();

    (factory, data)
}

#[test]
fn block_read_families_enforce_the_body_floor_and_preserve_empty_ranges() {
    let (factory, data) = populated_factory();
    factory.static_file_provider().raise_history_floor(2);
    let provider = factory.provider().unwrap();
    let expired_hash = data.blocks[0].0.hash();

    assert_expired(provider.block(1.into()), 1, 2);
    assert_expired(provider.find_block_by_hash(expired_hash, BlockSource::Canonical), 1, 2);
    assert_expired(provider.recovered_block(1.into(), TransactionVariant::WithHash), 1, 2);
    assert_expired(
        provider.sealed_block_with_senders(1.into(), TransactionVariant::WithHash),
        1,
        2,
    );
    assert_expired(provider.block_range(1..=2), 1, 2);
    assert_expired(provider.block_with_senders_range(1..=2), 1, 2);
    assert_expired(provider.recovered_block_range(1..=2), 1, 2);

    assert!(provider.block(2.into()).unwrap().is_some());
    assert_eq!(provider.block_range(2..=2).unwrap().len(), 1);
    assert!(provider.block_range(2..=1).unwrap().is_empty());
}

#[test]
fn transaction_read_families_enforce_the_body_floor_without_hash_errors() {
    let (factory, data) = populated_factory();
    let expired_hash = *data.blocks[0].0.body().transactions()[0].tx_hash();
    let available_hash = *data.blocks[1].0.body().transactions()[0].tx_hash();
    let before = factory.provider().unwrap();
    let expired_id = before.transaction_id(expired_hash).unwrap().unwrap();
    let available_id = before.transaction_id(available_hash).unwrap().unwrap();
    drop(before);

    factory.static_file_provider().raise_history_floor(2);
    let provider = factory.provider().unwrap();

    assert_expired(provider.block_body_indices(1), 1, 2);
    assert_expired(provider.block_body_indices_range(1..=2), 1, 2);
    assert_expired(provider.transactions_by_block(1.into()), 1, 2);
    assert_expired(provider.transactions_by_block_range(1..=2), 1, 2);
    assert_expired(provider.block_by_transaction_id(expired_id), 1, 2);
    assert_expired(provider.transaction_by_id(expired_id), 1, 2);
    assert_expired(provider.transaction_by_id_unhashed(expired_id), 1, 2);
    assert_expired(provider.transactions_by_tx_range(expired_id..=expired_id), 1, 2);
    assert_expired(provider.transaction_hashes_by_range(expired_id..expired_id + 1), 1, 2);
    assert_expired(provider.senders_by_tx_range(expired_id..=expired_id), 1, 2);
    assert_expired(provider.transaction_sender(expired_id), 1, 2);

    assert!(provider.transaction_id(expired_hash).unwrap().is_none());
    assert!(provider.transaction_by_hash(expired_hash).unwrap().is_none());
    assert!(provider.transaction_by_hash_with_meta(expired_hash).unwrap().is_none());
    assert_eq!(provider.transaction_id(available_hash).unwrap(), Some(available_id));
    assert!(provider.transaction_by_hash(available_hash).unwrap().is_some());
    assert!(provider.transaction_by_id(available_id).unwrap().is_some());
    assert!(provider.transactions_by_block(2.into()).unwrap().is_some());
    assert_eq!(provider.transactions_by_block_range(2..=2).unwrap().len(), 1);
    assert!(provider.transactions_by_block_range(2..2).unwrap().is_empty());
}

#[test]
fn receipt_read_families_enforce_the_body_floor_without_hash_errors() {
    let (factory, data) = populated_factory();
    let expired_hash = *data.blocks[0].0.body().transactions()[0].tx_hash();
    let available_hash = *data.blocks[1].0.body().transactions()[0].tx_hash();
    let before = factory.provider().unwrap();
    let expired_id: TxNumber = before.transaction_id(expired_hash).unwrap().unwrap();
    let available_id: TxNumber = before.transaction_id(available_hash).unwrap().unwrap();
    drop(before);

    factory.static_file_provider().raise_history_floor(2);
    let provider = factory.provider().unwrap();

    assert_expired(provider.receipt(expired_id), 1, 2);
    assert_expired(provider.receipts_by_block(1.into()), 1, 2);
    assert_expired(provider.receipts_by_tx_range(expired_id..=expired_id), 1, 2);
    assert_expired(provider.receipts_by_block_range(1..=2), 1, 2);

    assert!(provider.receipt_by_hash(expired_hash).unwrap().is_none());
    assert!(provider.receipt_by_hash(available_hash).unwrap().is_some());
    assert!(provider.receipt(available_id).unwrap().is_some());
    assert!(provider.receipts_by_block(2.into()).unwrap().is_some());
    assert_eq!(provider.receipts_by_block_range(2..=2).unwrap().len(), 1);
    assert!(provider.receipts_by_block_range(2..=1).unwrap().is_empty());
}
