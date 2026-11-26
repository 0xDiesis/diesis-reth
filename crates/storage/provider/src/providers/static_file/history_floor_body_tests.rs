use super::StaticFileProvider;
use crate::{
    test_utils::{create_test_provider_factory, MockNodeTypesWithDB},
    ProviderFactory, ReceiptProvider, StaticFileProviderFactory, StaticFileWriter,
    TransactionsProvider, TransactionsProviderExt,
};
use alloy_consensus::{transaction::TxHashRef as _, SignableTransaction, TxLegacy};
use alloy_primitives::{Address, BlockNumber, Signature, TxHash, U160};
use reth_db_api::{tables, transaction::DbTxMut};
use reth_ethereum_primitives::{EthPrimitives, Receipt, TransactionSigned};
use reth_static_file_types::StaticFileSegment;
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
        other => {
            panic!("expected expired block {requested} before {earliest_available}: {other:?}")
        }
    }
}

fn populated_provider(
) -> (ProviderFactory<MockNodeTypesWithDB>, StaticFileProvider<EthPrimitives>, TxHash, TxHash) {
    let factory = create_test_provider_factory();
    let provider = factory.static_file_provider();
    let db = factory.provider_rw().unwrap();
    for block in 0..=2 {
        db.tx_ref().put::<tables::TransactionBlocks>(block, block).unwrap();
    }
    db.commit().unwrap();

    let mut hashes = Vec::new();
    {
        let mut writer = provider.latest_writer(StaticFileSegment::Transactions).unwrap();
        for tx_num in 0..=2 {
            writer.increment_block(tx_num).unwrap();
            let signed: TransactionSigned = TxLegacy { nonce: tx_num, ..Default::default() }
                .into_signed(Signature::test_signature())
                .into();
            hashes.push(*signed.tx_hash());
            writer.append_transaction(tx_num, &signed).unwrap();
        }
        writer.commit().unwrap();
    }
    {
        let mut writer = provider.latest_writer(StaticFileSegment::Receipts).unwrap();
        for tx_num in 0..=2 {
            writer.increment_block(tx_num).unwrap();
            let receipt = Receipt { cumulative_gas_used: tx_num, ..Default::default() };
            writer.append_receipt(tx_num, &receipt).unwrap();
        }
        writer.commit().unwrap();
    }
    {
        let mut writer = provider.latest_writer(StaticFileSegment::TransactionSenders).unwrap();
        for tx_num in 0..=2 {
            writer.increment_block(tx_num).unwrap();
            writer.append_transaction_sender(tx_num, &Address::from(U160::from(tx_num))).unwrap();
        }
        writer.commit().unwrap();
    }

    (factory, provider, hashes[1], hashes[2])
}

#[test]
fn direct_static_transaction_number_reads_obey_the_body_floor() {
    let (_factory, provider, _, _) = populated_provider();
    provider.raise_history_floor(2);

    assert_expired(provider.transaction_by_id(1), 1, 2);
    assert_expired(provider.transaction_by_id_unhashed(1), 1, 2);

    assert!(provider.transaction_by_id(2).unwrap().is_some());
    assert!(provider.transaction_by_id_unhashed(2).unwrap().is_some());
}

#[test]
fn direct_static_transaction_ranges_obey_the_body_floor() {
    let (_factory, provider, _, _) = populated_provider();
    provider.raise_history_floor(2);

    assert_expired(provider.transactions_by_tx_range(1..2), 1, 2);
    assert_expired(provider.transaction_hashes_by_range(1..2), 1, 2);
    assert_expired(provider.senders_by_tx_range(1..2), 1, 2);

    assert_eq!(provider.transactions_by_tx_range(2..3).unwrap().len(), 1);
    assert_eq!(provider.transaction_hashes_by_range(2..3).unwrap().len(), 1);
    assert_eq!(provider.senders_by_tx_range(2..3).unwrap().len(), 1);
}

#[test]
fn direct_static_transaction_hash_reads_obey_the_body_floor() {
    let (_factory, provider, expired_hash, available_hash) = populated_provider();
    provider.raise_history_floor(2);

    assert!(provider.transaction_id(expired_hash).unwrap().is_none());
    assert!(provider.transaction_by_hash(expired_hash).unwrap().is_none());

    assert_eq!(provider.transaction_id(available_hash).unwrap(), Some(2));
    assert!(provider.transaction_by_hash(available_hash).unwrap().is_some());
}

#[test]
fn direct_static_transaction_sender_obeys_the_body_floor() {
    let (_factory, provider, _, _) = populated_provider();
    provider.raise_history_floor(2);

    assert_expired(provider.transaction_sender(1), 1, 2);
    assert!(provider.transaction_sender(2).unwrap().is_some());
}

#[test]
fn direct_static_receipt_number_reads_obey_the_body_floor() {
    let (_factory, provider, _, _) = populated_provider();
    provider.raise_history_floor(2);

    assert_expired(provider.receipt(1), 1, 2);
    assert!(provider.receipt(2).unwrap().is_some());
}

#[test]
fn direct_static_receipt_ranges_obey_the_body_floor() {
    let (_factory, provider, _, _) = populated_provider();
    provider.raise_history_floor(2);

    assert_expired(provider.receipts_by_tx_range(1..2), 1, 2);
    assert_eq!(provider.receipts_by_tx_range(2..3).unwrap().len(), 1);
}

#[test]
fn direct_static_receipt_hash_reads_obey_the_body_floor() {
    let (_factory, provider, expired_hash, available_hash) = populated_provider();
    provider.raise_history_floor(2);

    assert!(provider.receipt_by_hash(expired_hash).unwrap().is_none());
    assert!(provider.receipt_by_hash(available_hash).unwrap().is_some());
}
