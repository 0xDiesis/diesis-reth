use super::{StaticFileProvider, StaticFileProviderBuilder};
use crate::{BlockHashReader, HeaderProvider, StaticFileWriter};
use alloy_consensus::Header;
use alloy_primitives::{BlockNumber, B256};
use reth_db::test_utils::create_test_static_files_dir;
use reth_ethereum_primitives::EthPrimitives;
use reth_static_file_types::StaticFileSegment;
use reth_storage_errors::provider::{ProviderError, ProviderResult};
use std::{fmt::Debug, ops::RangeInclusive};

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

fn append_empty_history(provider: &StaticFileProvider<EthPrimitives>, first: BlockNumber) {
    let mut header = Header { number: first, ..Default::default() };
    let mut header_writer = provider.latest_writer(StaticFileSegment::Headers).unwrap();
    header_writer.append_header(&header, &B256::with_last_byte(1)).unwrap();
    header.number += 1;
    header_writer.append_header(&header, &B256::with_last_byte(2)).unwrap();
    header_writer.commit().unwrap();

    let mut transaction_writer = provider.latest_writer(StaticFileSegment::Transactions).unwrap();
    transaction_writer.increment_block(first).unwrap();
    transaction_writer.increment_block(first + 1).unwrap();
    transaction_writer.commit().unwrap();
}

#[test]
fn history_floors_only_rise_and_stay_independent() {
    let (static_dir, _) = create_test_static_files_dir();
    let provider: StaticFileProvider<EthPrimitives> =
        StaticFileProviderBuilder::read_write(&static_dir).build().unwrap();

    provider.raise_history_floor(301);
    provider.raise_history_floor(200);
    assert_eq!(provider.earliest_history_height(), 301);
    provider.raise_history_floor(400);
    assert_eq!(provider.earliest_history_height(), 400);

    provider.raise_header_history_floor(44);
    provider.raise_header_history_floor(12);
    assert_eq!(provider.earliest_header_height(), 44);
    assert_eq!(provider.earliest_history_height(), 400);
    provider.raise_header_history_floor(50);
    assert_eq!(provider.earliest_header_height(), 50);
}

#[test]
fn index_initialization_takes_the_maximum_of_explicit_and_indexed_floors() {
    let (static_dir, _) = create_test_static_files_dir();
    let provider: StaticFileProvider<EthPrimitives> =
        StaticFileProviderBuilder::read_write(&static_dir).build().unwrap();
    append_empty_history(&provider, 0);

    provider.raise_history_floor(301);
    provider.raise_header_history_floor(44);
    provider.initialize_index().unwrap();
    assert_eq!(provider.earliest_history_height(), 301);
    assert_eq!(provider.earliest_header_height(), 44);

    drop(provider);

    let indexed: StaticFileProvider<EthPrimitives> =
        StaticFileProviderBuilder::read_write(&static_dir).build().unwrap();
    assert_eq!(indexed.earliest_history_height(), 0);
    assert_eq!(indexed.earliest_header_height(), 0);
}

#[test]
fn every_header_family_enforces_only_the_header_floor() {
    let (static_dir, _) = create_test_static_files_dir();
    let provider: StaticFileProvider<EthPrimitives> =
        StaticFileProviderBuilder::read_write(&static_dir).build().unwrap();
    append_empty_history(&provider, 0);
    provider.raise_history_floor(2);
    provider.raise_header_history_floor(1);

    assert_expired(provider.header_by_number(0), 0, 1);
    assert_expired(provider.headers_range(0..=1), 0, 1);
    assert_expired(provider.sealed_header(0), 0, 1);
    assert_expired(provider.sealed_headers_range(0..=1), 0, 1);
    assert_expired(provider.block_hash(0), 0, 1);
    assert_expired(provider.canonical_hashes_range(0, 2), 0, 1);

    assert!(provider.header_by_number(1).unwrap().is_some());
    assert_eq!(provider.headers_range(1..=1).unwrap().len(), 1);
    assert!(provider.sealed_header(1).unwrap().is_some());
    assert_eq!(provider.sealed_headers_range(1..=1).unwrap().len(), 1);
    assert_eq!(provider.block_hash(1).unwrap(), Some(B256::with_last_byte(2)));
    assert_eq!(provider.canonical_hashes_range(1, 2).unwrap().len(), 1);
    assert!(provider.headers_range(RangeInclusive::new(2, 1)).unwrap().is_empty());
}

#[test]
fn standalone_header_hash_lookups_require_an_index() {
    let (static_dir, _) = create_test_static_files_dir();
    let provider: StaticFileProvider<EthPrimitives> =
        StaticFileProviderBuilder::read_write(&static_dir).build().unwrap();
    append_empty_history(&provider, 0);
    provider.raise_header_history_floor(1);

    for hash in [B256::with_last_byte(1), B256::with_last_byte(2), B256::ZERO] {
        assert!(matches!(provider.header(hash), Err(ProviderError::UnsupportedProvider)));
    }
}
