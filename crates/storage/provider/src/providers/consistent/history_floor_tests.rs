use super::ConsistentProvider;
use crate::{
    providers::blockchain_provider::BlockchainProvider,
    test_utils::{create_test_provider_factory, MockNodeTypesWithDB},
    BlockReaderIdExt, BlockWriter, ProviderError, ReceiptProviderIdExt, StaticFileProviderFactory,
};
use alloy_consensus::Header;
use alloy_eips::{BlockId, BlockNumberOrTag};
use alloy_primitives::B256;
use reth_chain_state::{CanonicalInMemoryState, ExecutedBlock, NewCanonicalChain};
use reth_ethereum_primitives::Receipt;
use reth_execution_types::{BlockExecutionOutput, BlockExecutionResult};
use reth_primitives_traits::{RecoveredBlock, SealedHeader};
use reth_storage_errors::provider::ProviderResult;
use reth_testing_utils::generators::{self, random_block_range, BlockRangeParams};
use revm::database::BundleState;
use std::{fmt::Debug, sync::Arc};

fn assert_expired<T: Debug>(result: ProviderResult<T>, requested: u64, earliest_available: u64) {
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

fn tagged_provider(
    tagged_number: u64,
    header_floor: u64,
) -> ConsistentProvider<MockNodeTypesWithDB> {
    let factory = create_test_provider_factory();
    factory.static_file_provider().raise_header_history_floor(header_floor);
    let tagged = SealedHeader::seal_slow(Header { number: tagged_number, ..Default::default() });
    let state =
        CanonicalInMemoryState::with_head(tagged.clone(), Some(tagged.clone()), Some(tagged));
    ConsistentProvider::new(factory, state).unwrap()
}

#[test]
fn in_memory_header_tags_obey_the_header_floor() {
    let expired = tagged_provider(1, 2);
    for tag in [BlockNumberOrTag::Latest, BlockNumberOrTag::Safe, BlockNumberOrTag::Finalized] {
        assert_expired(expired.header_by_number_or_tag(tag), 1, 2);
        assert_expired(expired.sealed_header_by_number_or_tag(tag), 1, 2);
    }

    let available = tagged_provider(2, 2);
    for tag in [BlockNumberOrTag::Latest, BlockNumberOrTag::Safe, BlockNumberOrTag::Finalized] {
        assert!(available.header_by_number_or_tag(tag).unwrap().is_some());
        assert!(available.sealed_header_by_number_or_tag(tag).unwrap().is_some());
    }
}

#[test]
fn noncanonical_receipt_fallback_cannot_bypass_the_body_floor() -> eyre::Result<()> {
    let mut rng = generators::rng();
    let factory = create_test_provider_factory();
    let static_files = factory.static_file_provider();
    let blocks = random_block_range(
        &mut rng,
        0..=2,
        BlockRangeParams { parent: Some(B256::ZERO), tx_count: 1..2, ..Default::default() },
    );

    let provider_rw = factory.provider_rw()?;
    provider_rw
        .insert_block(&blocks[0].clone().try_recover().expect("database block has senders"))?;
    provider_rw.commit()?;

    let provider = BlockchainProvider::new(factory)?;
    provider.canonical_in_memory_state.update_chain(NewCanonicalChain::Commit {
        new: blocks[1..]
            .iter()
            .map(|block| {
                let senders = block.senders().expect("in-memory block has senders");
                ExecutedBlock {
                    recovered_block: Arc::new(RecoveredBlock::new_sealed(block.clone(), senders)),
                    execution_output: Arc::new(BlockExecutionOutput {
                        state: BundleState::default(),
                        result: BlockExecutionResult {
                            receipts: vec![Receipt::default(); block.body().transactions.len()],
                            requests: Default::default(),
                            gas_used: 0,
                            blob_gas_used: 0,
                        },
                    }),
                    ..Default::default()
                }
            })
            .collect(),
    });

    static_files.raise_history_floor(2);
    let provider = provider.consistent_provider()?;
    let expired = BlockId::Hash(blocks[1].hash().into());
    assert_expired(provider.receipts_by_block_id(expired), 1, 2);

    let available = BlockId::Hash(blocks[2].hash().into());
    assert_eq!(provider.receipts_by_block_id(available)?.unwrap().len(), 1);
    Ok(())
}
