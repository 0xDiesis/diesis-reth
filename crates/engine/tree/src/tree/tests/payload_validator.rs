use super::*;

use alloy_primitives::{Signature, U256};
use reth_primitives_traits::{BlockBody as _, GotExpected};

#[derive(Debug, Default)]
struct CountingBodyValidationConsensus {
    body_validation_calls: AtomicUsize,
}

impl CountingBodyValidationConsensus {
    fn validate_body(
        &self,
        block: &SealedBlock<Block>,
        transaction_root: Option<B256>,
    ) -> Result<(), ConsensusError> {
        self.body_validation_calls.fetch_add(1, Ordering::Relaxed);
        let got = transaction_root.unwrap_or_else(|| block.body().calculate_tx_root());
        let expected = block.header().transactions_root;
        if got != expected {
            return Err(ConsensusError::BodyTransactionRootDiff(
                GotExpected { got, expected }.into(),
            ));
        }
        Ok(())
    }
}

impl HeaderValidator<Header> for CountingBodyValidationConsensus {
    fn requires_parent_state_validation(&self) -> bool {
        true
    }

    fn validate_header(&self, _header: &SealedHeader<Header>) -> Result<(), ConsensusError> {
        Ok(())
    }

    fn validate_header_against_parent(
        &self,
        _header: &SealedHeader<Header>,
        _parent: &SealedHeader<Header>,
    ) -> Result<(), ConsensusError> {
        panic!("engine validation must supply parent state")
    }

    fn validate_header_against_parent_with_state(
        &self,
        _header: &SealedHeader<Header>,
        _parent: &SealedHeader<Header>,
        _parent_state: &dyn StateProvider,
    ) -> Result<(), ConsensusError> {
        Ok(())
    }
}

impl Consensus<Block> for CountingBodyValidationConsensus {
    fn validate_body_against_header(
        &self,
        _body: &<Block as reth_primitives_traits::Block>::Body,
        _header: &SealedHeader<Header>,
    ) -> Result<(), ConsensusError> {
        Ok(())
    }

    fn validate_block_pre_execution(
        &self,
        block: &SealedBlock<Block>,
    ) -> Result<(), ConsensusError> {
        self.validate_body(block, None)
    }

    fn validate_block_pre_execution_with_tx_root(
        &self,
        block: &SealedBlock<Block>,
        transaction_root: Option<B256>,
    ) -> Result<(), ConsensusError> {
        self.validate_body(block, transaction_root)
    }
}

impl FullConsensus<EthPrimitives> for CountingBodyValidationConsensus {
    fn validate_block_post_execution(
        &self,
        _block: &RecoveredBlock<Block>,
        _result: &BlockExecutionResult<Receipt>,
        _receipt_root_bloom: Option<ReceiptRootBloom>,
        _block_access_list_hash: Option<B256>,
    ) -> Result<(), ConsensusError> {
        Ok(())
    }
}

#[test]
fn default_engine_path_execution_failure_runs_ordinary_parent_validation_exactly_once() {
    let consensus = Arc::new(DefaultParentValidationConsensus::default());
    let chain_spec = execution_test_chain_spec();
    let mut branch =
        TestBlockBuilder::eth().with_chain_spec(chain_spec.as_ref().clone()).with_state();
    let parent = branch.get_executed_block_with_number(1, chain_spec.genesis_hash());
    let candidate = branch.get_executed_block_with_number(2, parent.recovered_block().hash());
    let mut candidate = candidate.recovered_block().clone().into_sealed_block().unseal();
    let (transaction, _, hash) = candidate.body.transactions[0].clone().into_parts();
    candidate.body.transactions[0] = reth_ethereum_primitives::TransactionSigned::new(
        transaction,
        Signature::new(U256::ZERO, U256::ZERO, false),
        hash,
    );
    let candidate = candidate.seal_slow();
    let canonical_head = parent.recovered_block().num_hash();
    let result = validate_block_with_real_provider(
        chain_spec,
        Arc::clone(&consensus) as Arc<dyn FullConsensus<EthPrimitives>>,
        vec![parent],
        canonical_head,
        candidate,
    );

    assert_matches!(
        result,
        Err(InsertPayloadError::Block(error))
            if matches!(error.kind(), crate::tree::error::InsertBlockErrorKind::Execution(_))
    );
    assert_eq!(consensus.calls.load(Ordering::Relaxed), 1);
}

#[test]
fn opt_in_bad_body_precedes_execution_error() {
    let consensus = Arc::new(CountingBodyValidationConsensus::default());
    let chain_spec = execution_test_chain_spec();
    let mut branch =
        TestBlockBuilder::eth().with_chain_spec(chain_spec.as_ref().clone()).with_state();
    let parent = branch.get_executed_block_with_number(1, chain_spec.genesis_hash());
    let candidate = branch.get_executed_block_with_number(2, parent.recovered_block().hash());
    let mut candidate = candidate.recovered_block().clone().into_sealed_block().unseal();
    candidate.header.transactions_root = B256::ZERO;
    let (transaction, _, hash) = candidate.body.transactions[0].clone().into_parts();
    candidate.body.transactions[0] = reth_ethereum_primitives::TransactionSigned::new(
        transaction,
        Signature::new(U256::ZERO, U256::ZERO, false),
        hash,
    );
    let candidate = candidate.seal_slow();
    let canonical_head = parent.recovered_block().num_hash();
    let result = validate_block_with_real_provider(
        chain_spec,
        Arc::clone(&consensus) as Arc<dyn FullConsensus<EthPrimitives>>,
        vec![parent],
        canonical_head,
        candidate,
    );

    assert_matches!(
        result,
        Err(InsertPayloadError::Block(error))
            if matches!(
                error.kind(),
                crate::tree::error::InsertBlockErrorKind::Consensus(
                    ConsensusError::BodyTransactionRootDiff(_)
                )
            )
    );
    assert_eq!(consensus.body_validation_calls.load(Ordering::Relaxed), 1);
}

#[test]
fn opt_in_bad_body_after_successful_execution_is_rejected() {
    let consensus = Arc::new(CountingBodyValidationConsensus::default());
    let chain_spec = execution_test_chain_spec();
    let mut branch =
        TestBlockBuilder::eth().with_chain_spec(chain_spec.as_ref().clone()).with_state();
    let parent = branch.get_executed_block_with_number(1, chain_spec.genesis_hash());
    let candidate = branch.get_executed_block_with_number(2, parent.recovered_block().hash());
    let mut candidate = empty_child_candidate(&candidate, &parent).unseal();
    candidate.header.transactions_root = B256::ZERO;
    let candidate = candidate.seal_slow();
    let parent_hash = parent.recovered_block().hash();
    let result = validate_block_with_real_provider(
        chain_spec,
        Arc::clone(&consensus) as Arc<dyn FullConsensus<EthPrimitives>>,
        vec![parent],
        BlockNumHash::new(1, parent_hash),
        candidate,
    );

    assert_matches!(
        result,
        Err(InsertPayloadError::Block(error))
            if matches!(
                error.kind(),
                crate::tree::error::InsertBlockErrorKind::Consensus(
                    ConsensusError::BodyTransactionRootDiff(_)
                )
            )
    );
    assert_eq!(consensus.body_validation_calls.load(Ordering::Relaxed), 1);
}

#[test]
fn opt_in_suspicious_gas_bad_body_is_rejected_before_execution() {
    let consensus = Arc::new(CountingBodyValidationConsensus::default());
    let mut branch = TestBlockBuilder::eth().with_chain_spec(MAINNET.as_ref().clone()).with_state();
    let parent = branch.get_executed_block_with_number(1, B256::ZERO);
    let candidate = branch.get_executed_block_with_number(2, parent.recovered_block().hash());
    let mut candidate = candidate.recovered_block().clone().into_sealed_block().unseal();
    candidate.header.transactions_root = B256::ZERO;
    candidate.header.gas_used = candidate.header.gas_limit * 2 + 1;
    let candidate = candidate.seal_slow();
    let canonical_head = parent.recovered_block().num_hash();
    let mut harness = ValidatorTestHarness::new_with_consensus(MAINNET.clone(), consensus.clone())
        .with_unpersisted_fork_blocks(vec![parent], canonical_head);

    let result = harness.validate_block_direct(candidate);

    assert_matches!(
        result,
        Err(InsertPayloadError::Block(error))
            if matches!(
                error.kind(),
                crate::tree::error::InsertBlockErrorKind::Consensus(
                    ConsensusError::BodyTransactionRootDiff(_)
                )
            )
    );
    assert_eq!(consensus.body_validation_calls.load(Ordering::Relaxed), 1);
}
