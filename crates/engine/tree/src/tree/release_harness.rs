//! Joined tree-actor, database, persistence-writer and release-journal harness.
//!
//! The harness runs the real `EngineApiTreeHandler`, a real `ProviderFactory` with its
//! persistence service and pruner, and the real writer-fence journal in one process, so a
//! release capability obtained through it carries an actor-issued receipt. It is compiled
//! for this crate's tests and, behind `test-utils`, for downstream crates that join the actor
//! to their own durable release stores.

use crate::{
    engine::EngineApiKind,
    persistence::PersistenceHandle,
    tree::{
        BasicEngineValidator, EngineApiTreeHandler, EngineApiTreeState, PersistenceState,
        TreeConfig,
    },
    writer_fence::{
        AbortableRelease, ReleaseBinding, WriterFenceBootstrap, WriterFenceError,
        WriterFenceHandle, WriterFencePhase, WriterFenceState,
    },
};
use alloy_eips::{BlockNumHash, NumHash};
use alloy_primitives::{Bytes, B256};
use alloy_rpc_types_engine::ExecutionData;
use reth_chain_state::{test_utils::TestBlockBuilder, ExecutedBlock};
use reth_chainspec::{ChainSpec, MAINNET};
use reth_db::{init_db, mdbx::DatabaseArguments, test_utils::tempdir_path, Database, DatabaseEnv};
use reth_engine_primitives::{EngineApiValidator, NoopInvalidBlockHook};
use reth_ethereum_consensus::EthBeaconConsensus;
use reth_ethereum_engine_primitives::EthEngineTypes;
use reth_ethereum_primitives::{Block, EthPrimitives};
use reth_evm_ethereum::MockEvmConfig;
use reth_exex_types::FinishedExExHeight;
use reth_payload_builder::{PayloadBuilderHandle, PayloadServiceCommand};
use reth_primitives_traits::{Block as _, SealedHeader};
use reth_provider::{
    providers::{BlockchainProvider, RocksDBBuilder, StaticFileProvider},
    test_utils::MockNodeTypesWithDB,
    BalConfig, BalNotificationStream, BalStore, BalStoreHandle, BlockHashReader, BlockNumReader,
    HeaderProvider, InMemoryBalStore, ProviderFactory, ProviderResult, RawBal,
};
use reth_prune::Pruner;
use reth_prune_types::PruneMode;
use reth_storage_overlay::{ChangesetCache, OverlayManager};
use std::{
    fmt,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

/// Provider type of the joined harness: the actor and the persistence service share one
/// database.
pub type JoinedNodeTypes = MockNodeTypesWithDB<Arc<DatabaseEnv>>;
/// Provider type used by the joined harness and its restart path.
pub type JoinedProvider = BlockchainProvider<JoinedNodeTypes>;
/// Tree actor type of the joined harness.
pub type JoinedTree = EngineApiTreeHandler<
    EthPrimitives,
    JoinedProvider,
    EthEngineTypes,
    BasicEngineValidator<JoinedProvider, MockEvmConfig, MockEngineValidator>,
    MockEvmConfig,
>;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        Self(tempdir_path())
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The real tree actor, database, persistence writer and release journal in one process.
pub struct JoinedHarness {
    // Drop the actor and the last persistence handle before the factory cleans its TempDatabase.
    pub(crate) tree: JoinedTree,
    pub(crate) persistence: PersistenceHandle,
    pub(crate) factory: ProviderFactory<JoinedNodeTypes>,
    pub(crate) fence: WriterFenceHandle<EthEngineTypes>,
    pub(crate) journal: PathBuf,
    pub(crate) journal_identity: B256,
    pub(crate) expected: BlockNumHash,
    pub(crate) release_binding: ReleaseBinding,
    pub(crate) bal_store: BalStoreHandle,
    pub(crate) prune_calls: Arc<AtomicUsize>,
    expected_prune_calls: usize,
    pub(crate) old_bal_hash: B256,
    pub(crate) retained_bal_hash: B256,
    _datadir: Option<TestDirectory>,
    pub(crate) _events: UnboundedReceiver<crate::engine::EngineApiEvent>,
    pub(crate) _payload_commands: UnboundedReceiver<PayloadServiceCommand<EthEngineTypes>>,
}

/// What survives an actor shutdown: the journal path and the database directory that owns it.
pub struct JoinedRestart {
    journal: PathBuf,
    _factory: ProviderFactory<JoinedNodeTypes>,
    _datadir: Option<TestDirectory>,
}

impl fmt::Debug for JoinedHarness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JoinedHarness")
            .field("journal", &self.journal)
            .field("expected", &self.expected)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for JoinedRestart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JoinedRestart")
            .field("journal", &self.journal)
            .finish_non_exhaustive()
    }
}

impl JoinedRestart {
    /// Exact journal path of the stopped actor.
    pub fn journal(&self) -> &Path {
        &self.journal
    }
}

/// Payload validator that accepts every well-formed payload; the harness never executes one.
#[derive(Debug, Clone, Default)]
pub struct MockEngineValidator {
    conversion_calls: Option<Arc<AtomicUsize>>,
}

impl MockEngineValidator {
    /// Count payload conversions through the shared counter.
    pub fn with_conversion_counter(conversion_calls: Arc<AtomicUsize>) -> Self {
        Self { conversion_calls: Some(conversion_calls) }
    }
}

impl reth_engine_primitives::PayloadValidator<EthEngineTypes> for MockEngineValidator {
    type Block = Block;

    fn convert_payload_to_block(
        &self,
        payload: ExecutionData,
    ) -> Result<
        reth_primitives_traits::SealedBlock<Self::Block>,
        reth_payload_primitives::NewPayloadError,
    > {
        if let Some(conversion_calls) = &self.conversion_calls {
            conversion_calls.fetch_add(1, Ordering::Relaxed);
        }
        let block = reth_ethereum_primitives::Block::try_from(payload.payload).map_err(|e| {
            reth_payload_primitives::NewPayloadError::Other(format!("{e:?}").into())
        })?;
        Ok(block.seal_slow())
    }
}

impl EngineApiValidator<EthEngineTypes> for MockEngineValidator {
    fn validate_version_specific_fields(
        &self,
        _version: reth_payload_primitives::EngineApiMessageVersion,
        _payload_or_attrs: reth_payload_primitives::PayloadOrAttributes<
            '_,
            alloy_rpc_types_engine::ExecutionData,
            alloy_rpc_types_engine::PayloadAttributes,
        >,
    ) -> Result<(), reth_payload_primitives::EngineObjectValidationError> {
        Ok(())
    }

    fn ensure_well_formed_attributes(
        &self,
        _version: reth_payload_primitives::EngineApiMessageVersion,
        _attributes: &alloy_rpc_types_engine::PayloadAttributes,
    ) -> Result<(), reth_payload_primitives::EngineObjectValidationError> {
        Ok(())
    }
}

#[derive(Debug)]
struct ObservedBalStore {
    inner: InMemoryBalStore,
    prune_calls: Arc<AtomicUsize>,
}

impl BalStore for ObservedBalStore {
    fn insert(&self, block: NumHash, bal: RawBal) -> ProviderResult<()> {
        self.inner.insert(block, bal)
    }

    fn flush(&self) -> ProviderResult<()> {
        self.inner.flush()
    }

    fn prune(&self, tip: u64) -> ProviderResult<usize> {
        let result = self.inner.prune(tip)?;
        self.prune_calls.fetch_add(1, Ordering::Release);
        Ok(result)
    }

    fn get_by_hashes(&self, hashes: &[B256]) -> ProviderResult<Vec<Option<Bytes>>> {
        self.inner.get_by_hashes(hashes)
    }

    fn bal_stream(&self) -> BalNotificationStream {
        self.inner.bal_stream()
    }
}

impl JoinedHarness {
    /// Build the joined actor at a two-block chain with a queued child save that only the
    /// actor's release drain completes. The default release binding names fixed digests.
    pub fn new() -> Self {
        let mut blocks = TestBlockBuilder::eth().get_executed_blocks(0..2).collect::<Vec<_>>();
        let child = blocks.pop().unwrap();
        let genesis = blocks.pop().unwrap();
        Self::with_blocks(MAINNET.clone(), genesis, Some(child))
    }

    /// Start the real actor at a caller's fully materialized genesis state.
    ///
    /// The complete executed block is saved by the real persistence service
    /// before the actor is created. Its sealed header must equal the supplied
    /// chain specification's genesis; a caller cannot override only the fence
    /// binding or advance the persistence watermark without saving the state.
    pub fn from_persisted_genesis(
        chain_spec: Arc<ChainSpec>,
        genesis: ExecutedBlock<EthPrimitives>,
    ) -> Self {
        assert_eq!(genesis.recovered_block().number, 0);
        assert_eq!(genesis.recovered_block().hash(), chain_spec.genesis_header.hash());
        Self::with_blocks(chain_spec, genesis, None)
    }

    /// Start a joined actor in a caller-owned directory at a materialized genesis.
    ///
    /// The directory contains the database, static files, RocksDB state and writer-fence
    /// journal. A later process can reopen the same directory with [`Self::reopen_root`].
    pub fn from_persisted_genesis_at(
        root: impl AsRef<Path>,
        chain_spec: Arc<ChainSpec>,
        genesis: ExecutedBlock<EthPrimitives>,
    ) -> Self {
        let root = root.as_ref();
        let factory = Self::open_factory_at(root, chain_spec.clone());
        let (bal_store, prune_calls) = Self::new_bal_store();
        Self::with_external_factory(chain_spec, factory, bal_store, prune_calls, genesis, None)
    }

    /// Rebuild the actor around the database and journal left by a prior process.
    ///
    /// `bootstrap` must be the clean or already-reconciled pre-writer bootstrap. This method
    /// never creates or queues a genesis/child block; the persisted database head must already
    /// equal `expected`.
    pub fn reopen_root(
        root: impl AsRef<Path>,
        chain_spec: Arc<ChainSpec>,
        expected: BlockNumHash,
        bootstrap: WriterFenceBootstrap,
    ) -> Self {
        let root = root.as_ref();
        let factory = Self::open_factory_at(root, chain_spec.clone());
        let (bal_store, prune_calls) = Self::new_bal_store();
        let provider = BlockchainProvider::new(factory.clone()).unwrap();
        let last_number = provider.last_block_number().unwrap();
        let last_hash = provider.block_hash(last_number).unwrap().unwrap();
        assert_eq!(BlockNumHash::new(last_number, last_hash), expected);
        let head = provider.sealed_header_by_hash(expected.hash).unwrap().unwrap();
        let writer_state = WriterFenceState::from_bootstrap(bootstrap);
        let release_binding =
            ReleaseBinding::new(expected, B256::repeat_byte(0xa1), B256::repeat_byte(0xb2))
                .unwrap();
        Self::with_existing_factory(
            chain_spec,
            factory,
            bal_store,
            prune_calls,
            expected,
            head,
            release_binding,
            writer_state,
        )
    }

    /// Return the stable writer-fence journal location for a caller-owned root.
    pub fn journal_at(root: impl AsRef<Path>) -> PathBuf {
        root.as_ref().join("db/joined-release-fence/journal")
    }

    fn new_bal_store() -> (BalStoreHandle, Arc<AtomicUsize>) {
        let prune_calls = Arc::new(AtomicUsize::new(0));
        (
            BalStoreHandle::new(ObservedBalStore {
                inner: InMemoryBalStore::new(BalConfig::with_in_memory_retention(
                    PruneMode::Before(1),
                )),
                prune_calls: prune_calls.clone(),
            }),
            prune_calls,
        )
    }

    fn open_factory_at(
        root: &Path,
        chain_spec: Arc<ChainSpec>,
    ) -> ProviderFactory<JoinedNodeTypes> {
        std::fs::create_dir_all(root.join("static_files")).unwrap();
        let db = Arc::new(init_db(root.join("db"), DatabaseArguments::test()).unwrap());
        ProviderFactory::new(
            db,
            chain_spec,
            StaticFileProvider::read_write(root.join("static_files")).unwrap(),
            RocksDBBuilder::new(root.join("rocksdb")).with_default_tables().build().unwrap(),
            reth_tasks::Runtime::test(),
        )
        .unwrap()
    }

    fn with_external_factory(
        chain_spec: Arc<ChainSpec>,
        factory: ProviderFactory<JoinedNodeTypes>,
        bal_store: BalStoreHandle,
        prune_calls: Arc<AtomicUsize>,
        genesis: ExecutedBlock<EthPrimitives>,
        child: Option<ExecutedBlock<EthPrimitives>>,
    ) -> Self {
        let expected_prune_calls = if child.is_some() { 2 } else { 1 };
        let factory = factory.with_bal_store(bal_store.clone());
        let old_bal_hash = B256::random();
        let retained_bal_hash = B256::random();
        bal_store
            .insert(NumHash::new(0, old_bal_hash), RawBal::new(Bytes::from_static(b"old")))
            .unwrap();
        bal_store
            .insert(
                NumHash::new(1, retained_bal_hash),
                RawBal::new(Bytes::from_static(b"retained")),
            )
            .unwrap();
        let journal = factory.db_ref().path().join("joined-release-fence/journal");
        let writer_state = WriterFenceState::from_bootstrap(
            WriterFenceBootstrap::acquire(journal.clone()).unwrap(),
        );
        let clean_record = std::fs::read(&journal).unwrap();
        assert_eq!(clean_record.len(), 225);
        let journal_identity = B256::from_slice(&clean_record[161..193]);
        let (control_tx, control_rx) = crossbeam_channel::bounded(32);
        let fence = WriterFenceHandle::new(control_tx.clone(), writer_state.actor());
        let (_finished_tx, finished_rx) = tokio::sync::watch::channel(FinishedExExHeight::NoExExs);
        let pruner = Pruner::new_with_factory(factory.clone(), vec![], 0, 0, None, finished_rx);
        let (metrics_tx, _metrics_rx) = unbounded_channel();
        let persistence =
            PersistenceHandle::<EthPrimitives>::spawn_service(factory.clone(), pruner, metrics_tx);
        let persisted_genesis = genesis.recovered_block().num_hash();
        let head = child.as_ref().unwrap_or(&genesis).recovered_block().clone_sealed_header();
        let expected =
            child.as_ref().map_or(persisted_genesis, |block| block.recovered_block().num_hash());
        let release_binding =
            ReleaseBinding::new(expected, B256::repeat_byte(0xa1), B256::repeat_byte(0xb2))
                .unwrap();
        let (tx, rx) = crossbeam_channel::bounded(1);
        persistence.save_blocks(vec![genesis], tx).unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(10)).unwrap().last_block,
            Some(persisted_genesis)
        );
        let provider = BlockchainProvider::new(factory.clone()).unwrap();
        let canonical = provider.canonical_in_memory_state();
        canonical.set_canonical_head(head);
        let consensus = Arc::new(EthBeaconConsensus::new(chain_spec));
        let config = TreeConfig::default().with_has_enough_parallelism(true);
        let runtime = reth_tasks::Runtime::test();
        let overlays = OverlayManager::default();
        let changesets = ChangesetCache::new();
        let validator = BasicEngineValidator::new(
            provider.clone(),
            consensus.clone(),
            MockEvmConfig::default(),
            MockEngineValidator::default(),
            config.clone(),
            Box::new(NoopInvalidBlockHook::default()),
            changesets.clone(),
            overlays.clone(),
            runtime.clone(),
        );
        let (events_tx, events_rx) = unbounded_channel();
        let (payload_tx, payload_rx) = unbounded_channel();
        let mut tree = EngineApiTreeHandler::new(
            provider,
            consensus,
            validator,
            events_tx,
            EngineApiTreeState::new(
                10,
                10,
                config.invalid_header_hit_eviction_threshold(),
                expected,
                EngineApiKind::Ethereum,
                overlays,
            ),
            canonical,
            persistence.clone(),
            PersistenceState { last_persisted_block: persisted_genesis, rx: None },
            PayloadBuilderHandle::new(payload_tx),
            config,
            EngineApiKind::Ethereum,
            MockEvmConfig::default(),
            changesets,
            runtime,
            false,
            Arc::new(std::sync::atomic::AtomicU64::new(persisted_genesis.number)),
            writer_state,
            control_tx,
            control_rx,
        );
        if let Some(child) = child {
            tree.state.tree_state.insert_executed(child.clone());
            tree.persist_blocks(vec![child]);
            assert!(tree.persistence_state.in_progress());
        }
        Self {
            tree,
            persistence,
            factory,
            fence,
            journal,
            journal_identity,
            expected,
            release_binding,
            bal_store,
            prune_calls,
            expected_prune_calls,
            old_bal_hash,
            retained_bal_hash,
            _datadir: None,
            _events: events_rx,
            _payload_commands: payload_rx,
        }
    }

    fn with_existing_factory(
        chain_spec: Arc<ChainSpec>,
        factory: ProviderFactory<JoinedNodeTypes>,
        bal_store: BalStoreHandle,
        prune_calls: Arc<AtomicUsize>,
        expected: BlockNumHash,
        head: SealedHeader<alloy_consensus::Header>,
        release_binding: ReleaseBinding,
        writer_state: WriterFenceState,
    ) -> Self {
        let factory = factory.with_bal_store(bal_store.clone());
        let journal = factory.db_ref().path().join("joined-release-fence/journal");
        let clean_record = std::fs::read(&journal).unwrap();
        assert_eq!(clean_record.len(), 225);
        let journal_identity = B256::from_slice(&clean_record[161..193]);
        let (control_tx, control_rx) = crossbeam_channel::bounded(32);
        let fence = WriterFenceHandle::new(control_tx.clone(), writer_state.actor());
        let (_finished_tx, finished_rx) = tokio::sync::watch::channel(FinishedExExHeight::NoExExs);
        let pruner = Pruner::new_with_factory(factory.clone(), vec![], 0, 0, None, finished_rx);
        let (metrics_tx, _metrics_rx) = unbounded_channel();
        let persistence =
            PersistenceHandle::<EthPrimitives>::spawn_service(factory.clone(), pruner, metrics_tx);
        let provider = BlockchainProvider::new(factory.clone()).unwrap();
        let canonical = provider.canonical_in_memory_state();
        canonical.set_canonical_head(head);
        let consensus = Arc::new(EthBeaconConsensus::new(chain_spec));
        let config = TreeConfig::default().with_has_enough_parallelism(true);
        let runtime = reth_tasks::Runtime::test();
        let overlays = OverlayManager::default();
        let changesets = ChangesetCache::new();
        let validator = BasicEngineValidator::new(
            provider.clone(),
            consensus.clone(),
            MockEvmConfig::default(),
            MockEngineValidator::default(),
            config.clone(),
            Box::new(NoopInvalidBlockHook::default()),
            changesets.clone(),
            overlays.clone(),
            runtime.clone(),
        );
        let (events_tx, events_rx) = unbounded_channel();
        let (payload_tx, payload_rx) = unbounded_channel();
        let tree = EngineApiTreeHandler::new(
            provider,
            consensus,
            validator,
            events_tx,
            EngineApiTreeState::new(
                10,
                10,
                config.invalid_header_hit_eviction_threshold(),
                expected,
                EngineApiKind::Ethereum,
                overlays,
            ),
            canonical,
            persistence.clone(),
            PersistenceState { last_persisted_block: expected, rx: None },
            PayloadBuilderHandle::new(payload_tx),
            config,
            EngineApiKind::Ethereum,
            MockEvmConfig::default(),
            changesets,
            runtime,
            false,
            Arc::new(std::sync::atomic::AtomicU64::new(expected.number)),
            writer_state,
            control_tx,
            control_rx,
        );
        Self {
            tree,
            persistence,
            factory,
            fence,
            journal,
            journal_identity,
            expected,
            release_binding,
            bal_store,
            prune_calls,
            expected_prune_calls: 0,
            old_bal_hash: B256::ZERO,
            retained_bal_hash: B256::ZERO,
            _datadir: None,
            _events: events_rx,
            _payload_commands: payload_rx,
        }
    }

    fn with_blocks(
        chain_spec: Arc<ChainSpec>,
        genesis: ExecutedBlock<EthPrimitives>,
        child: Option<ExecutedBlock<EthPrimitives>>,
    ) -> Self {
        let expected_prune_calls = if child.is_some() { 2 } else { 1 };
        let prune_calls = Arc::new(AtomicUsize::new(0));
        let bal_store = BalStoreHandle::new(ObservedBalStore {
            inner: InMemoryBalStore::new(BalConfig::with_in_memory_retention(PruneMode::Before(1))),
            prune_calls: prune_calls.clone(),
        });
        let old_bal_hash = B256::random();
        let retained_bal_hash = B256::random();
        bal_store
            .insert(NumHash::new(0, old_bal_hash), RawBal::new(Bytes::from_static(b"old")))
            .unwrap();
        bal_store
            .insert(
                NumHash::new(1, retained_bal_hash),
                RawBal::new(Bytes::from_static(b"retained")),
            )
            .unwrap();
        let datadir = TestDirectory::new();
        let factory = Self::open_factory_at(datadir.path(), chain_spec.clone())
            .with_bal_store(bal_store.clone());
        // This is inside the TempDatabase's unique, automatically cleaned data directory.
        // The test runner's scratch routing determines where that directory is allocated.
        let journal = factory.db_ref().path().join("joined-release-fence/journal");
        let writer_state = WriterFenceState::from_bootstrap(
            WriterFenceBootstrap::acquire(journal.clone()).unwrap(),
        );
        let clean_record = std::fs::read(&journal).unwrap();
        assert_eq!(clean_record.len(), 225);
        let journal_identity = B256::from_slice(&clean_record[161..193]);
        let (control_tx, control_rx) = crossbeam_channel::bounded(32);
        let fence = WriterFenceHandle::new(control_tx.clone(), writer_state.actor());
        let (_finished_tx, finished_rx) = tokio::sync::watch::channel(FinishedExExHeight::NoExExs);
        let pruner = Pruner::new_with_factory(factory.clone(), vec![], 0, 0, None, finished_rx);
        let (metrics_tx, _metrics_rx) = unbounded_channel();
        let persistence =
            PersistenceHandle::<EthPrimitives>::spawn_service(factory.clone(), pruner, metrics_tx);

        let persisted_genesis = genesis.recovered_block().num_hash();
        let head = child.as_ref().unwrap_or(&genesis).recovered_block().clone_sealed_header();
        let expected =
            child.as_ref().map_or(persisted_genesis, |block| block.recovered_block().num_hash());
        let release_binding =
            ReleaseBinding::new(expected, B256::repeat_byte(0xa1), B256::repeat_byte(0xb2))
                .unwrap();
        let (tx, rx) = crossbeam_channel::bounded(1);
        persistence.save_blocks(vec![genesis], tx).unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(10)).unwrap().last_block,
            Some(persisted_genesis)
        );

        let provider = BlockchainProvider::new(factory.clone()).unwrap();
        let canonical = provider.canonical_in_memory_state();
        canonical.set_canonical_head(head);
        let consensus = Arc::new(EthBeaconConsensus::new(chain_spec));
        let config = TreeConfig::default().with_has_enough_parallelism(true);
        let runtime = reth_tasks::Runtime::test();
        let overlays = OverlayManager::default();
        let changesets = ChangesetCache::new();
        let validator = BasicEngineValidator::new(
            provider.clone(),
            consensus.clone(),
            MockEvmConfig::default(),
            MockEngineValidator::default(),
            config.clone(),
            Box::new(NoopInvalidBlockHook::default()),
            changesets.clone(),
            overlays.clone(),
            runtime.clone(),
        );
        let (events_tx, events_rx) = unbounded_channel();
        let (payload_tx, payload_rx) = unbounded_channel();
        let mut tree = EngineApiTreeHandler::new(
            provider,
            consensus,
            validator,
            events_tx,
            EngineApiTreeState::new(
                10,
                10,
                config.invalid_header_hit_eviction_threshold(),
                expected,
                EngineApiKind::Ethereum,
                overlays,
            ),
            canonical,
            persistence.clone(),
            PersistenceState { last_persisted_block: persisted_genesis, rx: None },
            PayloadBuilderHandle::new(payload_tx),
            config,
            EngineApiKind::Ethereum,
            MockEvmConfig::default(),
            changesets,
            runtime,
            false,
            Arc::new(std::sync::atomic::AtomicU64::new(persisted_genesis.number)),
            writer_state,
            control_tx,
            control_rx,
        );
        if let Some(child) = child {
            tree.state.tree_state.insert_executed(child.clone());
            // Queue a real save and leave its response to the actor's release drain.
            tree.persist_blocks(vec![child]);
            assert!(tree.persistence_state.in_progress());
        }
        Self {
            tree,
            persistence,
            factory,
            fence,
            journal,
            journal_identity,
            expected,
            release_binding,
            bal_store,
            prune_calls,
            expected_prune_calls,
            old_bal_hash,
            retained_bal_hash,
            _datadir: Some(datadir),
            _events: events_rx,
            _payload_commands: payload_rx,
        }
    }

    /// Exact canonical head the actor fences: the queued child block.
    pub const fn expected(&self) -> BlockNumHash {
        self.expected
    }

    /// Binding used by [`Self::acquire`].
    pub const fn release_binding(&self) -> ReleaseBinding {
        self.release_binding
    }

    /// Exact journal path retained by the actor.
    pub fn journal_path(&self) -> &Path {
        &self.journal
    }

    /// A clone of the actor-issued writer-fence handle.
    pub fn fence(&self) -> WriterFenceHandle<EthEngineTypes> {
        self.fence.clone()
    }

    /// Whether the actor is idle, so ordinary canonical ingress is open again.
    pub fn is_idle(&self) -> bool {
        matches!(self.tree.writer_fence.phase(), WriterFencePhase::Idle)
    }

    /// Whether the actor holds an armed release.
    pub fn is_armed(&self) -> bool {
        matches!(self.tree.writer_fence.phase(), WriterFencePhase::ReleaseCommitArmed { .. })
    }

    /// Whether the actor is faulted.
    pub fn is_faulted(&self) -> bool {
        matches!(self.tree.writer_fence.phase(), WriterFencePhase::Faulted)
    }

    /// Let the real actor process exactly one queued writer-fence request, then await the
    /// caller that produced it.
    pub async fn drive<R>(&mut self, caller: tokio::task::JoinHandle<R>) -> R {
        tokio::task::yield_now().await;
        let request =
            self.tree.writer_fence_incoming.recv_timeout(Duration::from_secs(10)).unwrap();
        self.tree
            .on_writer_fence_request(request)
            .expect("joined writer-fence request is non-fatal");
        tokio::time::timeout(Duration::from_secs(10), caller).await.unwrap().unwrap()
    }

    /// Pump real actor requests until a composed asynchronous release operation finishes.
    pub async fn drive_until<R>(&mut self, mut caller: tokio::task::JoinHandle<R>) -> R {
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                while let Ok(request) = self.tree.writer_fence_incoming.try_recv() {
                    self.tree
                        .on_writer_fence_request(request)
                        .expect("joined writer-fence request is non-fatal");
                }
                tokio::select! {
                    result = &mut caller => return result.expect("joined caller completes"),
                    _ = tokio::time::sleep(Duration::from_millis(1)) => {}
                }
            }
        })
        .await
        .expect("joined release operation completes within its deadline")
    }

    /// Open qualified ingress and acquire the release fence for the default binding.
    pub async fn acquire(&mut self) -> AbortableRelease<EthEngineTypes> {
        let binding = self.release_binding;
        self.acquire_with(binding).await
    }

    /// Open qualified ingress and acquire the release fence for one exact binding at the
    /// harness head, draining the queued child save through the real persistence writer.
    pub async fn acquire_with(
        &mut self,
        binding: ReleaseBinding,
    ) -> AbortableRelease<EthEngineTypes> {
        assert_eq!(binding.canonical_parent(), self.expected, "binding names the actor head");
        self.release_binding = binding;
        let open = tokio::spawn({
            let handle = self.fence.clone();
            async move { handle.open_qualified_ingress().await }
        });
        self.drive(open).await.unwrap();
        let acquire = tokio::spawn({
            let handle = self.fence.clone();
            async move { handle.acquire_release(binding).await }
        });
        let token = self.drive(acquire).await.unwrap();
        assert_eq!(token.binding(), binding);
        assert!(!self.tree.persistence_state.in_progress());
        assert_eq!(self.tree.persistence_state.last_persisted_block, self.expected);
        self.assert_exact_database_head();
        // Inserts may also prune this store. Count the actual service prune calls separately:
        // Every actual save, including the optional drained child, must finish pruning.
        assert_eq!(self.prune_calls.load(Ordering::Acquire), self.expected_prune_calls);
        assert_eq!(
            self.bal_store.get_by_hashes(&[self.old_bal_hash, self.retained_bal_hash]).unwrap(),
            vec![None, Some(Bytes::from_static(b"retained"))]
        );
        token
    }

    /// Read the actual durable head before selecting a restart branch.
    pub fn persisted_head_at(root: impl AsRef<Path>, chain_spec: Arc<ChainSpec>) -> BlockNumHash {
        let factory = Self::open_factory_at(root.as_ref(), chain_spec);
        let provider = factory.provider().expect("persisted head provider");
        let number = provider.last_block_number().expect("persisted number");
        let hash = provider.block_hash(number).expect("persisted hash read").expect("persisted hash");
        BlockNumHash::new(number, hash)
    }

    /// Read a numbered header from the persisted Engine database.
    pub fn persisted_header(&self, number: u64) -> Option<SealedHeader<alloy_consensus::Header>> {
        self.factory.provider().expect("persisted header provider")
            .sealed_header(number).expect("persisted header read")
    }

    /// Read callback storage from the real persisted canonical state.
    pub fn persisted_storage(&self, address: alloy_primitives::Address, key: B256) -> alloy_primitives::U256 {
        use reth_provider::StateProvider;
        self.factory.latest().expect("persisted state provider")
            .storage(address, key).expect("persisted storage read").unwrap_or_default()
    }

    /// Publish an audited executed child through direct admission and tagged FCU,
    /// then drain the real persistence service before returning its durable identity.
    pub async fn publish_and_persist(&mut self, block: ExecutedBlock<EthPrimitives>) -> BlockNumHash {
        use crate::engine::{DirectInsertBlockIdentity, ExecutedBlockInsertSender, EngineApiRequest, FromEngine};
        use alloy_rpc_types_engine::ForkchoiceState;
        let parent = self.expected;
        let child = block.recovered_block().num_hash();
        if matches!(self.tree.writer_fence.phase(), WriterFencePhase::BootClosed) {
            let open = tokio::spawn({
                let handle = self.fence.clone();
                async move { handle.open_qualified_ingress().await }
            });
            self.drive(open).await.expect("qualified publication ingress");
        }
        assert!(self.is_idle(), "publication requires idle actor");
        assert!(!self.tree.writer_fence.untagged_forkchoice_allowed(), "qualified actor required");
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let sender = ExecutedBlockInsertSender::new(sender, 1);
        let insert = tokio::spawn(async move {
            sender.insert(DirectInsertBlockIdentity { expected_parent: parent, block: child }, block).await
        });
        let request = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
            .await.expect("direct insertion queued").expect("direct insertion request");
        let _ = self.tree.on_engine_message(FromEngine::Request(
            EngineApiRequest::InsertExecutedBlockIfCanonical(request),
        )).expect("real direct admission");
        insert.await.expect("insert task").expect("admitted executed child");
        let state = ForkchoiceState {
            head_block_hash: child.hash,
            safe_block_hash: child.hash,
            finalized_block_hash: child.hash,
        };
        let begin = tokio::spawn({
            let handle = self.fence.clone();
            async move { handle.begin_publication(parent, child, state).await }
        });
        let mut publication = self.drive(begin).await.expect("publication reservation");
        let tagged = tokio::spawn(async move {
            let response = publication.forkchoice_updated(None).await;
            (publication, response)
        });
        let (publication, response) = self.drive(tagged).await;
        assert!(response.expect("tagged forkchoice").payload_status.is_valid());
        self.drive(tokio::spawn(async move { publication.finish(child).await }))
            .await.expect("finish native handoff");
        self.expected = child;
        let binding = ReleaseBinding::new(child, B256::repeat_byte(0xe1), B256::repeat_byte(0xe2))
            .expect("persistence drain binding");
        let acquire = tokio::spawn({
            let handle = self.fence.clone();
            async move { handle.acquire_release(binding).await }
        });
        let release = self.drive(acquire).await.expect("drain published canonical child");
        self.assert_exact_database_head();
        self.drive(tokio::spawn(async move { release.abort().await }))
            .await.expect("resolve drain fence");
        self.assert_journal(0);
        child
    }

    /// The database, provider and tree all agree on the exact fenced head.
    pub fn assert_exact_database_head(&self) {
        let db = self.factory.provider().unwrap();
        assert_eq!(db.best_block_number().unwrap(), self.expected.number);
        assert_eq!(db.block_hash(self.expected.number).unwrap(), Some(self.expected.hash));
        assert_eq!(db.last_block_number().unwrap(), self.expected.number);
        assert_eq!(self.tree.exact_provider_head().unwrap(), self.expected);
        assert_eq!(*self.tree.state.tree_state.canonical_head(), self.expected);
    }

    /// The real persistence writer refuses every canonical mutation.
    pub fn assert_writer_closed(&self) {
        let clone = self.persistence.clone();
        let (tx, _rx) = crossbeam_channel::bounded(1);
        assert!(clone.remove_blocks_above(0, tx).is_err());
        let (tx, _rx) = crossbeam_channel::bounded(1);
        assert!(clone.save_blocks(vec![], tx).is_err());
        assert!(clone.save_safe_block_number(0).is_err());
        self.assert_exact_database_head();
    }

    /// The real persistence writer accepts a canonical mutation again.
    pub fn assert_writer_reopened(&self) {
        let (tx, rx) = crossbeam_channel::bounded(1);
        self.persistence.clone().remove_blocks_above(0, tx).unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(10)).unwrap().last_block.unwrap().number, 0);
    }

    pub(crate) fn operation(&self) -> u64 {
        match self.tree.writer_fence.phase() {
            WriterFencePhase::ReleaseHeldAbortable { operation, binding, .. }
            | WriterFencePhase::ReleaseCommitArmed { operation, binding, .. } => {
                assert_eq!(*binding, self.release_binding);
                *operation
            }
            phase => panic!("unexpected release phase: {phase:?}"),
        }
    }

    /// Check the persisted journal format, local-directory binding and checksum for the
    /// given state byte (0 Clean, 1 Intent, 2 Armed).
    pub fn assert_journal(&self, state: u8) {
        let bytes = std::fs::read(&self.journal).unwrap();
        assert_eq!(bytes.len(), 225);
        assert_eq!(&bytes[..8], b"RWFENCE2");
        assert_eq!(bytes[8], state);
        let (actor, operation, parent, release_digest, plan_digest, nonce) = if state == 0 {
            (0, 0, BlockNumHash::new(0, B256::ZERO), B256::ZERO, B256::ZERO, B256::ZERO)
        } else {
            let nonce = match self.tree.writer_fence.phase() {
                WriterFencePhase::ReleaseHeldAbortable { nonce, .. }
                | WriterFencePhase::ReleaseCommitArmed { nonce, .. } => *nonce,
                phase => panic!("unexpected journal phase: {phase:?}"),
            };
            (
                self.tree.writer_fence.actor(),
                self.operation(),
                self.release_binding.canonical_parent(),
                self.release_binding.release_digest(),
                self.release_binding.plan_digest(),
                nonce,
            )
        };
        assert_eq!(u64::from_le_bytes(bytes[9..17].try_into().unwrap()), actor);
        assert_eq!(u64::from_le_bytes(bytes[17..25].try_into().unwrap()), operation);
        assert_eq!(u64::from_le_bytes(bytes[25..33].try_into().unwrap()), parent.number);
        assert_eq!(&bytes[33..65], parent.hash.as_slice());
        assert_eq!(&bytes[65..97], release_digest.as_slice());
        assert_eq!(&bytes[97..129], plan_digest.as_slice());
        assert_eq!(&bytes[129..161], nonce.as_slice());
        assert_eq!(&bytes[161..193], self.journal_identity.as_slice());
        assert_eq!(&bytes[193..], alloy_primitives::keccak256(&bytes[..193]).as_slice());
    }

    /// Stop the actor and the persistence writer as a crash would, keeping the database
    /// directory (and therefore the journal) alive for a restart through the pre-writer
    /// bootstrap.
    pub fn shutdown_actor(self) -> JoinedRestart {
        let Self { tree, persistence, factory, journal, _datadir, .. } = self;
        drop(tree);
        // ServiceGuard joins the real writer once this final handle is dropped.
        drop(persistence);
        JoinedRestart { journal, _factory: factory, _datadir }
    }

    /// A clean journal restarts through the pre-writer bootstrap.
    pub fn assert_clean_restart(self) {
        self.assert_journal(0);
        let restart = self.shutdown_actor();
        let bootstrap = WriterFenceBootstrap::acquire(restart.journal.clone()).unwrap();
        assert!(restart.journal.is_file());
        drop(bootstrap);
        drop(restart);
    }

    /// Restart refuses an unresolved Armed record.
    pub fn assert_restart_refused(self) {
        self.assert_restart_refused_for("unresolved release fence record Armed");
    }

    /// Restart refuses with the given journal message.
    pub fn assert_restart_refused_for(self, expected_message: &str) {
        let restart = self.shutdown_actor();
        match WriterFenceBootstrap::acquire(restart.journal.clone()) {
            Err(WriterFenceError::Journal { message }) => {
                assert!(message.contains(expected_message), "{message}");
            }
            other => panic!("restart must refuse the unresolved or missing journal: {other:?}"),
        }
        // Keep the unique TempDatabase and journal alive through the restart read.
        drop(restart);
    }
}

impl Default for JoinedHarness {
    fn default() -> Self {
        Self::new()
    }
}
