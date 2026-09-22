use crate::metrics::PersistenceMetrics;
use alloy_eips::BlockNumHash;
use crossbeam_channel::Sender as CrossbeamSender;
use reth_chain_state::ExecutedBlock;
use reth_errors::ProviderError;
use reth_ethereum_primitives::EthPrimitives;
use reth_primitives_traits::{FastInstant as Instant, NodePrimitives};
use reth_provider::{
    providers::ProviderNodeTypes, BalProvider, BlockExecutionWriter, BlockHashReader,
    BlockNumReader, CanonicalSnapshotError, CanonicalSnapshotRequest, CanonicalSnapshotResult,
    ChainStateBlockWriter, DBProvider, DatabaseProviderFactory, ProviderFactory, SaveBlocksMode,
};
use reth_prune::{PrunerError, PrunerWithFactory};
use reth_stages_api::{MetricEvent, MetricEventsSender};
use reth_tasks::spawn_os_thread;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, SendError, Sender},
        Arc,
    },
    thread::JoinHandle,
    time::Duration,
};
use thiserror::Error;
use tracing::{debug, error, instrument, warn};

/// Unified result of any persistence operation.
#[derive(Debug)]
pub struct PersistenceResult {
    /// The last block that was persisted, if any.
    pub last_block: Option<BlockNumHash>,
    /// The commit duration, only available for save-blocks operations.
    pub commit_duration: Option<Duration>,
}

/// Writes parts of reth's in memory tree state to the database and static files.
///
/// This is meant to be a spawned service that listens for various incoming persistence operations,
/// performing those actions on disk, and returning the result in a channel.
///
/// This should be spawned in its own thread with [`std::thread::spawn`], since this performs
/// blocking I/O operations in an endless loop.
#[derive(Debug)]
pub struct PersistenceService<N>
where
    N: ProviderNodeTypes,
{
    /// The provider factory to use
    provider: ProviderFactory<N>,
    /// Incoming requests
    incoming: Receiver<PersistenceAction<N::Primitives>>,
    /// The pruner
    pruner: PrunerWithFactory<ProviderFactory<N>>,
    /// metrics
    metrics: PersistenceMetrics,
    /// Sender for sync metrics - we only submit sync metrics for persisted blocks
    sync_metrics_tx: MetricEventsSender,
    /// Pending finalized block number to be committed with the next block save.
    /// This avoids triggering a separate fsync for each finalized block update.
    pending_finalized_block: Option<u64>,
    /// Pending safe block number to be committed with the next block save.
    /// This avoids triggering a separate fsync for each safe block update.
    pending_safe_block: Option<u64>,
    /// Exactly one owner may hold the writer. Dropped acknowledgements do not release it.
    release_fence: Option<(u64, BlockNumHash)>,
    /// A storage fault cannot be cleared by an ordinary release request.
    release_fence_fault: Option<ReleaseFenceError>,
    /// Fast admission refusal shared with production handle clones. The service checks again.
    writer_closed: Arc<AtomicBool>,
}

impl<N> PersistenceService<N>
where
    N: ProviderNodeTypes,
{
    /// Create a new persistence service
    pub fn new(
        provider: ProviderFactory<N>,
        incoming: Receiver<PersistenceAction<N::Primitives>>,
        pruner: PrunerWithFactory<ProviderFactory<N>>,
        sync_metrics_tx: MetricEventsSender,
    ) -> Self {
        Self {
            provider,
            incoming,
            pruner,
            metrics: PersistenceMetrics::default(),
            sync_metrics_tx,
            pending_finalized_block: None,
            pending_safe_block: None,
            release_fence: None,
            release_fence_fault: None,
            writer_closed: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl<N> PersistenceService<N>
where
    N: ProviderNodeTypes,
{
    /// This is the main loop, that will listen to database events and perform the requested
    /// database actions
    pub fn run(mut self) -> Result<(), PersistenceError> {
        // If the receiver errors then senders have disconnected, so the loop should then end.
        while let Ok(action) = self.incoming.recv() {
            if self.writer_is_closed() && action.mutates_canonical_storage() {
                // Existing save/remove acknowledgements cannot carry errors. Disconnect them,
                // which the tree already treats as persistence failure, without touching storage.
                warn!(target: "engine::persistence", "Refusing mutation while release writer is fenced");
                continue;
            }
            match action {
                PersistenceAction::ReleaseFence(PersistenceReleaseFenceRequest {
                    operation,
                    tx,
                }) => {
                    let result = match operation {
                        ReleaseFenceOperation::Acquire { id, expected } => {
                            self.on_acquire_release_fence(id, expected)
                        }
                        ReleaseFenceOperation::Release { id } => self.on_release_release_fence(id),
                    };
                    // A lost acquisition receiver leaves the fence held. Only an explicit
                    // engine-owned release command may reopen it.
                    let _ = tx.try_send(result);
                }
                PersistenceAction::RemoveBlocksAbove(new_tip_num, sender) => {
                    let last_block = self.on_remove_blocks_above(new_tip_num)?;
                    // send new sync metrics based on removed blocks
                    let _ =
                        self.sync_metrics_tx.send(MetricEvent::SyncHeight { height: new_tip_num });
                    let _ = sender.send(PersistenceResult { last_block, commit_duration: None });
                }
                PersistenceAction::SaveBlocks(blocks, sender) => {
                    let result = self.on_save_blocks(blocks)?;
                    let result_number = result.last_block.map(|b| b.number);

                    let _ = sender.send(result);

                    if let Some(block_number) = result_number {
                        // send new sync metrics based on saved blocks
                        let _ = self
                            .sync_metrics_tx
                            .send(MetricEvent::SyncHeight { height: block_number });
                        self.maybe_run_pruner(block_number)?;
                    }
                }
                PersistenceAction::SaveFinalizedBlock(finalized_block) => {
                    self.pending_finalized_block = Some(finalized_block);
                }
                PersistenceAction::SaveSafeBlock(safe_block) => {
                    self.pending_safe_block = Some(safe_block);
                }
                PersistenceAction::ExportCanonicalSnapshot(request, tx) => {
                    // Capture the static-file boundary here, on the single-threaded
                    // persistence writer between saves, so no append is in flight
                    // and the lengths are a consistent cut of complete rows.
                    // The minutes-long copy (a consistent MDBX MVCC copy plus the
                    // truncated static-file copy) then runs on a separate thread so
                    // this writer is released immediately and consensus is not
                    // stalled. The MVCC copy is internally consistent, but does not by
                    // itself prove agreement with this earlier static-file boundary.
                    // Holding a release fence through export completion prevents this
                    // service from changing either store; acquisition alone does not
                    // wait for a detached copy or extend its lifetime.
                    match self.provider.capture_static_file_lengths() {
                        Ok(static_file_lengths) => {
                            let provider = self.provider.clone();
                            // Detached: the export replies on `tx` when it finishes.
                            let _ = spawn_os_thread("canonical-snapshot-export", move || {
                                let result = provider
                                    .export_canonical_snapshot(&request, &static_file_lengths);
                                if let Err(ref error) = result {
                                    debug!(target: "engine::persistence", %error, "Canonical snapshot export refused or failed");
                                }
                                let _ = tx.send(result);
                            });
                        }
                        Err(error) => {
                            error!(target: "engine::persistence", %error, "Failed to capture static-file boundary for snapshot export");
                            let _ = tx.send(Err(error));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn writer_is_closed(&self) -> bool {
        self.release_fence.is_some() || self.release_fence_fault.is_some()
    }

    fn fence_storage_fault(&mut self, error: ReleaseFenceError) -> ReleaseFenceError {
        self.writer_closed.store(true, Ordering::Release);
        self.release_fence_fault = Some(error.clone());
        error
    }

    fn verify_release_head(&self, expected: BlockNumHash) -> Result<(), ReleaseFenceError> {
        let provider = self.provider.provider().map_err(ReleaseFenceError::storage)?;
        let best = provider.best_block_number().map_err(ReleaseFenceError::storage)?;
        let actual = provider
            .block_hash(best)
            .map_err(ReleaseFenceError::storage)?
            .map(|hash| BlockNumHash::new(best, hash));
        let static_tip = provider.last_block_number().map_err(ReleaseFenceError::storage)?;
        if actual != Some(expected) || static_tip != expected.number {
            return Err(ReleaseFenceError::HeadMismatch { expected, actual, static_tip });
        }
        Ok(())
    }

    fn on_acquire_release_fence(
        &mut self,
        id: u64,
        expected: BlockNumHash,
    ) -> Result<(), ReleaseFenceError> {
        if let Some(error) = &self.release_fence_fault {
            return Err(error.clone());
        }
        if self.release_fence.is_some() {
            return Err(ReleaseFenceError::Busy);
        }
        if self.pending_finalized_block.is_some_and(|n| n > expected.number) ||
            self.pending_safe_block.is_some_and(|n| n > expected.number)
        {
            return Err(ReleaseFenceError::PendingMetadataAhead);
        }
        self.writer_closed.store(true, Ordering::Release);
        if let Err(error) = self.verify_release_head(expected) {
            if matches!(error, ReleaseFenceError::Storage(_)) {
                return Err(self.fence_storage_fault(error));
            }
            self.writer_closed.store(false, Ordering::Release);
            return Err(error);
        }

        // Safe/finalized updates are normally deferred until the next save. A successful fence
        // instead commits all preceding metadata here; values ahead of the head were refused.
        if self.pending_finalized_block.is_some() || self.pending_safe_block.is_some() {
            let result = (|| -> Result<(), ProviderError> {
                let provider = self.provider.database_provider_rw()?;
                if let Some(number) = self.pending_finalized_block {
                    provider.save_finalized_block_number(number)?;
                }
                if let Some(number) = self.pending_safe_block {
                    provider.save_safe_block_number(number)?;
                }
                provider.commit()?;
                Ok(())
            })();
            if let Err(error) = result {
                return Err(self.fence_storage_fault(ReleaseFenceError::storage(error)));
            }
            self.pending_finalized_block = None;
            self.pending_safe_block = None;
        }
        self.release_fence = Some((id, expected));
        Ok(())
    }

    fn on_release_release_fence(&mut self, id: u64) -> Result<(), ReleaseFenceError> {
        if let Some(error) = &self.release_fence_fault {
            return Err(error.clone());
        }
        let Some((held_id, expected)) = self.release_fence else {
            return Err(ReleaseFenceError::NotHeld);
        };
        if held_id != id {
            return Err(ReleaseFenceError::WrongOwner);
        }
        if let Err(error) = self.verify_release_head(expected) {
            return Err(self.fence_storage_fault(error));
        }
        self.release_fence = None;
        self.writer_closed.store(false, Ordering::Release);
        Ok(())
    }

    #[instrument(level = "debug", target = "engine::persistence", skip_all, fields(%new_tip_num))]
    fn on_remove_blocks_above(
        &self,
        new_tip_num: u64,
    ) -> Result<Option<BlockNumHash>, PersistenceError> {
        if self.writer_is_closed() {
            return Err(PersistenceError::ReleaseFenceClosed);
        }
        debug!(target: "engine::persistence", ?new_tip_num, "Removing blocks");
        let start_time = Instant::now();
        let provider_rw = self.provider.database_provider_rw()?;

        let new_tip_hash = provider_rw.block_hash(new_tip_num)?;
        provider_rw.remove_block_and_execution_above(new_tip_num)?;
        provider_rw.commit()?;

        debug!(target: "engine::persistence", ?new_tip_num, ?new_tip_hash, "Removed blocks from disk");
        self.metrics.remove_blocks_above_duration_seconds.record(start_time.elapsed());
        Ok(new_tip_hash.map(|hash| BlockNumHash { hash, number: new_tip_num }))
    }

    #[instrument(level = "debug", target = "engine::persistence", skip_all, fields(block_count = blocks.len()))]
    fn on_save_blocks(
        &mut self,
        blocks: Vec<ExecutedBlock<N::Primitives>>,
    ) -> Result<PersistenceResult, PersistenceError> {
        if self.writer_is_closed() {
            return Err(PersistenceError::ReleaseFenceClosed);
        }
        let first_block = blocks.first().map(|b| b.recovered_block.num_hash());
        let last_block = blocks.last().map(|b| b.recovered_block.num_hash());
        let block_count = blocks.len();

        debug!(target: "engine::persistence", ?block_count, first=?first_block, last=?last_block, "Saving range of blocks");

        let start_time = Instant::now();

        if let Some(last) = last_block {
            let pending_finalized = self.pending_finalized_block.take();
            let pending_safe = self.pending_safe_block.take();
            let provider_rw = self.provider.database_provider_rw()?;
            provider_rw.save_blocks(blocks, SaveBlocksMode::Full)?;

            if let Some(finalized) = pending_finalized {
                provider_rw.save_finalized_block_number(finalized.min(last.number))?;
                if finalized > last.number {
                    self.pending_finalized_block = Some(finalized);
                }
            }
            if let Some(safe) = pending_safe {
                provider_rw.save_safe_block_number(safe.min(last.number))?;
                if safe > last.number {
                    self.pending_safe_block = Some(safe);
                }
            }

            provider_rw.commit()?;
            if let Err(err) = self.provider.bal_store().flush() {
                warn!(target: "engine::persistence", last=?last_block, ?err, "Failed to flush BAL store");
                self.fence_storage_fault(ReleaseFenceError::storage(err));
            }
            debug!(target: "engine::persistence", first=?first_block, last=?last_block, "Saved range of blocks");
        }

        let elapsed = start_time.elapsed();
        self.metrics.save_blocks_batch_size.record(block_count as f64);
        self.metrics.save_blocks_duration_seconds.record(elapsed);

        Ok(PersistenceResult { last_block, commit_duration: Some(elapsed) })
    }

    fn maybe_run_pruner(&mut self, block_number: u64) -> Result<(), PersistenceError> {
        if self.writer_is_closed() {
            return Err(PersistenceError::ReleaseFenceClosed);
        }
        // The durable save is already committed at this point, so pruning can happen after we
        // acknowledge the save without extending the synchronous persistence wait.
        if self.pruner.is_pruning_needed(block_number) {
            debug!(target: "engine::persistence", block_num=?block_number, "Running pruner");
            let prune_start = Instant::now();
            let provider_rw = self.provider.database_provider_rw()?;
            let _ = self.pruner.run_with_provider(&provider_rw, block_number)?;
            provider_rw.commit()?;
            let pruned_bals = match self.provider.bal_store().prune(block_number) {
                Ok(pruned) => pruned,
                Err(err) => {
                    warn!(target: "engine::persistence", tip=?block_number, ?err, "Failed to prune BAL store");
                    self.fence_storage_fault(ReleaseFenceError::storage(err));
                    0
                }
            };
            debug!(target: "engine::persistence", tip=?block_number, pruned_bals, "Finished pruning after saving blocks");
            self.metrics.prune_before_duration_seconds.record(prune_start.elapsed());
        }

        Ok(())
    }
}

/// One of the errors that can happen when using the persistence service.
#[derive(Debug, Error)]
pub enum PersistenceError {
    /// A mutation was attempted while the release writer was held or faulted.
    #[error("persistence writer is release-fenced")]
    ReleaseFenceClosed,

    /// A pruner error
    #[error(transparent)]
    PrunerError(#[from] PrunerError),

    /// A provider error
    #[error(transparent)]
    ProviderError(#[from] ProviderError),
}

/// Refusal or failure of the persistence writer barrier.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReleaseFenceError {
    /// Another operation holds the writer, including a cancelled acknowledgement.
    #[error("persistence release fence is already held")]
    Busy,
    /// No matching acquisition remains active.
    #[error("persistence release fence is not held")]
    NotHeld,
    /// The operation identifier does not match the active owner.
    #[error("persistence release fence owner does not match")]
    WrongOwner,
    /// Metadata cannot be made durable at the requested head.
    #[error("pending safe or finalized metadata is ahead of the requested head")]
    PendingMetadataAhead,
    /// The finished stage and static-file head must both identify the exact requested block.
    #[error("persisted head mismatch: expected {expected:?}, actual {actual:?}, static tip {static_tip}")]
    HeadMismatch {
        /// Requested exact head.
        expected: BlockNumHash,
        /// Actual finished-stage head, if its canonical hash exists.
        actual: Option<BlockNumHash>,
        /// Last static-file header number.
        static_tip: u64,
    },
    /// Storage errors permanently close this service's writer admission.
    #[error("persistence release fence storage failure: {0}")]
    Storage(String),
    /// The persistence service has stopped or its channel is disconnected.
    #[error("persistence service is unavailable")]
    Unavailable,
}

impl ReleaseFenceError {
    fn storage(error: impl std::fmt::Display) -> Self {
        Self::Storage(error.to_string())
    }
}

/// A signal to the persistence service that part of the tree state can be persisted.
#[derive(Debug)]
pub enum PersistenceAction<N: NodePrimitives = EthPrimitives> {
    /// Engine-owned FIFO writer control. Its opaque request cannot be constructed externally.
    ReleaseFence(PersistenceReleaseFenceRequest),

    /// The section of tree state that should be persisted. These blocks are expected in order of
    /// increasing block number.
    ///
    /// First, header, transaction, and receipt-related data should be written to static files.
    /// Then the execution history-related data will be written to the database.
    SaveBlocks(Vec<ExecutedBlock<N>>, CrossbeamSender<PersistenceResult>),

    /// Removes block data above the given block number from the database.
    ///
    /// This will first update checkpoints from the database, then remove actual block data from
    /// static files.
    RemoveBlocksAbove(u64, CrossbeamSender<PersistenceResult>),

    /// Update the persisted finalized block on disk
    SaveFinalizedBlock(u64),

    /// Update the persisted safe block on disk
    SaveSafeBlock(u64),

    /// Export a consistent point-in-time snapshot of the canonical database and
    /// static files at a persisted block boundary.
    ///
    /// Capturing static-file lengths is serialized against saves. The detached read/copy
    /// itself may overlap later writes and may outlive a release fence. It does not mutate
    /// canonical storage and remains allowed while held; its completion is not part of
    /// the writer-barrier acknowledgement. The result has its own one-shot channel.
    ExportCanonicalSnapshot(
        CanonicalSnapshotRequest,
        tokio::sync::oneshot::Sender<Result<CanonicalSnapshotResult, CanonicalSnapshotError>>,
    ),
}

/// Opaque persistence control created only by this crate's engine-owned handle methods.
///
/// Public persistence action senders do not confer authority to acquire or release the fence.
/// No public constructor, field, cloning or decoding path exposes the operation identifier.
///
/// ```compile_fail
/// use reth_engine_tree::persistence::PersistenceReleaseFenceRequest;
/// let request = PersistenceReleaseFenceRequest {};
/// ```
///
/// ```compile_fail
/// use reth_engine_tree::persistence::PersistenceHandle;
/// fn release_without_engine_authority(handle: &PersistenceHandle) {
///     let _ = handle.release_release_fence(7);
/// }
/// ```
#[derive(Debug)]
pub struct PersistenceReleaseFenceRequest {
    operation: ReleaseFenceOperation,
    tx: CrossbeamSender<Result<(), ReleaseFenceError>>,
}

#[derive(Debug)]
enum ReleaseFenceOperation {
    Acquire { id: u64, expected: BlockNumHash },
    Release { id: u64 },
}

impl<N: NodePrimitives> PersistenceAction<N> {
    fn mutates_canonical_storage(&self) -> bool {
        matches!(
            self,
            Self::SaveBlocks(..) |
                Self::RemoveBlocksAbove(..) |
                Self::SaveFinalizedBlock(..) |
                Self::SaveSafeBlock(..)
        )
    }
}

/// A handle to the persistence service
#[derive(Debug, Clone)]
pub struct PersistenceHandle<N: NodePrimitives = EthPrimitives> {
    /// The channel used to communicate with the persistence service
    sender: Sender<PersistenceAction<N>>,
    /// Production clones share service admission state; service-side checks are authoritative.
    writer_closed: Arc<AtomicBool>,
    /// Guard that joins the service thread when all handles are dropped.
    /// Uses `Arc` so the handle remains `Clone`.
    _service_guard: Arc<ServiceGuard>,
}

impl<T: NodePrimitives> PersistenceHandle<T> {
    /// Create a new [`PersistenceHandle`] from a [`Sender<PersistenceAction>`].
    ///
    /// This is intended for testing purposes where you want to mock the persistence service.
    /// For production use, prefer [`spawn_service`](Self::spawn_service).
    pub fn new(sender: Sender<PersistenceAction<T>>) -> Self {
        Self {
            sender,
            writer_closed: Arc::new(AtomicBool::new(false)),
            _service_guard: Arc::new(ServiceGuard(None)),
        }
    }

    /// Create a new [`PersistenceHandle`], and spawn the persistence service.
    ///
    /// The returned handle can be cloned and shared. When all clones are dropped, the service
    /// thread will be joined, ensuring graceful shutdown before resources (like `RocksDB`) are
    /// released.
    pub fn spawn_service<N>(
        provider_factory: ProviderFactory<N>,
        pruner: PrunerWithFactory<ProviderFactory<N>>,
        sync_metrics_tx: MetricEventsSender,
    ) -> PersistenceHandle<N::Primitives>
    where
        N: ProviderNodeTypes,
    {
        // create the initial channels
        let (db_service_tx, db_service_rx) = std::sync::mpsc::channel();

        // spawn the persistence service
        let db_service =
            PersistenceService::new(provider_factory, db_service_rx, pruner, sync_metrics_tx);
        let writer_closed = db_service.writer_closed.clone();
        let join_handle = spawn_os_thread("persistence", || {
            if let Err(err) = db_service.run() {
                error!(target: "engine::persistence", ?err, "Persistence service failed");
            }
        });

        PersistenceHandle {
            sender: db_service_tx,
            writer_closed,
            _service_guard: Arc::new(ServiceGuard(Some(join_handle))),
        }
    }

    /// Sends a specific [`PersistenceAction`] in the contained channel. The caller is responsible
    /// for creating any channels for the given action.
    pub fn send_action(
        &self,
        action: PersistenceAction<T>,
    ) -> Result<(), SendError<PersistenceAction<T>>> {
        if action.mutates_canonical_storage() && self.writer_closed.load(Ordering::Acquire) {
            return Err(SendError(action));
        }
        self.sender.send(action)
    }

    /// Acquire a FIFO persistence barrier for an engine-owned operation.
    ///
    /// The bounded acknowledgement follows all earlier action work, including pruning and
    /// safe/finalized metadata commits. No deferred mutation queue is created. The existing
    /// service ingress is unchanged; actions already queued behind acquisition are refused.
    /// This low-level identifier is not a release capability: only the engine actor owns it.
    pub(crate) fn acquire_release_fence(
        &self,
        id: u64,
        expected: BlockNumHash,
    ) -> crossbeam_channel::Receiver<Result<(), ReleaseFenceError>> {
        let (tx, rx) = crossbeam_channel::bounded(1);
        if self
            .send_action(PersistenceAction::ReleaseFence(PersistenceReleaseFenceRequest {
                operation: ReleaseFenceOperation::Acquire { id, expected },
                tx: tx.clone(),
            }))
            .is_err()
        {
            let _ = tx.try_send(Err(ReleaseFenceError::Unavailable));
        }
        rx
    }

    /// Release only the active matching writer operation. Dropping this receiver does not
    /// cancel the explicit release. The engine must treat a lost reply as an uncertain outcome.
    pub(crate) fn release_release_fence(
        &self,
        id: u64,
    ) -> crossbeam_channel::Receiver<Result<(), ReleaseFenceError>> {
        let (tx, rx) = crossbeam_channel::bounded(1);
        if self
            .send_action(PersistenceAction::ReleaseFence(PersistenceReleaseFenceRequest {
                operation: ReleaseFenceOperation::Release { id },
                tx: tx.clone(),
            }))
            .is_err()
        {
            let _ = tx.try_send(Err(ReleaseFenceError::Unavailable));
        }
        rx
    }

    /// Tells the persistence service to save a certain list of finalized blocks. The blocks are
    /// assumed to be ordered by block number.
    ///
    /// This returns the latest hash that has been saved, allowing removal of that block and any
    /// previous blocks from in-memory data structures. This value is returned in the receiver end
    /// of the sender argument.
    ///
    /// If there are no blocks to persist, then `None` is sent in the sender.
    pub fn save_blocks(
        &self,
        blocks: Vec<ExecutedBlock<T>>,
        tx: CrossbeamSender<PersistenceResult>,
    ) -> Result<(), SendError<PersistenceAction<T>>> {
        self.send_action(PersistenceAction::SaveBlocks(blocks, tx))
    }

    /// Queues a consistent canonical snapshot export.
    ///
    /// The persistence thread captures the static-file boundary, then a detached thread
    /// performs the read/copy and replies on `tx`. This remains allowed while release-fenced;
    /// acquiring the writer fence does not wait for detached snapshot copies to finish.
    pub fn export_canonical_snapshot(
        &self,
        request: CanonicalSnapshotRequest,
        tx: tokio::sync::oneshot::Sender<Result<CanonicalSnapshotResult, CanonicalSnapshotError>>,
    ) -> Result<(), SendError<PersistenceAction<T>>> {
        self.send_action(PersistenceAction::ExportCanonicalSnapshot(request, tx))
    }

    /// Queues the finalized block number to be persisted on disk.
    ///
    /// The update is deferred and will be committed together with the next [`Self::save_blocks`]
    /// call to avoid triggering a separate fsync for each update.
    pub fn save_finalized_block_number(
        &self,
        finalized_block: u64,
    ) -> Result<(), SendError<PersistenceAction<T>>> {
        self.send_action(PersistenceAction::SaveFinalizedBlock(finalized_block))
    }

    /// Queues the safe block number to be persisted on disk.
    ///
    /// The update is deferred and will be committed together with the next [`Self::save_blocks`]
    /// call to avoid triggering a separate fsync for each update.
    pub fn save_safe_block_number(
        &self,
        safe_block: u64,
    ) -> Result<(), SendError<PersistenceAction<T>>> {
        self.send_action(PersistenceAction::SaveSafeBlock(safe_block))
    }

    /// Tells the persistence service to remove blocks above a certain block number. The removed
    /// blocks are returned by the service.
    ///
    /// When the operation completes, the new tip hash is returned in the receiver end of the sender
    /// argument.
    pub fn remove_blocks_above(
        &self,
        block_num: u64,
        tx: CrossbeamSender<PersistenceResult>,
    ) -> Result<(), SendError<PersistenceAction<T>>> {
        self.send_action(PersistenceAction::RemoveBlocksAbove(block_num, tx))
    }
}

/// Guard that joins the persistence service thread when dropped.
///
/// This ensures graceful shutdown - the service thread completes before resources like
/// `RocksDB` are released. Stored in an `Arc` inside [`PersistenceHandle`] so the handle
/// can be cloned while sharing the same guard.
struct ServiceGuard(Option<JoinHandle<()>>);

impl std::fmt::Debug for ServiceGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ServiceGuard").field(&self.0.as_ref().map(|_| "...")).finish()
    }
}

impl Drop for ServiceGuard {
    fn drop(&mut self) {
        if let Some(join_handle) = self.0.take() {
            let _ = join_handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eips::NumHash;
    use alloy_primitives::{BlockHash, BlockNumber, Bytes, B256, U256};
    use reth_chain_state::test_utils::TestBlockBuilder;
    use reth_exex_types::FinishedExExHeight;
    use reth_provider::{
        providers::{ProviderFactoryBuilder, ReadOnlyConfig},
        test_utils::{create_test_provider_factory, MockNodeTypes},
        AccountReader, BalConfig, BalNotificationStream, BalStore, BalStoreHandle,
        ChainSpecProvider, HeaderProvider, InMemoryBalStore, ProviderError, ProviderResult, RawBal,
        StorageSettingsCache, TryIntoHistoricalStateProvider,
    };
    use reth_prune::Pruner;
    use reth_prune_types::PruneMode;
    use tokio::sync::mpsc::unbounded_channel;

    fn default_persistence_handle() -> PersistenceHandle<EthPrimitives> {
        let provider = create_test_provider_factory();

        let (_finished_exex_height_tx, finished_exex_height_rx) =
            tokio::sync::watch::channel(FinishedExExHeight::NoExExs);

        let pruner =
            Pruner::new_with_factory(provider.clone(), vec![], 5, 0, None, finished_exex_height_rx);

        let (sync_metrics_tx, _sync_metrics_rx) = unbounded_channel();
        PersistenceHandle::<EthPrimitives>::spawn_service(provider, pruner, sync_metrics_tx)
    }

    #[test]
    fn test_release_fence_waits_for_pruning_and_refuses_queued_writes() {
        use reth_provider::BlockNumReader;

        let (entered_tx, entered_rx) = crossbeam_channel::bounded(1);
        let (resume_tx, resume_rx) = crossbeam_channel::bounded(1);
        let provider = create_test_provider_factory().with_bal_store(BalStoreHandle::new(
            BlockingPruneBalStore { entered: entered_tx, resume: resume_rx },
        ));
        let (_finished_tx, finished_rx) = tokio::sync::watch::channel(FinishedExExHeight::NoExExs);
        let pruner = Pruner::new_with_factory(provider.clone(), vec![], 0, 0, None, finished_rx);
        let (metrics_tx, _metrics_rx) = unbounded_channel();
        let handle =
            PersistenceHandle::<EthPrimitives>::spawn_service(provider.clone(), pruner, metrics_tx);
        let mut builder = TestBlockBuilder::eth();
        let blocks = builder.get_executed_blocks(0..2).collect::<Vec<_>>();
        let expected = blocks.last().unwrap().recovered_block().num_hash();
        let (save_tx, save_rx) = crossbeam_channel::bounded(1);
        handle.save_blocks(blocks, save_tx).unwrap();
        assert_eq!(
            save_rx.recv_timeout(Duration::from_secs(10)).unwrap().last_block,
            Some(expected)
        );
        entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();

        // SaveBlocks already replied, but the writer is still inside BAL pruning.
        let acquire = handle.acquire_release_fence(7, expected);
        let (later_save_tx, later_save_rx) = crossbeam_channel::bounded(1);
        handle.save_blocks(builder.get_executed_blocks(2..3).collect(), later_save_tx).unwrap();
        let (remove_tx, remove_rx) = crossbeam_channel::bounded(1);
        handle.remove_blocks_above(0, remove_tx).unwrap();
        assert_eq!(
            acquire.recv_timeout(Duration::from_millis(50)),
            Err(crossbeam_channel::RecvTimeoutError::Timeout)
        );
        resume_tx.send(()).unwrap();
        assert_eq!(acquire.recv_timeout(Duration::from_secs(10)).unwrap(), Ok(()));
        assert_eq!(
            later_save_rx.recv_timeout(Duration::from_secs(10)).unwrap_err(),
            crossbeam_channel::RecvTimeoutError::Disconnected
        );
        assert_eq!(
            remove_rx.recv_timeout(Duration::from_secs(10)).unwrap_err(),
            crossbeam_channel::RecvTimeoutError::Disconnected
        );
        let db = provider.provider().unwrap();
        assert_eq!(db.best_block_number().unwrap(), expected.number);
        assert_eq!(db.block_hash(expected.number).unwrap(), Some(expected.hash));
        drop(db);
        let (tx, _rx) = crossbeam_channel::bounded(1);
        assert!(handle.clone().remove_blocks_above(0, tx).is_err());
        assert!(handle
            .release_release_fence(8)
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .is_err());
        assert_eq!(
            handle.release_release_fence(7).recv_timeout(Duration::from_secs(10)).unwrap(),
            Ok(())
        );
        let (tx, rx) = crossbeam_channel::bounded(1);
        handle.remove_blocks_above(0, tx).unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(10)).unwrap().last_block.unwrap().number, 0);
        assert_eq!(provider.provider().unwrap().best_block_number().unwrap(), 0);
    }

    #[derive(Debug)]
    struct BlockingPruneBalStore {
        entered: CrossbeamSender<()>,
        resume: crossbeam_channel::Receiver<()>,
    }

    impl BalStore for BlockingPruneBalStore {
        fn insert(&self, _num_hash: NumHash, _bal: RawBal) -> ProviderResult<()> {
            Ok(())
        }
        fn prune(&self, _tip: BlockNumber) -> ProviderResult<usize> {
            self.entered.send(()).unwrap();
            self.resume.recv_timeout(Duration::from_secs(10)).unwrap();
            Ok(0)
        }
        fn get_by_hashes(&self, hashes: &[BlockHash]) -> ProviderResult<Vec<Option<Bytes>>> {
            Ok(vec![None; hashes.len()])
        }
        fn bal_stream(&self) -> BalNotificationStream {
            BalStoreHandle::noop().bal_stream()
        }
    }

    #[test]
    fn test_release_fence_flushes_metadata_and_cancel_does_not_release() {
        use reth_provider::ChainStateBlockReader;

        let provider = create_test_provider_factory();
        let (_finished_tx, finished_rx) = tokio::sync::watch::channel(FinishedExExHeight::NoExExs);
        let pruner = Pruner::new_with_factory(provider.clone(), vec![], 5, 0, None, finished_rx);
        let (metrics_tx, _metrics_rx) = unbounded_channel();
        let handle =
            PersistenceHandle::<EthPrimitives>::spawn_service(provider.clone(), pruner, metrics_tx);
        let blocks = TestBlockBuilder::eth().get_executed_blocks(0..2).collect::<Vec<_>>();
        let expected = blocks.last().unwrap().recovered_block().num_hash();
        let (tx, rx) = crossbeam_channel::bounded(1);
        handle.save_blocks(blocks, tx).unwrap();
        rx.recv_timeout(Duration::from_secs(10)).unwrap();
        handle.save_safe_block_number(1).unwrap();
        handle.save_finalized_block_number(0).unwrap();
        let (empty_tx, empty_rx) = crossbeam_channel::bounded(1);
        handle.save_blocks(vec![], empty_tx).unwrap();
        empty_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        drop(handle.acquire_release_fence(11, expected));
        // FIFO control reply proves the cancelled acquisition has been processed.
        assert!(handle
            .acquire_release_fence(12, expected)
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .is_err());
        let db = provider.provider().unwrap();
        assert_eq!(db.last_safe_block_number().unwrap(), Some(1));
        assert_eq!(db.last_finalized_block_number().unwrap(), Some(0));
        drop(db);
        assert!(handle.save_safe_block_number(0).is_err());
        assert_eq!(
            handle.release_release_fence(11).recv_timeout(Duration::from_secs(10)).unwrap(),
            Ok(())
        );
        assert!(handle
            .release_release_fence(11)
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .is_err());
    }

    #[test]
    fn test_release_fence_allows_snapshot_request_without_unfencing() {
        let provider = create_test_provider_factory();
        let (_finished_tx, finished_rx) = tokio::sync::watch::channel(FinishedExExHeight::NoExExs);
        let pruner = Pruner::new_with_factory(provider.clone(), vec![], 5, 0, None, finished_rx);
        let (metrics_tx, _metrics_rx) = unbounded_channel();
        let handle =
            PersistenceHandle::<EthPrimitives>::spawn_service(provider.clone(), pruner, metrics_tx);
        let blocks = TestBlockBuilder::eth().get_executed_blocks(0..2).collect::<Vec<_>>();
        let expected = blocks.last().unwrap().recovered_block().num_hash();
        let (tx, rx) = crossbeam_channel::bounded(1);
        handle.save_blocks(blocks, tx).unwrap();
        rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(
            handle
                .acquire_release_fence(1, expected)
                .recv_timeout(Duration::from_secs(10))
                .unwrap(),
            Ok(())
        );
        // A bad target yields an exporter error, demonstrating that snapshot requests are
        // processed through their separate read/copy path while writer admission stays closed.
        let (tx, rx) = tokio::sync::oneshot::channel();
        let request = CanonicalSnapshotRequest {
            target: BlockNumHash::new(expected.number + 1, B256::random()),
            output_dir: provider.db_ref().path().join("refused-release-fence-snapshot"),
        };
        handle.export_canonical_snapshot(request, tx).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
        let result = runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(10), rx).await.unwrap().unwrap()
        });
        assert!(matches!(result, Err(CanonicalSnapshotError::TargetNotPersistedHead { .. })));
        assert!(handle.save_safe_block_number(0).is_err());
        assert_eq!(
            handle.release_release_fence(1).recv_timeout(Duration::from_secs(10)).unwrap(),
            Ok(())
        );
    }

    #[test]
    fn test_release_fence_checks_exact_persisted_head_and_pending_metadata() {
        let handle = default_persistence_handle();
        let blocks = TestBlockBuilder::eth().get_executed_blocks(0..2).collect::<Vec<_>>();
        let expected = blocks.last().unwrap().recovered_block().num_hash();
        let (tx, rx) = crossbeam_channel::bounded(1);
        handle.save_blocks(blocks, tx).unwrap();
        rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let wrong_hash = BlockNumHash::new(expected.number, B256::random());
        assert!(handle
            .acquire_release_fence(1, wrong_hash)
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .is_err());
        let ancestor = BlockNumHash::new(0, B256::random());
        assert!(handle
            .acquire_release_fence(2, ancestor)
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .is_err());
        handle.save_safe_block_number(expected.number + 1).unwrap();
        assert_eq!(
            handle
                .acquire_release_fence(3, expected)
                .recv_timeout(Duration::from_secs(10))
                .unwrap(),
            Err(ReleaseFenceError::PendingMetadataAhead)
        );
        handle.save_safe_block_number(expected.number).unwrap();
        assert_eq!(
            handle
                .acquire_release_fence(4, expected)
                .recv_timeout(Duration::from_secs(10))
                .unwrap(),
            Ok(())
        );
        assert_eq!(
            handle.release_release_fence(4).recv_timeout(Duration::from_secs(10)).unwrap(),
            Ok(())
        );
    }

    #[test]
    fn test_release_fence_refuses_after_pruner_fault() {
        let provider = create_test_provider_factory()
            .with_bal_store(BalStoreHandle::new(FailingPruneBalStore));
        let (_finished_tx, finished_rx) = tokio::sync::watch::channel(FinishedExExHeight::NoExExs);
        let pruner = Pruner::new_with_factory(provider.clone(), vec![], 0, 0, None, finished_rx);
        let (metrics_tx, _metrics_rx) = unbounded_channel();
        let handle =
            PersistenceHandle::<EthPrimitives>::spawn_service(provider, pruner, metrics_tx);
        let blocks = TestBlockBuilder::eth().get_executed_blocks(0..2).collect::<Vec<_>>();
        let expected = blocks.last().unwrap().recovered_block().num_hash();
        let (tx, rx) = crossbeam_channel::bounded(1);
        handle.save_blocks(blocks, tx).unwrap();
        rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(handle
            .acquire_release_fence(1, expected)
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .is_err());
        assert!(handle
            .release_release_fence(1)
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .is_err());
        let (tx, _rx) = crossbeam_channel::bounded(1);
        assert!(handle.remove_blocks_above(0, tx).is_err());
    }

    #[test]
    fn test_pruner_prunes_bal_store() {
        reth_tracing::init_test_tracing();

        let old_hash = B256::random();
        let retained_hash = B256::random();
        let old_bal = Bytes::from_static(b"old");
        let retained_bal = Bytes::from_static(b"retained");
        let bal_store = BalStoreHandle::new(InMemoryBalStore::new(
            BalConfig::with_in_memory_retention(PruneMode::Before(2)),
        ));

        bal_store.insert(NumHash::new(1, old_hash), RawBal::new(old_bal)).unwrap();
        bal_store
            .insert(NumHash::new(2, retained_hash), RawBal::new(retained_bal.clone()))
            .unwrap();

        let provider = create_test_provider_factory().with_bal_store(bal_store.clone());
        let (_finished_exex_height_tx, finished_exex_height_rx) =
            tokio::sync::watch::channel(FinishedExExHeight::NoExExs);
        let pruner =
            Pruner::new_with_factory(provider.clone(), vec![], 0, 0, None, finished_exex_height_rx);
        let (_db_service_tx, db_service_rx) = std::sync::mpsc::channel();
        let (sync_metrics_tx, _sync_metrics_rx) = unbounded_channel();
        let mut service = PersistenceService::new(provider, db_service_rx, pruner, sync_metrics_tx);

        service.maybe_run_pruner(2).unwrap();

        assert_eq!(
            bal_store.get_by_hashes(&[old_hash, retained_hash]).unwrap(),
            vec![None, Some(retained_bal)]
        );
    }

    #[test]
    fn test_pruner_retains_bal_store_prune_error_for_release_fence() {
        reth_tracing::init_test_tracing();

        let provider = create_test_provider_factory()
            .with_bal_store(BalStoreHandle::new(FailingPruneBalStore));
        let (_finished_exex_height_tx, finished_exex_height_rx) =
            tokio::sync::watch::channel(FinishedExExHeight::NoExExs);
        let pruner =
            Pruner::new_with_factory(provider.clone(), vec![], 0, 0, None, finished_exex_height_rx);
        let (_db_service_tx, db_service_rx) = std::sync::mpsc::channel();
        let (sync_metrics_tx, _sync_metrics_rx) = unbounded_channel();
        let mut service = PersistenceService::new(provider, db_service_rx, pruner, sync_metrics_tx);

        service.maybe_run_pruner(2).unwrap();
        assert!(matches!(service.release_fence_fault, Some(ReleaseFenceError::Storage(_))));
        assert!(matches!(service.maybe_run_pruner(3), Err(PersistenceError::ReleaseFenceClosed)));
    }

    #[derive(Debug)]
    struct FailingPruneBalStore;

    impl BalStore for FailingPruneBalStore {
        fn insert(&self, _num_hash: NumHash, _bal: RawBal) -> ProviderResult<()> {
            Ok(())
        }

        fn prune(&self, _tip: BlockNumber) -> ProviderResult<usize> {
            Err(ProviderError::other(std::io::Error::other("BAL store prune failed")))
        }

        fn get_by_hashes(&self, block_hashes: &[BlockHash]) -> ProviderResult<Vec<Option<Bytes>>> {
            Ok(vec![None; block_hashes.len()])
        }

        fn bal_stream(&self) -> BalNotificationStream {
            BalStoreHandle::noop().bal_stream()
        }
    }

    #[test]
    fn test_save_blocks_empty() {
        reth_tracing::init_test_tracing();
        let handle = default_persistence_handle();

        let blocks = vec![];
        let (tx, rx) = crossbeam_channel::bounded(1);

        handle.save_blocks(blocks, tx).unwrap();

        let result = rx.recv().unwrap();
        assert!(result.last_block.is_none());
    }

    #[test]
    fn test_save_blocks_single_block() {
        reth_tracing::init_test_tracing();
        let handle = default_persistence_handle();
        let block_number = 0;
        let mut test_block_builder = TestBlockBuilder::eth();
        let executed =
            test_block_builder.get_executed_block_with_number(block_number, B256::random());
        let block_hash = executed.recovered_block().hash();

        let blocks = vec![executed];
        let (tx, rx) = crossbeam_channel::bounded(1);

        handle.save_blocks(blocks, tx).unwrap();

        let result = rx.recv_timeout(std::time::Duration::from_secs(10)).expect("test timed out");

        assert_eq!(block_hash, result.last_block.unwrap().hash);
    }

    #[test]
    fn test_save_blocks_multiple_blocks() {
        reth_tracing::init_test_tracing();
        let handle = default_persistence_handle();

        let mut test_block_builder = TestBlockBuilder::eth();
        let blocks = test_block_builder.get_executed_blocks(0..5).collect::<Vec<_>>();
        let last_hash = blocks.last().unwrap().recovered_block().hash();
        let (tx, rx) = crossbeam_channel::bounded(1);

        handle.save_blocks(blocks, tx).unwrap();
        let result = rx.recv().unwrap();
        assert_eq!(last_hash, result.last_block.unwrap().hash);
    }

    #[test]
    fn test_save_blocks_multiple_calls() {
        reth_tracing::init_test_tracing();
        let handle = default_persistence_handle();

        let ranges = [0..1, 1..2, 2..4, 4..5];
        let mut test_block_builder = TestBlockBuilder::eth();
        for range in ranges {
            let blocks = test_block_builder.get_executed_blocks(range).collect::<Vec<_>>();
            let last_hash = blocks.last().unwrap().recovered_block().hash();
            let (tx, rx) = crossbeam_channel::bounded(1);

            handle.save_blocks(blocks, tx).unwrap();

            let result = rx.recv().unwrap();
            assert_eq!(last_hash, result.last_block.unwrap().hash);
        }
    }

    /// Verifies that committing `save_blocks` history before running the pruner
    /// prevents the pruner from overwriting new entries.
    ///
    /// Previously, both `save_blocks` and the pruner pushed `RocksDB` batches before
    /// a single commit. Both read committed state, so the pruner didn't see the
    /// new entries and its batch overwrote them. The fix commits `save_blocks`
    /// first, then runs the pruner against committed state in a separate provider.
    #[test]
    fn test_save_blocks_then_prune_preserves_new_history() {
        use reth_db::{models::ShardedKey, tables, BlockNumberList};
        use reth_provider::RocksDBProviderFactory;

        reth_tracing::init_test_tracing();

        let provider_factory = create_test_provider_factory();
        let tracked_addr = alloy_primitives::Address::from([0xBE; 20]);

        // Phase 1: Establish baseline history for blocks 0..20.
        let rocksdb = provider_factory.rocksdb_provider();
        {
            let mut batch = rocksdb.batch();
            let initial_blocks: Vec<u64> = (0..20).collect();
            let shard = BlockNumberList::new_pre_sorted(initial_blocks.iter().copied());
            batch
                .put::<tables::AccountsHistory>(ShardedKey::new(tracked_addr, u64::MAX), &shard)
                .unwrap();
            batch.commit().unwrap();
        }

        // Phase 2: Simulate the fixed on_save_blocks flow.
        // Step 1: save_blocks appends new entries 20..25 and commits immediately.
        let mut batch1 = rocksdb.batch();
        batch1.append_account_history_shard(tracked_addr, 20..25u64).unwrap();
        batch1.commit().unwrap();

        // Step 2: Pruner runs AFTER commit, so it reads state that includes 20..25.
        // Prunes entries ≤ 14, leaving [15..25).
        let mut batch2 = rocksdb.batch();
        batch2.prune_account_history_to(tracked_addr, 14).unwrap();
        batch2.commit().unwrap();

        // Verify new entries survived pruning.
        let shards = rocksdb.account_history_shards(tracked_addr).unwrap();
        let entries: Vec<u64> = shards.iter().flat_map(|(_, list)| list.iter()).collect();
        let expected: Vec<u64> = (15..25).collect();
        assert_eq!(entries, expected, "new entries 20..25 must survive pruning");
    }

    #[test]
    fn test_read_only_consistency_across_reorg() {
        reth_tracing::init_test_tracing();

        // Allow opening the same MDBX env twice in-process
        reth_db::test_utils::enable_legacy_multiopen();

        let provider_factory = create_test_provider_factory();
        provider_factory.set_storage_settings_cache(reth_provider::StorageSettings::v2());

        // Open the secondary provider concurrently with the primary.
        let secondary = ProviderFactoryBuilder::<MockNodeTypes>::default()
            .open_read_only(
                provider_factory.chain_spec(),
                ReadOnlyConfig::from_datadir(provider_factory.db_ref().path()),
                reth_tasks::Runtime::test(),
            )
            .expect("failed to open read-only provider factory");
        secondary.set_storage_settings_cache(reth_provider::StorageSettings::v2());

        // --- Phase 1: Write blocks 0..3 via the primary ---
        let mut test_block_builder = TestBlockBuilder::eth().with_state();
        let signer = test_block_builder.signer;
        let blocks_a: Vec<_> = test_block_builder.get_executed_blocks(0..3).collect();
        let hash_a1 = blocks_a[1].recovered_block().hash();
        let hash_a2 = blocks_a[2].recovered_block().hash();

        // Compute expected signer state after each block from tx counts.
        let single_cost = TestBlockBuilder::<EthPrimitives>::single_tx_cost();
        let initial_balance = U256::from(10).pow(U256::from(18));
        let txs_in_block0 = blocks_a[0].recovered_block().body().transactions.len() as u64;
        let txs_in_block1 = blocks_a[1].recovered_block().body().transactions.len() as u64;

        let balance_after_block0 = initial_balance - single_cost * U256::from(txs_in_block0);
        let nonce_after_block0 = txs_in_block0;
        let balance_after_block1 = balance_after_block0 - single_cost * U256::from(txs_in_block1);
        let nonce_after_block1 = nonce_after_block0 + txs_in_block1;

        {
            let provider_rw = provider_factory.database_provider_rw().unwrap();
            provider_rw.save_blocks(blocks_a, SaveBlocksMode::Full).unwrap();
            provider_rw.commit().unwrap();
        }

        // Secondary catches up and sees all 3 blocks.
        // Hold this provider (and its MDBX RO tx) across the reorg to test snapshot isolation.
        let pre_reorg_provider = secondary.provider().unwrap();
        assert_eq!(
            pre_reorg_provider.sealed_header(2).unwrap().as_ref().map(|h| h.hash()),
            Some(hash_a2),
            "secondary must see block 2 after initial append"
        );

        // Check the primary can read its own historical state.
        {
            let primary_state_at_1 = provider_factory.history_by_block_number(1).unwrap();
            let primary_account = primary_state_at_1.basic_account(&signer).unwrap();
            assert!(primary_account.is_some(), "primary: signer must exist at block 1");
        }

        // Verify historical state at block 1 is accessible via changesets on the secondary.
        {
            let state_at_1 = secondary.history_by_block_number(1).unwrap();
            let account_at_1 = state_at_1.basic_account(&signer).unwrap();
            assert!(account_at_1.is_some(), "signer account must exist at block 1");
            let account_at_1 = account_at_1.unwrap();
            assert_eq!(account_at_1.balance, balance_after_block1, "signer balance at block 1");
            assert_eq!(account_at_1.nonce, nonce_after_block1, "signer nonce at block 1");
        }

        // --- Phase 2: Reorg — remove block 2 and append a different block 2 ---
        // Build the reorg block before starting the commit so we can write it in the
        // same thread after the unwind.
        let block_b2 = test_block_builder.get_executed_block_with_number(2, hash_a1);
        let hash_b2 = block_b2.recovered_block().hash();
        let txs_in_block_b2 = block_b2.recovered_block().body().transactions.len() as u64;
        assert_ne!(hash_a2, hash_b2, "reorg block must differ");

        // Expected signer state after the reorged block 2.
        let balance_after_reorg_block2 =
            balance_after_block1 - single_cost * U256::from(txs_in_block_b2);
        let nonce_after_reorg_block2 = nonce_after_block1 + txs_in_block_b2;

        // Spawn the reorg on a background thread because `commit_unwind` calls
        // `wait_for_pre_commit_readers()` which blocks until the secondary's held
        // RO tx is dropped.
        //
        // We want to keep provider factory around, otherwise it's gonna drop mdbx env before the
        // reorg thread is on
        #[expect(clippy::redundant_clone)]
        let pf = provider_factory.clone();
        let reorg_handle = std::thread::spawn(move || {
            let provider_rw = pf.database_provider_rw().unwrap();
            provider_rw.remove_block_and_execution_above(1).unwrap();
            provider_rw.commit().unwrap();

            let provider_rw = pf.database_provider_rw().unwrap();
            provider_rw.save_blocks(vec![block_b2], SaveBlocksMode::Full).unwrap();
            provider_rw.commit().unwrap();
        });

        // Give the reorg thread time to start and block on wait_for_pre_commit_readers.
        std::thread::sleep(std::time::Duration::from_millis(100));

        // The pre-reorg provider still holds its MDBX snapshot — it must still see
        // the OLD block 2 from before the reorg.
        assert_eq!(
            pre_reorg_provider.sealed_header(2).unwrap().as_ref().map(|h| h.hash()),
            Some(hash_a2),
            "pre-reorg provider must still see the original block 2"
        );
        assert_eq!(
            pre_reorg_provider.sealed_header(1).unwrap().as_ref().map(|h| h.hash()),
            Some(hash_a1),
            "pre-reorg provider must still see block 1"
        );

        // The held RO tx must still be able to read historical state at block 1 via
        // changesets, even though the reorg thread is about to rewrite block 2's data.
        // Consuming pre_reorg_provider here also unblocks the reorg commit.
        let state_at_1 = pre_reorg_provider.try_into_history_at_block(1).unwrap();
        let account = state_at_1.basic_account(&signer).unwrap();
        assert!(
            account.is_some(),
            "pre-reorg RO tx must still read signer at block 1 during reorg"
        );
        let account = account.unwrap();
        assert_eq!(
            account.balance, balance_after_block1,
            "pre-reorg RO tx: signer balance at block 1 during reorg"
        );
        assert_eq!(
            account.nonce, nonce_after_block1,
            "pre-reorg RO tx: signer nonce at block 1 during reorg"
        );
        drop(state_at_1);
        reorg_handle.join().expect("reorg thread panicked");

        // A new provider catches up and sees the reorged chain.
        let obs_header = secondary.provider().unwrap().sealed_header(2).unwrap();
        assert_eq!(
            obs_header.as_ref().map(|h| h.hash()),
            Some(hash_b2),
            "secondary must see the reorged block 2, not the old one"
        );

        // Block 1 should still be the original.
        let obs_header = secondary.provider().unwrap().sealed_header(1).unwrap();
        assert_eq!(
            obs_header.as_ref().map(|h| h.hash()),
            Some(hash_a1),
            "secondary must still see block 1"
        );

        // Verify historical state at block 1 is still accessible after the reorg.
        let state_at_1 = secondary.history_by_block_number(1).unwrap();
        let account_at_1 = state_at_1.basic_account(&signer).unwrap();
        assert!(account_at_1.is_some(), "signer account must exist at block 1 after reorg");
        let account_at_1 = account_at_1.unwrap();
        assert_eq!(
            account_at_1.balance, balance_after_block1,
            "signer balance at block 1 must survive reorg"
        );
        assert_eq!(
            account_at_1.nonce, nonce_after_block1,
            "signer nonce at block 1 must survive reorg"
        );

        // Verify the latest state (at block 2) reflects the reorged execution.
        let state_at_2 = secondary.history_by_block_number(2).unwrap();
        let account_at_2 = state_at_2.basic_account(&signer).unwrap();
        assert!(account_at_2.is_some(), "signer account must exist at block 2 after reorg");
        let account_at_2 = account_at_2.unwrap();
        assert_eq!(
            account_at_2.balance, balance_after_reorg_block2,
            "signer balance at block 2 must reflect reorged execution"
        );
        assert_eq!(
            account_at_2.nonce, nonce_after_reorg_block2,
            "signer nonce at block 2 must reflect reorged execution"
        );
    }
}
