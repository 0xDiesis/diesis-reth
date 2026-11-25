//! Engine node related functionality.

use crate::{
    common::{Attached, LaunchContextWith, WithConfigs},
    hooks::NodeHooks,
    rpc::{
        EngineShutdown, EngineValidatorAddOn, EngineValidatorBuilder, ExecutedBlockInsertRequest,
        ExecutedBlockInsertSender, RethRpcAddOns, RpcHandle,
    },
    setup::build_networked_pipeline,
    sync::{BackfillClientFor, BackfillContext, BackfillSyncBuilder, PipelineBackfill},
    AddOns, AddOnsContext, FullNode, LaunchContext, LaunchNode, Node, NodeAdapter,
    NodeBuilderWithComponents, NodeComponents, NodeComponentsBuilder, NodeHandle, NodeTypesAdapter,
    RethFullAdapter,
};
use alloy_consensus::BlockHeader;
use futures::{stream::FusedStream, stream_select, FutureExt, StreamExt};
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_db::{database_metrics::DatabaseMetrics, Database};
use reth_engine_tree::{
    chain::{ChainEvent, FromOrchestrator},
    engine::{EngineApiKind, EngineApiRequest, EngineRequestHandler},
    launch::EngineOrchestratorBuilder,
    tree::TreeConfig,
    writer_fence::WriterFenceBootstrap,
};
use reth_engine_util::EngineMessageStreamExt;
use reth_exex::ExExManagerHandle;
use reth_network::{types::BlockRangeUpdate, NetworkSyncUpdater, SyncState};
use reth_network_api::BlockDownloaderProvider;
use reth_node_api::{
    BuiltPayload, ConsensusEngineHandle, FullNodeTypes, NodeTypes, NodeTypesWithDBAdapter,
};
use reth_node_core::{
    args::PruneConfigKind,
    dirs::{ChainPath, DataDirPath},
    exit::NodeExitFuture,
    primitives::Head,
};
use reth_node_events::node;
use reth_node_metrics::recorder::install_prometheus_recorder;
use reth_provider::{
    providers::{BlockchainProvider, NodeTypesForProvider},
    BlockNumReader, StorageSettingsCache,
};
use reth_rpc_layer::JwtSecret;
use reth_storage_overlay::OverlayManager;
use reth_tasks::TaskExecutor;
use reth_tokio_util::EventSender;
use reth_tracing::tracing::{debug, error, info};
use std::{future::Future, pin::Pin, sync::Arc};
use tokio::sync::{mpsc::unbounded_channel, oneshot};
use tokio_stream::wrappers::UnboundedReceiverStream;

const DIESIS_EXECUTED_BLOCK_CHANNEL_CAPACITY: usize = 64;

/// Journal file name of the engine writer release fence inside the node data directory.
const WRITER_FENCE_JOURNAL_NAME: &str = "engine-writer-release-fence";

/// The engine node launcher.
///
/// `B` builds the engine's backfill, the staged pipeline unless set with
/// [`Self::with_backfill`].
#[derive(Debug)]
pub struct EngineNodeLauncher<B = PipelineBackfill> {
    /// The task executor for the node.
    pub ctx: LaunchContext,

    /// Temporary configuration for engine tree.
    /// After engine is stabilized, this should be configured through node builder.
    pub engine_tree_config: TreeConfig,

    // Builds the backfill the engine runs while far behind the chain.
    backfill: B,
    /// Optional already reconciled writer-fence bootstrap supplied by trusted node startup.
    writer_fence_bootstrap: Option<WriterFenceBootstrap>,
}

/// Consume a supplied bootstrap only when it retains the exact launcher journal path and is
/// still the exact Clean record under its retained lock and directory identity; otherwise
/// perform the default clean-only acquisition.
fn accept_writer_fence_bootstrap(
    supplied: Option<WriterFenceBootstrap>,
    expected: std::path::PathBuf,
) -> Result<WriterFenceBootstrap, reth_engine_tree::writer_fence::WriterFenceError> {
    match supplied {
        None => WriterFenceBootstrap::acquire(expected),
        Some(bootstrap) => {
            if bootstrap.journal_path() != expected {
                return Err(reth_engine_tree::writer_fence::WriterFenceError::Journal {
                    message: format!(
                        "supplied writer-fence bootstrap path {} differs from launcher path {}",
                        bootstrap.journal_path().display(),
                        expected.display()
                    ),
                })
            }
            bootstrap.recheck_clean()?;
            Ok(bootstrap)
        }
    }
}

impl EngineNodeLauncher {
    /// Create a new instance of the ethereum node launcher.
    pub const fn new(
        task_executor: TaskExecutor,
        data_dir: ChainPath<DataDirPath>,
        engine_tree_config: TreeConfig,
    ) -> Self {
        Self {
            ctx: LaunchContext::new(task_executor, data_dir),
            engine_tree_config,
            backfill: PipelineBackfill,
            writer_fence_bootstrap: None,
        }
    }

    /// Exact writer-fence journal path for a node data directory.
    pub fn writer_fence_journal_path(data_dir: &std::path::Path) -> std::path::PathBuf {
        data_dir.join(WRITER_FENCE_JOURNAL_NAME)
    }
}

impl<B> EngineNodeLauncher<B> {
    /// Use a writer bootstrap already reconciled for this node data directory.
    pub fn with_writer_fence_bootstrap(mut self, bootstrap: WriterFenceBootstrap) -> Self {
        self.writer_fence_bootstrap = Some(bootstrap);
        self
    }

    async fn launch_node<N, DB, T, CB, AO>(
        self,
        target: NodeBuilderWithComponents<T, CB, AO>,
    ) -> eyre::Result<NodeHandle<NodeAdapter<T, CB::Components>, AO>>
    where
        N: Node<RethFullAdapter<DB, N>> + NodeTypesForProvider,
        DB: Database + DatabaseMetrics + Clone + Unpin + 'static,
        T: FullNodeTypes<
            Types = N,
            Provider = BlockchainProvider<NodeTypesWithDBAdapter<N, DB>>,
            DB = DB,
        >,
        CB: NodeComponentsBuilder<T>,
        AO: RethRpcAddOns<NodeAdapter<T, CB::Components>>
            + EngineValidatorAddOn<NodeAdapter<T, CB::Components>>,
        B: BackfillSyncBuilder<NodeTypesWithDBAdapter<N, DB>, BackfillClientFor<T, CB::Components>>,
    {
        let Self { ctx, engine_tree_config, mut backfill, writer_fence_bootstrap } = self;
        // Acquire and inspect the durable release journal before genesis initialization, static
        // file movement, component startup, or any other writer in this launch path. A supplied
        // reconciled bootstrap is consumed only for this exact path after a fresh Clean recheck.
        let require_tagged_forkchoice = writer_fence_bootstrap.is_some();
        let writer_fence_bootstrap = accept_writer_fence_bootstrap(
            writer_fence_bootstrap,
            EngineNodeLauncher::writer_fence_journal_path(&ctx.data_dir.data_dir()),
        )?;
        let NodeBuilderWithComponents {
            adapter: NodeTypesAdapter { database },
            rocksdb_provider,
            components_builder,
            add_ons: AddOns { hooks, exexs: installed_exex, add_ons },
            config,
        } = target;
        let NodeHooks { on_component_initialized, on_node_started, .. } = hooks;

        // Install the recorder before creating anything that registers metrics: metrics registered
        // earlier stay no-ops, and derived metrics cache their first instance for the process.
        install_prometheus_recorder();

        // Create the overlay manager that will be shared across the provider and engine.
        let overlay_manager = OverlayManager::<N::Primitives>::new(
            ctx.task_executor.state_trie_overlay_worker_pool(),
        );
        let disabled_stages = N::disabled_stages();

        // setup the launch context
        let ctx = ctx
            .with_configured_globals(engine_tree_config.reserved_cpu_cores())
            // load the toml config
            .with_loaded_toml_config(config)?
            // add resolved peers
            .with_resolved_peers()?
            // attach the database
            .attach(database.clone())
            // ensure certain settings take effect
            .with_adjusted_configs()
            // Create the provider factory with the shared overlay manager, letting the backfill
            // finish writes an earlier run left half-committed before the consistency check
            .with_provider_factory_and_recovery::<_, <CB::Components as NodeComponents<T>>::Evm>(
                overlay_manager.clone(),
                rocksdb_provider,
                disabled_stages,
                |factory| backfill.recover(factory),
            )
            .await?
            .inspect(|_| {
                info!(target: "reth::cli", "Database opened");
            })
            .with_prometheus_server().await?
            .inspect(|this| {
                debug!(target: "reth::cli", chain=%this.chain_id(), genesis=?this.genesis_hash(), "Initializing genesis");
            })
            .with_genesis()?
            .inspect(|this: &LaunchContextWith<Attached<WithConfigs<<T::Types as NodeTypes>::ChainSpec>, _>>| {
                info!(target: "reth::cli", "\n{}", this.chain_spec().display_hardforks());
                let settings = this.provider_factory().cached_storage_settings();
                let pruning_mode =
                    PruneConfigKind::from_config(&this.prune_config(), this.chain_spec().as_ref()).as_str();
                info!(target: "reth::cli", ?settings, ?pruning_mode, "Loaded storage settings");
            })
            .with_metrics_task()
            // passing FullNodeTypes as type parameter here so that we can build
            // later the components.
            .with_blockchain_db::<T, _>(move |provider_factory| {
                Ok(BlockchainProvider::new(provider_factory)?)
            })?
            .with_components(components_builder, on_component_initialized).await?;

        // spawn exexs if any
        let maybe_exex_manager_handle = ctx.launch_exex(installed_exex).await?;

        // create pipeline
        let network_handle = ctx.components().network().clone();
        let network_client = network_handle.fetch_client().await?;
        let (consensus_engine_tx, consensus_engine_rx) = unbounded_channel();

        let node_config = ctx.node_config();

        // We always assume that node is syncing after a restart
        network_handle.update_sync_state(SyncState::Syncing);

        let max_block = ctx.max_block(network_client.clone()).await?;

        let static_file_producer = ctx.static_file_producer();
        let static_file_producer_events = static_file_producer.lock().events();
        info!(target: "reth::cli", "StaticFileProducer initialized");

        let consensus = Arc::new(ctx.components().consensus().clone());

        let pipeline = build_networked_pipeline(
            &ctx.toml_config().stages,
            network_client.clone(),
            consensus.clone(),
            ctx.provider_factory().clone(),
            ctx.task_executor(),
            ctx.sync_metrics_tx(),
            ctx.prune_config(),
            max_block,
            static_file_producer,
            ctx.components().evm_config().clone(),
            maybe_exex_manager_handle.clone().unwrap_or_else(ExExManagerHandle::empty),
            ctx.era_import_source(),
            disabled_stages,
        )?;

        // The new engine writes directly to static files. This ensures that they're up to the tip.
        pipeline.move_to_static_files()?;

        let pipeline_events = pipeline.events();

        let mut pruner_builder = ctx.pruner_builder();
        if let Some(exex_manager_handle) = &maybe_exex_manager_handle {
            pruner_builder =
                pruner_builder.finished_exex_height(exex_manager_handle.finished_height());
        }
        let pruner = pruner_builder.build_with_provider_factory(ctx.provider_factory().clone());
        let pruner_events = pruner.events();
        info!(target: "reth::cli", prune_config=?ctx.prune_config(), "Pruner initialized");

        let event_sender = EventSender::default();

        let beacon_engine_handle = ConsensusEngineHandle::new(consensus_engine_tx.clone());

        // The JWT secret is only used by the auth server, so don't read or create it when the auth
        // server is disabled.
        let jwt_secret = if ctx.node_config().rpc.disable_auth_server {
            JwtSecret::random()
        } else {
            ctx.auth_jwt_secret()?
        };

        let add_ons_ctx = AddOnsContext {
            node: ctx.node_adapter().clone(),
            config: ctx.node_config(),
            beacon_engine_handle: beacon_engine_handle.clone(),
            jwt_secret,
            engine_events: event_sender.clone(),
            sender_recovery_cache: ctx.sender_recovery_cache().cloned(),
        };
        let validator_builder = add_ons.engine_validator_builder();

        // Build the engine validator with all required components
        let engine_validator = validator_builder
            .clone()
            .build_tree_validator(&add_ons_ctx, engine_tree_config.clone(), overlay_manager.clone())
            .await?;

        // Create the consensus engine stream with optional reorg
        let reorg_overlay_manager = overlay_manager.clone();
        let consensus_engine_stream = UnboundedReceiverStream::from(consensus_engine_rx)
            .maybe_skip_fcu(node_config.debug.skip_fcu)
            .maybe_skip_new_payload(node_config.debug.skip_new_payload)
            .maybe_reorg(
                ctx.blockchain_db().clone(),
                ctx.components().evm_config().clone(),
                || async {
                    validator_builder
                        .build_tree_validator(
                            &add_ons_ctx,
                            engine_tree_config.clone(),
                            reorg_overlay_manager.clone(),
                        )
                        .await
                },
                node_config.debug.reorg_frequency,
                node_config.debug.reorg_depth,
            )
            .await?
            // Store messages _after_ skipping so that `replay-engine` command
            // would replay only the messages that were observed by the engine
            // during this run.
            .maybe_store_messages(node_config.debug.engine_api_store.clone());

        // Shared persisted-head counter. Written by the engine tree handler on persistence
        // completion and read by Diesis consumers to gate overlay eviction.
        let persisted_head = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

        let engine_kind = if ctx.chain_spec().is_optimism() {
            EngineApiKind::OpStack
        } else {
            EngineApiKind::Ethereum
        };

        let (backfill_client, backfill_factory) =
            (network_client.clone(), ctx.provider_factory().clone());
        let (mut orchestrator, writer_fence_handle) = EngineOrchestratorBuilder {
            engine_kind,
            consensus,
            client: network_client,
            incoming_requests: Box::pin(consensus_engine_stream),
            pipeline,
            pipeline_task_spawner: ctx.task_executor().clone(),
            provider: ctx.provider_factory().clone(),
            blockchain_db: ctx.blockchain_db().clone(),
            pruner,
            payload_builder: ctx.components().payload_builder_handle().clone(),
            payload_validator: engine_validator,
            overlay_manager,
            tree_config: engine_tree_config,
            sync_metrics_tx: ctx.sync_metrics_tx(),
            evm_config: ctx.components().evm_config().clone(),
            runtime: ctx.task_executor().clone(),
            persisted_head_notifier: Arc::clone(&persisted_head),
            writer_fence_bootstrap,
            require_tagged_forkchoice,
        }
        .build_with_backfill(|pipeline, runtime| {
            backfill.build(BackfillContext::new(
                pipeline,
                backfill_client,
                backfill_factory,
                runtime,
            ))
        })?;

        info!(target: "reth::cli", "Consensus engine initialized");

        #[expect(clippy::needless_continue)]
        let events = stream_select!(
            event_sender.new_listener().map(Into::into),
            pipeline_events.map(Into::into),
            ctx.consensus_layer_events(),
            pruner_events.map(Into::into),
            static_file_producer_events.map(Into::into),
        );

        ctx.task_executor().spawn_critical_task(
            "events task",
            node::handle_events(
                Some(Box::new(ctx.components().network().clone())),
                Some(ctx.head().number),
                events,
            ),
        );

        let RpcHandle {
            rpc_server_handles,
            rpc_registry,
            engine_events,
            beacon_engine_handle,
            engine_shutdown: _,
            executed_block_tx: _,
            persisted_head: _,
            writer_fence: _,
        } = add_ons.launch_add_ons(add_ons_ctx).await?;

        // Create engine shutdown handle
        let (engine_shutdown, shutdown_rx) = EngineShutdown::new();

        // Run consensus engine to completion
        let initial_target = ctx.initial_backfill_target(disabled_stages)?;
        let initial_backfill_permit = if initial_target.is_some() {
            Some(writer_fence_handle.reserve_backfill_start().await?)
        } else {
            writer_fence_handle.open_qualified_ingress().await?;
            None
        };
        let mut built_payloads = ctx
            .components()
            .payload_builder_handle()
            .subscribe()
            .await
            .map_err(|e| eyre::eyre!("Failed to subscribe to payload builder events: {:?}", e))?
            .into_built_payload_stream()
            .fuse();

        let chainspec = ctx.chain_spec();
        let provider = ctx.blockchain_db().clone();
        let (exit, rx) = oneshot::channel();
        let terminate_after_backfill = ctx.terminate_after_initial_backfill();
        let startup_sync_state_idle = ctx.node_config().debug.startup_sync_state_idle;

        // Channel for typed direct executed-block admission from the Diesis pipeline. The
        // acknowledgement proves only engine-tree admission; forkchoice and persistence remain
        // separate. Created outside the async block so the sender can be exposed on RpcHandle.
        let (executed_block_ingress_tx, executed_block_rx) =
            tokio::sync::mpsc::channel::<
                ExecutedBlockInsertRequest<<T::Types as reth_node_api::NodeTypes>::Primitives>,
            >(DIESIS_EXECUTED_BLOCK_CHANNEL_CAPACITY);
        let executed_block_tx = ExecutedBlockInsertSender::new(
            executed_block_ingress_tx,
            DIESIS_EXECUTED_BLOCK_CHANNEL_CAPACITY,
        );

        info!(target: "reth::cli", "Starting consensus engine");
        let consensus_engine = move |mut on_graceful_shutdown| async move {
            let mut res = Ok(());
            if let Some(initial_target) = initial_target {
                debug!(target: "reth::cli", %initial_target,  "start backfill sync");
                // network_handle's sync state is already initialized at Syncing
                if let Err(error) = orchestrator.start_backfill_sync(
                    initial_target,
                    initial_backfill_permit.expect("permit reserved with startup target"),
                ) {
                    let _ = exit.send(Err(eyre::eyre!(error)));
                    return
                }
            } else if startup_sync_state_idle {
                network_handle.update_sync_state(SyncState::Idle);
            }

            let mut shutdown_rx = shutdown_rx.fuse();
            let mut executed_block_rx = executed_block_rx;

            // advance the chain and await payloads built locally to add into the engine api
            // tree handler to prevent re-execution if that block is received as payload from
            // the CL
            loop {
                tokio::select! {
                    event = orchestrator.next() => {
                        let Some(event) = event else { break };
                        debug!(target: "reth::cli", "Event: {event}");
                        match event {
                            ChainEvent::BackfillSyncFinished => {
                                if terminate_after_backfill {
                                    debug!(target: "reth::cli", "Terminating after initial backfill");
                                    break
                                }
                                if startup_sync_state_idle {
                                    network_handle.update_sync_state(SyncState::Idle);
                                }
                            }
                            ChainEvent::BackfillSyncStarted => {
                                network_handle.update_sync_state(SyncState::Syncing);
                            }
                            ChainEvent::FatalError => {
                                error!(target: "reth::cli", "Fatal error in consensus engine");
                                res = Err(eyre::eyre!("Fatal error in consensus engine"));
                                break
                            }
                            ChainEvent::Handler(ev) => {
                                if let Some(head) = ev.canonical_header() {
                                    // Once we're progressing via live sync, we can consider the node is not syncing anymore
                                    network_handle.update_sync_state(SyncState::Idle);
                                    let head_block = Head {
                                        number: head.number(),
                                        hash: head.hash(),
                                        difficulty: head.difficulty(),
                                        timestamp: head.timestamp(),
                                        total_difficulty: chainspec.final_paris_total_difficulty()
                                            .filter(|_| chainspec.is_paris_active_at_block(head.number()))
                                            .unwrap_or_default(),
                                    };
                                    network_handle.update_status(head_block);

                                    let updated = BlockRangeUpdate {
                                        earliest: provider.earliest_block_number().unwrap_or_default(),
                                        latest: head.number(),
                                        latest_hash: head.hash(),
                                    };
                                    network_handle.update_block_range(updated);
                                }
                                event_sender.notify(ev);
                            }
                        }
                    }
                    Some(payload) = built_payloads.next(), if !built_payloads.is_terminated() => {
                        if let Some(executed_block) = payload.executed_block() {
                            debug!(target: "reth::cli", block=?executed_block.recovered_block.num_hash(),  "inserting built payload");
                            orchestrator.handler_mut().handler_mut().on_event(EngineApiRequest::InsertExecutedBlock(executed_block).into());
                        }
                    }
                    Some(request) = executed_block_rx.recv() => {
                        debug!(
                            target: "reth::cli",
                            identity=?request.identity(),
                            block=?request.block().recovered_block().num_hash(),
                            "conditionally inserting pipeline executed block (direct insert)"
                        );
                        orchestrator.handler_mut().handler_mut().on_event(
                            EngineApiRequest::InsertExecutedBlockIfCanonical(request).into()
                        );
                    }
                    shutdown_req = &mut shutdown_rx => {
                        if let Ok(req) = shutdown_req {
                            debug!(target: "reth::cli", "received engine shutdown request");
                            orchestrator.handler_mut().handler_mut().on_event(
                                FromOrchestrator::Terminate { tx: req.done_tx }.into()
                            );
                        }
                    }
                    _guard = &mut on_graceful_shutdown => {
                        // Shutdown signal received.
                        // Send Terminate so the engine OS thread can exit cleanly before we
                        // drop the orchestrator.
                        debug!(target: "reth::cli", "shutdown signal received, terminating engine");
                        let (done_tx, done_rx) = oneshot::channel();
                        orchestrator.handler_mut().handler_mut().on_event(
                            FromOrchestrator::Terminate { tx: done_tx }.into()
                        );
                        let _ = done_rx.await;
                        break;
                    }
                }
            }

            let _ = exit.send(res);
        };
        ctx.task_executor()
            .spawn_critical_with_graceful_shutdown_signal("consensus engine", consensus_engine);

        let engine_events_for_ethstats = engine_events.new_listener();

        let full_node = FullNode {
            evm_config: ctx.components().evm_config().clone(),
            pool: ctx.components().pool().clone(),
            network: ctx.components().network().clone(),
            provider: ctx.node_adapter().provider.clone(),
            payload_builder_handle: ctx.components().payload_builder_handle().clone(),
            task_executor: ctx.task_executor().clone(),
            config: ctx.node_config().clone(),
            data_dir: ctx.data_dir().clone(),
            add_ons_handle: RpcHandle {
                rpc_server_handles,
                rpc_registry,
                engine_events,
                beacon_engine_handle,
                engine_shutdown,
                executed_block_tx: Some(executed_block_tx),
                persisted_head: std::sync::Arc::clone(&persisted_head),
                writer_fence: Some(writer_fence_handle),
            },
        };
        // Notify on node started
        on_node_started.on_event(FullNode::clone(&full_node))?;

        ctx.spawn_ethstats(engine_events_for_ethstats).await?;

        let handle = NodeHandle {
            node_exit_future: NodeExitFuture::new(async { rx.await? }),
            node: full_node,
        };

        Ok(handle)
    }

    /// Returns this launcher with the engine's backfill built by `backfill`.
    pub fn with_backfill<B2>(self, backfill: B2) -> EngineNodeLauncher<B2> {
        let Self { ctx, engine_tree_config, writer_fence_bootstrap, .. } = self;
        EngineNodeLauncher { ctx, engine_tree_config, backfill, writer_fence_bootstrap }
    }
}

impl<N, DB, T, CB, AO, B> LaunchNode<NodeBuilderWithComponents<T, CB, AO>> for EngineNodeLauncher<B>
where
    T: FullNodeTypes<
        Types = N,
        DB = DB,
        Provider = BlockchainProvider<NodeTypesWithDBAdapter<N, DB>>,
    >,
    N: Node<RethFullAdapter<DB, N>> + NodeTypesForProvider,
    DB: Database + DatabaseMetrics + Clone + Unpin + 'static,
    CB: NodeComponentsBuilder<T> + 'static,
    AO: RethRpcAddOns<NodeAdapter<T, CB::Components>>
        + EngineValidatorAddOn<NodeAdapter<T, CB::Components>>
        + 'static,
    B: BackfillSyncBuilder<NodeTypesWithDBAdapter<N, DB>, BackfillClientFor<T, CB::Components>>
        + 'static,
{
    type Node = NodeHandle<NodeAdapter<T, CB::Components>, AO>;
    type Future = Pin<Box<dyn Future<Output = eyre::Result<Self::Node>> + Send>>;

    fn launch_node(self, target: NodeBuilderWithComponents<T, CB, AO>) -> Self::Future {
        Box::pin(self.launch_node(target))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        accept_writer_fence_bootstrap, EngineNodeLauncher, ExecutedBlockInsertRequest,
        ExecutedBlockInsertSender, DIESIS_EXECUTED_BLOCK_CHANNEL_CAPACITY,
    };
    use reth_engine_tree::writer_fence::{WriterFenceBootstrap, WriterFenceError};

    #[test]
    fn supplied_bootstrap_is_consumed_only_at_the_exact_launcher_path() {
        let data_dir = tempfile::tempdir().unwrap();
        let expected = EngineNodeLauncher::writer_fence_journal_path(data_dir.path());
        let bootstrap = WriterFenceBootstrap::acquire(expected.clone()).unwrap();
        let accepted = accept_writer_fence_bootstrap(Some(bootstrap), expected.clone()).unwrap();
        assert_eq!(accepted.journal_path(), expected);
        // The retained owner lock excludes a second clean-only acquisition while consumed.
        assert!(matches!(
            WriterFenceBootstrap::acquire(expected.clone()),
            Err(WriterFenceError::Journal { .. })
        ));
        drop(accepted);

        let other_dir = tempfile::tempdir().unwrap();
        let foreign = WriterFenceBootstrap::acquire(EngineNodeLauncher::writer_fence_journal_path(
            other_dir.path(),
        ))
        .unwrap();
        assert!(matches!(
            accept_writer_fence_bootstrap(Some(foreign), expected.clone()),
            Err(WriterFenceError::Journal { message }) if message.contains("differs from launcher path")
        ));

        // Default startup keeps clean-only acquisition at the exact path.
        let default = accept_writer_fence_bootstrap(None, expected.clone()).unwrap();
        assert_eq!(default.journal_path(), expected);
    }

    #[test]
    fn supplied_bootstrap_that_is_no_longer_exactly_clean_is_refused() {
        let data_dir = tempfile::tempdir().unwrap();
        let expected = EngineNodeLauncher::writer_fence_journal_path(data_dir.path());
        let bootstrap = WriterFenceBootstrap::acquire(expected.clone()).unwrap();
        let clean = std::fs::read(&expected).unwrap();
        // Any byte change to the retained record, including a corrupt or replaced journal,
        // must be caught by the consumption-time recheck rather than trusted from earlier.
        let mut changed = clean.clone();
        changed[8] = 2;
        std::fs::write(&expected, &changed).unwrap();
        assert!(matches!(
            accept_writer_fence_bootstrap(Some(bootstrap), expected.clone()),
            Err(WriterFenceError::Journal { .. })
        ));
        std::fs::write(&expected, &clean[..clean.len() - 1]).unwrap();
        let bootstrap = WriterFenceBootstrap::inspect(expected.clone());
        assert!(matches!(bootstrap, Err(WriterFenceError::Journal { .. })));
    }

    #[test]
    fn diesis_executed_block_channel_capacity_is_bounded() {
        let (tx, _rx) = tokio::sync::mpsc::channel::<ExecutedBlockInsertRequest>(
            DIESIS_EXECUTED_BLOCK_CHANNEL_CAPACITY,
        );
        let sender = ExecutedBlockInsertSender::new(tx, DIESIS_EXECUTED_BLOCK_CHANNEL_CAPACITY);

        assert_eq!(sender.capacity(), DIESIS_EXECUTED_BLOCK_CHANNEL_CAPACITY);
        assert_eq!(sender.available_capacity(), DIESIS_EXECUTED_BLOCK_CHANNEL_CAPACITY);
    }
}
