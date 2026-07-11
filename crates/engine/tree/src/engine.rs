//! An engine API handler for the chain.

use crate::{
    backfill::BackfillAction,
    chain::{ChainHandler, FromOrchestrator, HandlerEvent},
    download::{BlockDownloader, DownloadAction, DownloadOutcome},
};
use alloy_eips::BlockNumHash;
use alloy_primitives::{map::B256Set, B256};
use crossbeam_channel::Sender;
use futures::{Stream, StreamExt};
use reth_chain_state::ExecutedBlock;
use reth_engine_primitives::{BeaconEngineMessage, ConsensusEngineEvent};
use reth_ethereum_primitives::EthPrimitives;
use reth_payload_primitives::PayloadTypes;
use reth_primitives_traits::{Block, NodePrimitives, SealedBlock};
use std::{
    fmt::Display,
    sync::Arc,
    task::{ready, Context, Poll},
};
use tokio::sync::{
    mpsc::{self, UnboundedReceiver},
    oneshot, OwnedSemaphorePermit, Semaphore,
};

/// A [`ChainHandler`] that advances the chain based on incoming requests (CL engine API).
///
/// This is a general purpose request handler with network access.
/// This type listens for incoming messages and processes them via the configured request handler.
///
/// ## Overview
///
/// This type is an orchestrator for incoming messages and responsible for delegating requests
/// received from the CL to the handler.
///
/// It is responsible for handling the following:
/// - Delegating incoming requests to the [`EngineRequestHandler`].
/// - Advancing the [`EngineRequestHandler`] by polling it and emitting events.
/// - Downloading blocks on demand from the network if requested by the [`EngineApiRequestHandler`].
///
/// The core logic is part of the [`EngineRequestHandler`], which is responsible for processing the
/// incoming requests.
#[derive(Debug)]
pub struct EngineHandler<T, S, D> {
    /// Processes requests.
    ///
    /// This type is responsible for processing incoming requests.
    handler: T,
    /// Receiver for incoming requests (from the engine API endpoint) that need to be processed.
    incoming_requests: S,
    /// A downloader to download blocks on demand.
    downloader: D,
}

impl<T, S, D> EngineHandler<T, S, D> {
    /// Creates a new [`EngineHandler`] with the given handler and downloader and incoming stream of
    /// requests.
    pub const fn new(handler: T, downloader: D, incoming_requests: S) -> Self
    where
        T: EngineRequestHandler,
    {
        Self { handler, incoming_requests, downloader }
    }

    /// Returns a mutable reference to the request handler.
    pub const fn handler_mut(&mut self) -> &mut T {
        &mut self.handler
    }
}

impl<T, S, D> ChainHandler for EngineHandler<T, S, D>
where
    T: EngineRequestHandler<Block = D::Block>,
    S: Stream + Send + Sync + Unpin + 'static,
    <S as Stream>::Item: Into<T::Request>,
    D: BlockDownloader,
{
    type Event = T::Event;

    fn on_event(&mut self, event: FromOrchestrator) {
        // delegate event to the handler
        self.handler.on_event(event.into());
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<HandlerEvent<Self::Event>> {
        loop {
            // drain the handler first
            while let Poll::Ready(ev) = self.handler.poll(cx) {
                match ev {
                    RequestHandlerEvent::HandlerEvent(ev) => {
                        return match ev {
                            HandlerEvent::BackfillAction(target) => {
                                // bubble up backfill sync request
                                self.downloader.on_action(DownloadAction::Clear);
                                Poll::Ready(HandlerEvent::BackfillAction(target))
                            }
                            HandlerEvent::Event(ev) => {
                                // bubble up the event
                                Poll::Ready(HandlerEvent::Event(ev))
                            }
                            HandlerEvent::FatalError => Poll::Ready(HandlerEvent::FatalError),
                        }
                    }
                    RequestHandlerEvent::Download(req) => {
                        // delegate download request to the downloader
                        self.downloader.on_action(DownloadAction::Download(req));
                    }
                }
            }

            // pop the next incoming request
            if let Poll::Ready(Some(req)) = self.incoming_requests.poll_next_unpin(cx) {
                // and delegate the request to the handler
                self.handler.on_event(FromEngine::Request(req.into()));
                // skip downloading in this iteration to allow the handler to process the request
                continue
            }

            // advance the downloader
            if let Poll::Ready(outcome) = self.downloader.poll(cx) {
                if let DownloadOutcome::Blocks(blocks) = outcome {
                    // delegate the downloaded blocks to the handler
                    self.handler.on_event(FromEngine::DownloadedBlocks(blocks));
                }
                continue
            }

            return Poll::Pending
        }
    }
}

/// A type that processes incoming requests (e.g. requests from the consensus layer, engine API,
/// such as newPayload).
///
/// ## Control flow
///
/// Requests and certain updates, such as a change in backfill sync status, are delegated to this
/// type via [`EngineRequestHandler::on_event`]. This type is responsible for processing the
/// incoming requests and advancing the chain and emit events when it is polled.
pub trait EngineRequestHandler: Send + Sync {
    /// Event type this handler can emit
    type Event: Send;
    /// The request type this handler can process.
    type Request;
    /// Type of the block sent in [`FromEngine::DownloadedBlocks`] variant.
    type Block: Block;

    /// Informs the handler about an event from the [`EngineHandler`].
    fn on_event(&mut self, event: FromEngine<Self::Request, Self::Block>);

    /// Advances the handler.
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<RequestHandlerEvent<Self::Event>>;
}

/// An [`EngineRequestHandler`] that processes engine API requests by delegating to an execution
/// task.
///
/// This type is responsible for advancing the chain during live sync (following the tip of the
/// chain).
///
/// It advances the chain based on received engine API requests by delegating them to the tree
/// executor.
///
/// There are two types of requests that can be processed:
///
/// - `on_new_payload`: Executes the payload and inserts it into the tree. These are allowed to be
///   processed concurrently.
/// - `on_forkchoice_updated`: Updates the fork choice based on the new head. These require write
///   access to the database and are skipped if the handler can't acquire exclusive access to the
///   database.
///
/// In case required blocks are missing, the handler will request them from the network, by emitting
/// a download request upstream.
#[derive(Debug)]
pub struct EngineApiRequestHandler<Request, N: NodePrimitives> {
    /// channel to send messages to the tree to execute the payload.
    to_tree: Sender<FromEngine<Request, N::Block>>,
    /// channel to receive messages from the tree.
    from_tree: UnboundedReceiver<EngineApiEvent<N>>,
}

impl<Request, N: NodePrimitives> EngineApiRequestHandler<Request, N> {
    /// Creates a new `EngineApiRequestHandler`.
    pub const fn new(
        to_tree: Sender<FromEngine<Request, N::Block>>,
        from_tree: UnboundedReceiver<EngineApiEvent<N>>,
    ) -> Self {
        Self { to_tree, from_tree }
    }
}

impl<T, N> EngineRequestHandler for EngineApiRequestHandler<EngineApiRequest<T, N>, N>
where
    T: PayloadTypes,
    N: NodePrimitives,
{
    type Event = ConsensusEngineEvent<N>;
    type Request = EngineApiRequest<T, N>;
    type Block = N::Block;

    fn on_event(&mut self, event: FromEngine<Self::Request, Self::Block>) {
        // delegate to the tree
        if let Err(error) = self.to_tree.send(event) &&
            let FromEngine::Request(EngineApiRequest::InsertExecutedBlockIfCanonical(request)) =
                error.0
        {
            request.reject(ExecutedBlockInsertError::EngineUnavailable);
        }
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<RequestHandlerEvent<Self::Event>> {
        let Some(ev) = ready!(self.from_tree.poll_recv(cx)) else {
            return Poll::Ready(RequestHandlerEvent::HandlerEvent(HandlerEvent::FatalError))
        };

        let ev = match ev {
            EngineApiEvent::BeaconConsensus(ev) => {
                RequestHandlerEvent::HandlerEvent(HandlerEvent::Event(ev))
            }
            EngineApiEvent::BackfillAction(action) => {
                RequestHandlerEvent::HandlerEvent(HandlerEvent::BackfillAction(action))
            }
            EngineApiEvent::Download(action) => RequestHandlerEvent::Download(action),
        };
        Poll::Ready(ev)
    }
}

/// The type for specifying the kind of engine api.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EngineApiKind {
    /// The chain contains Ethereum configuration.
    #[default]
    Ethereum,
    /// The chain contains Optimism configuration.
    OpStack,
}

impl EngineApiKind {
    /// Returns true if this is the ethereum variant
    pub const fn is_ethereum(&self) -> bool {
        matches!(self, Self::Ethereum)
    }

    /// Returns true if this is the ethereum variant
    pub const fn is_opstack(&self) -> bool {
        matches!(self, Self::OpStack)
    }
}

/// The request variants that the engine API handler can receive.
#[derive(Debug)]
pub enum EngineApiRequest<T: PayloadTypes, N: NodePrimitives> {
    /// A request received from the consensus engine.
    Beacon(BeaconEngineMessage<T>),
    /// Request to insert an already executed block, e.g. via payload building.
    InsertExecutedBlock(ExecutedBlock<N>),
    /// Request to insert an already executed block only if it is the direct child of the expected
    /// canonical head.
    InsertExecutedBlockIfCanonical(ExecutedBlockInsertRequest<N>),
}

impl<T: PayloadTypes, N: NodePrimitives> Display for EngineApiRequest<T, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Beacon(msg) => msg.fmt(f),
            Self::InsertExecutedBlock(block) => {
                write!(f, "InsertExecutedBlock({:?})", block.recovered_block().num_hash())
            }
            Self::InsertExecutedBlockIfCanonical(request) => write!(
                f,
                "InsertExecutedBlockIfCanonical(expected={:?}, block={:?})",
                request.expected_canonical_head(),
                request.block().recovered_block().num_hash()
            ),
        }
    }
}

/// An executed block whose admission is conditional on an exact canonical head.
#[derive(Debug)]
pub struct ExecutedBlockInsertRequest<N: NodePrimitives = EthPrimitives> {
    expected_canonical_head: BlockNumHash,
    block: ExecutedBlock<N>,
    response: oneshot::Sender<Result<(), ExecutedBlockInsertError>>,
    permit: OwnedSemaphorePermit,
}

impl<N: NodePrimitives> ExecutedBlockInsertRequest<N> {
    fn new(
        expected_canonical_head: BlockNumHash,
        block: ExecutedBlock<N>,
        permit: OwnedSemaphorePermit,
    ) -> (Self, oneshot::Receiver<Result<(), ExecutedBlockInsertError>>) {
        let (response, receiver) = oneshot::channel();
        (Self { expected_canonical_head, block, response, permit }, receiver)
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        expected_canonical_head: BlockNumHash,
        block: ExecutedBlock<N>,
    ) -> (Self, oneshot::Receiver<Result<(), ExecutedBlockInsertError>>) {
        let semaphore = Arc::new(Semaphore::new(1));
        let permit = semaphore.try_acquire_owned().expect("test semaphore has one permit");
        Self::new(expected_canonical_head, block, permit)
    }

    /// Returns the canonical head that must still be current when the request is handled.
    pub const fn expected_canonical_head(&self) -> BlockNumHash {
        self.expected_canonical_head
    }

    /// Returns the executed block awaiting admission.
    pub const fn block(&self) -> &ExecutedBlock<N> {
        &self.block
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        BlockNumHash,
        ExecutedBlock<N>,
        oneshot::Sender<Result<(), ExecutedBlockInsertError>>,
        OwnedSemaphorePermit,
    ) {
        (self.expected_canonical_head, self.block, self.response, self.permit)
    }

    fn reject(self, error: ExecutedBlockInsertError) {
        let (_, _, response, permit) = self.into_parts();
        drop(permit);
        let _ = response.send(Err(error));
    }
}

/// Bounded handle for acknowledged direct insertion into the engine tree.
///
/// The shared permit is retained while a request is in either the Tokio ingress queue or the
/// engine tree's crossbeam queue. This bounds total outstanding direct-insert work rather than
/// only the first queue. Callers cannot construct an unpermitted request.
#[derive(Debug, Clone)]
pub struct ExecutedBlockInsertSender<N: NodePrimitives = EthPrimitives> {
    sender: mpsc::Sender<ExecutedBlockInsertRequest<N>>,
    permits: Arc<Semaphore>,
    capacity: usize,
}

impl<N: NodePrimitives> ExecutedBlockInsertSender<N> {
    /// Creates a sender with an end-to-end outstanding-request limit.
    pub fn new(sender: mpsc::Sender<ExecutedBlockInsertRequest<N>>, capacity: usize) -> Self {
        assert!(capacity > 0, "direct insert capacity must be positive");
        Self { sender, permits: Arc::new(Semaphore::new(capacity)), capacity }
    }

    /// Conditionally inserts an executed block and waits for the engine tree's acknowledgement.
    ///
    /// Capacity exhaustion is reported immediately. A successful return means the tree validated
    /// the expected canonical parent and inserted the block before acknowledging it.
    pub async fn insert(
        &self,
        expected_canonical_head: BlockNumHash,
        block: ExecutedBlock<N>,
    ) -> Result<(), ExecutedBlockInsertError> {
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| ExecutedBlockInsertError::QueueFull { capacity: self.capacity })?;
        let (request, response) =
            ExecutedBlockInsertRequest::new(expected_canonical_head, block, permit);
        self.sender.send(request).await.map_err(|_| ExecutedBlockInsertError::EngineUnavailable)?;
        response.await.map_err(|_| ExecutedBlockInsertError::AcknowledgementDropped)?
    }

    /// Maximum number of direct-insert requests that may be outstanding end to end.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of requests that can be admitted without waiting for prior work to complete.
    pub fn available_capacity(&self) -> usize {
        self.permits.available_permits()
    }
}

/// Reason a conditional executed-block insertion was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExecutedBlockInsertError {
    /// The bounded direct-insert path has reached its end-to-end capacity.
    #[error("direct block admission queue is full (capacity {capacity})")]
    QueueFull {
        /// Configured outstanding-request limit.
        capacity: usize,
    },
    /// The engine ingress or engine tree is no longer available.
    #[error("engine tree is unavailable")]
    EngineUnavailable,
    /// The tree-side acknowledgement was dropped, so the admission outcome is ambiguous.
    #[error("direct block admission acknowledgement was dropped")]
    AcknowledgementDropped,
    /// The canonical head changed before the engine tree handled the request.
    #[error("canonical head mismatch: expected {expected:?}, actual {actual:?}")]
    CanonicalHeadMismatch {
        /// Head supplied by the caller.
        expected: BlockNumHash,
        /// Head observed by the engine tree.
        actual: BlockNumHash,
    },
    /// The expected canonical head cannot have a child because its number is already maximal.
    #[error("canonical head block number cannot be incremented: {head:?}")]
    CanonicalHeadNumberOverflow {
        /// Canonical head whose number overflowed.
        head: BlockNumHash,
    },
    /// The submitted block number is not exactly one greater than the canonical head.
    #[error("block number mismatch: expected {expected}, actual {actual}")]
    BlockNumberMismatch {
        /// Required child block number.
        expected: u64,
        /// Submitted block number.
        actual: u64,
    },
    /// The submitted block does not name the canonical head as its parent.
    #[error("parent hash mismatch: expected {expected}, actual {actual}")]
    ParentHashMismatch {
        /// Required parent hash.
        expected: B256,
        /// Submitted parent hash.
        actual: B256,
    },
}

#[cfg(test)]
mod direct_insert_sender_tests {
    use super::*;
    use reth_chain_state::test_utils::TestBlockBuilder;
    use reth_ethereum_engine_primitives::EthEngineTypes;

    fn executed_block(number: u64, parent_hash: B256) -> ExecutedBlock {
        TestBlockBuilder::eth().get_executed_block_with_number(number, parent_hash)
    }

    fn sender_with_capacity(
        capacity: usize,
    ) -> (ExecutedBlockInsertSender, mpsc::Receiver<ExecutedBlockInsertRequest>) {
        let (tx, rx) = mpsc::channel(capacity);
        (ExecutedBlockInsertSender::new(tx, capacity), rx)
    }

    #[tokio::test]
    async fn sixty_fifth_request_is_full_after_tokio_to_crossbeam_forwarding() {
        const CAPACITY: usize = 64;
        let (sender, mut ingress) = sender_with_capacity(CAPACITY);
        let expected_head = BlockNumHash::new(0, B256::random());
        let (to_tree, from_ingress) = crossbeam_channel::unbounded::<
            FromEngine<
                EngineApiRequest<EthEngineTypes, EthPrimitives>,
                reth_ethereum_primitives::Block,
            >,
        >();

        let mut inserts = Vec::with_capacity(CAPACITY);
        for _ in 0..CAPACITY {
            inserts.push(tokio::spawn({
                let sender = sender.clone();
                async move {
                    sender.insert(expected_head, executed_block(1, expected_head.hash)).await
                }
            }));
            let request = ingress.recv().await.expect("request reaches Tokio ingress");
            to_tree
                .send(FromEngine::Request(EngineApiRequest::InsertExecutedBlockIfCanonical(
                    request,
                )))
                .expect("request reaches the engine tree queue");
        }

        assert_eq!(sender.available_capacity(), 0);
        assert_eq!(
            sender.insert(expected_head, executed_block(1, expected_head.hash)).await,
            Err(ExecutedBlockInsertError::QueueFull { capacity: CAPACITY })
        );

        drop(from_ingress);
        for insert in inserts {
            assert_eq!(
                insert.await.unwrap(),
                Err(ExecutedBlockInsertError::AcknowledgementDropped)
            );
        }
        assert_eq!(sender.available_capacity(), CAPACITY);
    }

    #[tokio::test]
    async fn cancellation_before_enqueue_releases_permit() {
        let (raw_tx, mut ingress) = mpsc::channel(1);
        let sender = ExecutedBlockInsertSender::new(raw_tx, 2);
        let expected_head = BlockNumHash::new(0, B256::random());
        let first = tokio::spawn({
            let sender = sender.clone();
            async move { sender.insert(expected_head, executed_block(1, expected_head.hash)).await }
        });
        tokio::task::yield_now().await;

        let second = tokio::spawn({
            let sender = sender.clone();
            async move { sender.insert(expected_head, executed_block(1, expected_head.hash)).await }
        });
        tokio::task::yield_now().await;
        assert_eq!(sender.available_capacity(), 0);

        second.abort();
        assert!(second.await.unwrap_err().is_cancelled());
        assert_eq!(sender.available_capacity(), 1);

        drop(ingress.recv().await.expect("first request was enqueued"));
        assert_eq!(first.await.unwrap(), Err(ExecutedBlockInsertError::AcknowledgementDropped));
        assert_eq!(sender.available_capacity(), 2);
    }

    #[tokio::test]
    async fn cancellation_after_enqueue_releases_when_request_finishes() {
        let (sender, mut ingress) = sender_with_capacity(1);
        let expected_head = BlockNumHash::new(0, B256::random());
        let task = tokio::spawn({
            let sender = sender.clone();
            async move { sender.insert(expected_head, executed_block(1, expected_head.hash)).await }
        });
        let request = ingress.recv().await.expect("request was enqueued");
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(sender.available_capacity(), 0);

        drop(request);
        assert_eq!(sender.available_capacity(), 1);
    }

    #[tokio::test]
    async fn tree_completion_releases_capacity_before_ack_is_consumed() {
        let (sender, mut ingress) = sender_with_capacity(1);
        let expected_head = BlockNumHash::new(0, B256::random());
        let first = tokio::spawn({
            let sender = sender.clone();
            async move { sender.insert(expected_head, executed_block(1, expected_head.hash)).await }
        });
        let request = ingress.recv().await.expect("first request was enqueued");
        let (_, _, response, permit) = request.into_parts();
        drop(permit);
        response.send(Ok(())).expect("caller still awaits acknowledgement");

        assert_eq!(sender.available_capacity(), 1);
        assert_eq!(first.await.unwrap(), Ok(()));

        let second = tokio::spawn({
            let sender = sender.clone();
            async move { sender.insert(expected_head, executed_block(1, expected_head.hash)).await }
        });
        let request = ingress.recv().await.expect("next request admitted at capacity one");
        request.reject(ExecutedBlockInsertError::EngineUnavailable);
        assert_eq!(second.await.unwrap(), Err(ExecutedBlockInsertError::EngineUnavailable));
    }

    #[tokio::test]
    async fn closed_tokio_ingress_is_typed_and_leak_free() {
        let (sender, ingress) = sender_with_capacity(1);
        drop(ingress);
        let expected_head = BlockNumHash::new(0, B256::random());

        assert_eq!(
            sender.insert(expected_head, executed_block(1, expected_head.hash)).await,
            Err(ExecutedBlockInsertError::EngineUnavailable)
        );
        assert_eq!(sender.available_capacity(), 1);
    }

    #[tokio::test]
    async fn closed_crossbeam_tree_ingress_is_typed_and_leak_free() {
        let (sender, mut ingress) = sender_with_capacity(1);
        let expected_head = BlockNumHash::new(0, B256::random());
        let insert = tokio::spawn({
            let sender = sender.clone();
            async move { sender.insert(expected_head, executed_block(1, expected_head.hash)).await }
        });
        let request = ingress.recv().await.expect("request was enqueued");

        let (to_tree, tree_rx) = crossbeam_channel::unbounded();
        drop(tree_rx);
        let (_from_tree_tx, from_tree_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut handler = EngineApiRequestHandler::<
            EngineApiRequest<EthEngineTypes, EthPrimitives>,
            EthPrimitives,
        >::new(to_tree, from_tree_rx);
        handler.on_event(FromEngine::Request(EngineApiRequest::InsertExecutedBlockIfCanonical(
            request,
        )));

        assert_eq!(insert.await.unwrap(), Err(ExecutedBlockInsertError::EngineUnavailable));
        assert_eq!(sender.available_capacity(), 1);
    }
}

impl<T: PayloadTypes, N: NodePrimitives> From<BeaconEngineMessage<T>> for EngineApiRequest<T, N> {
    fn from(msg: BeaconEngineMessage<T>) -> Self {
        Self::Beacon(msg)
    }
}

impl<T: PayloadTypes, N: NodePrimitives> From<EngineApiRequest<T, N>>
    for FromEngine<EngineApiRequest<T, N>, N::Block>
{
    fn from(req: EngineApiRequest<T, N>) -> Self {
        Self::Request(req)
    }
}

/// Events emitted by the engine API handler.
#[derive(Debug)]
pub enum EngineApiEvent<N: NodePrimitives = EthPrimitives> {
    /// Event from the consensus engine.
    // TODO(mattsse): find a more appropriate name for this variant, consider phasing it out.
    BeaconConsensus(ConsensusEngineEvent<N>),
    /// Backfill action is needed.
    BackfillAction(BackfillAction),
    /// Block download is needed.
    Download(DownloadRequest),
}

impl<N: NodePrimitives> EngineApiEvent<N> {
    /// Returns `true` if the event is a backfill action.
    pub const fn is_backfill_action(&self) -> bool {
        matches!(self, Self::BackfillAction(_))
    }
}

impl<N: NodePrimitives> From<ConsensusEngineEvent<N>> for EngineApiEvent<N> {
    fn from(event: ConsensusEngineEvent<N>) -> Self {
        Self::BeaconConsensus(event)
    }
}

/// Events received from the engine.
#[derive(Debug)]
pub enum FromEngine<Req, B: Block> {
    /// Event from the top level orchestrator.
    Event(FromOrchestrator),
    /// Request from the engine.
    Request(Req),
    /// Downloaded blocks from the network.
    DownloadedBlocks(Vec<SealedBlock<B>>),
}

impl<Req: Display, B: Block> Display for FromEngine<Req, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Event(ev) => write!(f, "Event({ev:?})"),
            Self::Request(req) => write!(f, "Request({req})"),
            Self::DownloadedBlocks(blocks) => {
                write!(f, "DownloadedBlocks({} blocks)", blocks.len())
            }
        }
    }
}

impl<Req, B: Block> From<FromOrchestrator> for FromEngine<Req, B> {
    fn from(event: FromOrchestrator) -> Self {
        Self::Event(event)
    }
}

/// Requests produced by a [`EngineRequestHandler`].
#[derive(Debug)]
pub enum RequestHandlerEvent<T> {
    /// An event emitted by the handler.
    HandlerEvent(HandlerEvent<T>),
    /// Request to download blocks.
    Download(DownloadRequest),
}

/// A request to download blocks from the network.
#[derive(Debug)]
pub enum DownloadRequest {
    /// Download the given set of blocks.
    BlockSet(B256Set),
    /// Download the given range of blocks.
    BlockRange(B256, u64),
}

impl DownloadRequest {
    /// Returns a [`DownloadRequest`] for a single block.
    pub fn single_block(hash: B256) -> Self {
        Self::BlockSet(B256Set::from_iter([hash]))
    }
}
