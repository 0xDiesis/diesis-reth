use crate::{
    backfill::{BackfillAction, BackfillEvent, BackfillSync},
    writer_fence::{BackfillStartPermit, WriterFenceError},
};
use futures::Stream;
use reth_stages_api::{ControlFlow, PipelineTarget};
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    pin::Pin,
    task::{Context, Poll},
};
use tracing::*;

/// The type that drives the chain forward.
///
/// A state machine that orchestrates the components responsible for advancing the chain
///
///
/// ## Control flow
///
/// The [`ChainOrchestrator`] is responsible for controlling the backfill sync and additional hooks.
/// It polls the given `handler`, which is responsible for advancing the chain, how is up to the
/// handler. However, due to database restrictions (e.g. exclusive write access), following
/// invariants apply:
///  - If the handler requests a backfill run (e.g. [`BackfillAction::Start`]), the handler must
///    ensure that while the backfill sync is running, no other write access is granted.
///  - At any time the [`ChainOrchestrator`] can request exclusive write access to the database
///    (e.g. if pruning is required), but will not do so until the handler has acknowledged the
///    request for write access.
///
/// The [`ChainOrchestrator`] polls the [`ChainHandler`] to advance the chain and handles the
/// emitted events. Requests and events are passed to the [`ChainHandler`] via
/// [`ChainHandler::on_event`].
#[must_use = "Stream does nothing unless polled"]
#[derive(Debug)]
pub struct ChainOrchestrator<T, P>
where
    T: ChainHandler,
    P: BackfillSync,
{
    /// The handler for advancing the chain.
    handler: T,
    /// Controls backfill sync.
    backfill_sync: P,
    /// Exact engine actor allowed to authorize a direct startup pipeline spawn.
    writer_fence_actor: Option<u64>,
}

impl<T, P> ChainOrchestrator<T, P>
where
    T: ChainHandler + Unpin,
    P: BackfillSync + Unpin,
{
    /// Creates a new [`ChainOrchestrator`] with the given handler and backfill sync.
    pub const fn new(handler: T, backfill_sync: P) -> Self {
        Self { handler, backfill_sync, writer_fence_actor: None }
    }

    /// Bind startup pipeline authorization to one concrete engine actor incarnation.
    pub(crate) const fn with_writer_fence_actor(mut self, actor: u64) -> Self {
        self.writer_fence_actor = Some(actor);
        self
    }

    /// Returns the handler
    pub const fn handler(&self) -> &T {
        &self.handler
    }

    /// Returns a mutable reference to the handler
    pub const fn handler_mut(&mut self) -> &mut T {
        &mut self.handler
    }

    /// Triggers a backfill sync for the __valid__ given target.
    ///
    /// CAUTION: This function should be used with care and with a valid target.
    pub fn start_backfill_sync(
        &mut self,
        target: impl Into<PipelineTarget>,
        permit: BackfillStartPermit,
    ) -> Result<(), WriterFenceError> {
        let actor = self.writer_fence_actor.ok_or(WriterFenceError::RecoveryFenced)?;
        permit.authorize(actor)?;
        self.backfill_sync.on_action(BackfillAction::Start(target.into()));
        Ok(())
    }

    /// Internal function used to advance the chain.
    ///
    /// Polls the `ChainOrchestrator` for the next event.
    #[tracing::instrument(level = "debug", target = "engine::tree::chain_orchestrator", skip_all)]
    fn poll_next_event(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<ChainEvent<T::Event>> {
        let this = self.get_mut();

        // This loop polls the components
        //
        // 1. Polls the backfill sync to completion, if active.
        // 2. Advances the chain by polling the handler.
        'outer: loop {
            // try to poll the backfill sync to completion, if active
            match this.backfill_sync.poll(cx) {
                Poll::Ready(backfill_sync_event) => match backfill_sync_event {
                    BackfillEvent::Started(_) => {
                        // notify handler that backfill sync started
                        this.handler.on_event(FromOrchestrator::BackfillSyncStarted);
                        return Poll::Ready(ChainEvent::BackfillSyncStarted);
                    }
                    BackfillEvent::Finished(res) => {
                        return match res {
                            Ok(ctrl) => {
                                tracing::debug!(?ctrl, "backfill sync finished");
                                // notify handler that backfill sync finished
                                this.handler.on_event(FromOrchestrator::BackfillSyncFinished(ctrl));
                                Poll::Ready(ChainEvent::BackfillSyncFinished)
                            }
                            Err(err) => {
                                tracing::error!( %err, "backfill sync failed");
                                Poll::Ready(ChainEvent::FatalError)
                            }
                        }
                    }
                    BackfillEvent::TaskDropped(err) => {
                        tracing::error!( %err, "backfill sync task dropped");
                        return Poll::Ready(ChainEvent::FatalError);
                    }
                },
                Poll::Pending => {}
            }

            // poll the handler for the next event
            match this.handler.poll(cx) {
                Poll::Ready(handler_event) => {
                    match handler_event {
                        HandlerEvent::BackfillAction(action) => {
                            // forward action to backfill_sync
                            this.backfill_sync.on_action(action);
                        }
                        HandlerEvent::Event(ev) => {
                            // bubble up the event
                            return Poll::Ready(ChainEvent::Handler(ev));
                        }
                        HandlerEvent::FatalError => {
                            error!(target: "engine::tree", "Fatal error");
                            return Poll::Ready(ChainEvent::FatalError)
                        }
                    }
                }
                Poll::Pending => {
                    // no more events to process
                    break 'outer
                }
            }
        }

        Poll::Pending
    }
}

impl<T, P> Stream for ChainOrchestrator<T, P>
where
    T: ChainHandler + Unpin,
    P: BackfillSync + Unpin,
{
    type Item = ChainEvent<T::Event>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.as_mut().poll_next_event(cx).map(Some)
    }
}

/// Event emitted by the [`ChainOrchestrator`]
///
/// These are meant to be used for observability and debugging purposes.
#[derive(Debug)]
pub enum ChainEvent<T> {
    /// Backfill sync started
    BackfillSyncStarted,
    /// Backfill sync finished
    BackfillSyncFinished,
    /// Fatal error
    FatalError,
    /// Event emitted by the handler
    Handler(T),
}

impl<T: Display> Display for ChainEvent<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::BackfillSyncStarted => {
                write!(f, "BackfillSyncStarted")
            }
            Self::BackfillSyncFinished => {
                write!(f, "BackfillSyncFinished")
            }
            Self::FatalError => {
                write!(f, "FatalError")
            }
            Self::Handler(event) => {
                write!(f, "Handler({event})")
            }
        }
    }
}

/// A trait that advances the chain by handling actions.
///
/// This is intended to be implement the chain consensus logic, for example `engine` API.
///
/// ## Control flow
///
/// The [`ChainOrchestrator`] is responsible for advancing this handler through
/// [`ChainHandler::poll`] and handling the emitted events, for example
/// [`HandlerEvent::BackfillAction`] to start a backfill sync. Events from the [`ChainOrchestrator`]
/// are passed to the handler via [`ChainHandler::on_event`], e.g.
/// [`FromOrchestrator::BackfillSyncStarted`] once the backfill sync started or finished.
pub trait ChainHandler: Send + Sync {
    /// Event generated by this handler that orchestrator can bubble up;
    type Event: Send;

    /// Informs the handler about an event from the [`ChainOrchestrator`].
    fn on_event(&mut self, event: FromOrchestrator);

    /// Polls for actions that [`ChainOrchestrator`] should handle.
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<HandlerEvent<Self::Event>>;
}

/// Events/Requests that the [`ChainHandler`] can emit to the [`ChainOrchestrator`].
#[derive(Clone, Debug)]
pub enum HandlerEvent<T> {
    /// Request an action to backfill sync
    BackfillAction(BackfillAction),
    /// Other event emitted by the handler
    Event(T),
    /// Fatal error
    FatalError,
}

/// Internal events issued by the [`ChainOrchestrator`].
#[derive(Debug)]
pub enum FromOrchestrator {
    /// Invoked when backfill sync finished
    BackfillSyncFinished(ControlFlow),
    /// Invoked when backfill sync started
    BackfillSyncStarted,
    /// Gracefully terminate the engine service.
    ///
    /// When this variant is received, the engine will persist all remaining in-memory blocks
    /// to disk before shutting down. Once persistence is complete, a signal is sent through
    /// the oneshot channel to notify the caller.
    Terminate {
        /// Channel to signal termination completion.
        tx: tokio::sync::oneshot::Sender<()>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backfill::PipelineSync, test_utils::TestPipelineBuilder, writer_fence::BackfillStartPermit,
    };
    use alloy_primitives::B256;
    use assert_matches::assert_matches;
    use futures::{poll, StreamExt};
    use reth_chainspec::MAINNET;
    use reth_tasks::Runtime;
    use std::task::Poll;

    #[derive(Debug, Default)]
    struct IdleHandler;

    impl ChainHandler for IdleHandler {
        type Event = ();

        fn on_event(&mut self, _event: FromOrchestrator) {}

        fn poll(&mut self, _cx: &mut Context<'_>) -> Poll<HandlerEvent<Self::Event>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn actual_pipeline_spawn_requires_permit_from_bound_actor() {
        const ACTOR: u64 = 41;
        let pipeline = TestPipelineBuilder::new().build(MAINNET.clone());
        let pipeline_sync = PipelineSync::new(pipeline, Runtime::test());
        let mut orchestrator =
            ChainOrchestrator::new(IdleHandler, pipeline_sync).with_writer_fence_actor(ACTOR);
        let target = PipelineTarget::Sync(B256::repeat_byte(0x42));

        assert_matches!(
            orchestrator
                .start_backfill_sync(target, BackfillStartPermit::new_for_test(ACTOR + 1, 1),),
            Err(WriterFenceError::StaleCapability)
        );
        assert_matches!(poll!(orchestrator.next()), Poll::Pending);

        orchestrator
            .start_backfill_sync(target, BackfillStartPermit::new_for_test(ACTOR, 2))
            .unwrap();
        assert_matches!(orchestrator.next().await, Some(ChainEvent::BackfillSyncStarted));
    }
}
