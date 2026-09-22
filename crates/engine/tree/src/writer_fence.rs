//! Actor-owned exclusion for Diesis canonical publication and randomness release.

use crate::tree::TreeOutcome;
use alloy_eips::BlockNumHash;
use alloy_primitives::{keccak256, B256};
use alloy_rpc_types_engine::{ForkchoiceState, ForkchoiceUpdated};
use crossbeam_channel::Sender;
use rand_08::RngCore;
use reth_engine_primitives::OnForkChoiceUpdated;
use reth_payload_primitives::PayloadTypes;
#[cfg(unix)]
use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    marker::PhantomData,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::sync::oneshot;

static NEXT_ACTOR_INCARNATION: AtomicU64 = AtomicU64::new(1);
static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(1);
const V1_JOURNAL_MAGIC: &[u8; 8] = b"RWFENCE1";
const V1_JOURNAL_LEN: usize = 8 + 1 + 8 + 8 + 8 + 32 + 32 + 32;
const JOURNAL_MAGIC: &[u8; 8] = b"RWFENCE2";
const JOURNAL_LEN: usize = 8 + 1 + 8 + 8 + 8 + 32 + 32 + 32 + 32 + 32 + 32;
const RECEIPT_MAGIC: &[u8; 8] = b"RWRCP001";
const RELEASE_RECEIPT_LEN: usize = 8 + 8 + 8 + 8 + 32 + 32 + 32 + 32 + 32;
const RECORD_KEY_DOMAIN: &[u8] = b"diesis/reth-writer-fence/record-key/v1";

/// Capacity errors and actor refusals for the canonical writer fence.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WriterFenceError {
    /// The exact engine actor is unavailable.
    #[error("engine writer-fence actor is unavailable")]
    EngineUnavailable,
    /// The bounded control ingress is full.
    #[error("engine writer-fence control queue is full (capacity {capacity})")]
    QueueFull {
        /// Fixed capacity of the actor's private control queue.
        capacity: usize,
    },
    /// The actor reply was lost, so the operation's outcome is ambiguous.
    #[error("engine writer-fence acknowledgement was dropped")]
    AcknowledgementDropped,
    /// Another canonical owner or backfill operation is active.
    #[error("canonical writer is busy in phase {phase}")]
    Busy {
        /// Actor phase that currently owns canonical mutation.
        phase: &'static str,
    },
    /// The expected head is not the actor's exact canonical head.
    #[error("canonical head mismatch: expected {expected:?}, actual {actual:?}")]
    HeadMismatch {
        /// Exact head bound to the requested capability.
        expected: BlockNumHash,
        /// Head observed by the actor or provider.
        actual: BlockNumHash,
    },
    /// A capability belongs to another actor incarnation or operation.
    #[error("writer-fence capability is stale or belongs to another actor")]
    StaleCapability,
    /// The publication tuple differs from the tuple reserved by the actor.
    #[error("tagged publication does not match the reserved parent, child, or forkchoice tuple")]
    PublicationMismatch,
    /// Tagged publication does not support payload building attributes.
    #[error("tagged publication requires payload attributes to be absent")]
    PayloadAttributesUnsupported,
    /// The publication target is not already known to the engine tree or provider.
    #[error("publication target is not preinserted: {target:?}")]
    UnknownPublicationTarget {
        /// Exact target that must be preinserted before publication begins.
        target: BlockNumHash,
    },
    /// The stored target header does not match the reserved number and hash.
    #[error("publication target identity mismatch: expected {expected:?}, actual {actual:?}")]
    PublicationTargetIdentityMismatch {
        /// Number and hash reserved by the publication caller.
        expected: BlockNumHash,
        /// Number and hash read from the stored header.
        actual: BlockNumHash,
    },
    /// A direct child target does not link to the reserved canonical parent.
    #[error("publication target parent mismatch: expected {expected:?}, actual {actual:?}")]
    PublicationParentMismatch {
        /// Hash required at the ancestry boundary.
        expected: B256,
        /// Hash reached by walking the stored header chain.
        actual: B256,
    },
    /// A phase transition was attempted out of order.
    #[error("writer-fence transition is not valid in phase {phase}")]
    InvalidTransition {
        /// Actor phase in which the requested transition was refused.
        phase: &'static str,
    },
    /// Canonical mutation is closed until startup and journal reconciliation complete.
    #[error("canonical writer ingress is closed for startup or release recovery")]
    RecoveryFenced,
    /// A persistence writer barrier could not be established or released.
    #[error("persistence writer fence failed: {message}")]
    Persistence {
        /// Persistence barrier or drain failure detail.
        message: String,
    },
    /// The exact provider head could not be read.
    #[error("canonical provider head read failed: {message}")]
    Provider {
        /// Canonical provider read failure detail.
        message: String,
    },
    /// The crash-safe release journal could not be read or committed.
    #[error("release fence journal failure: {message}")]
    Journal {
        /// Durable journal validation or write failure detail.
        message: String,
    },
    /// The release or plan digest is zero.
    #[error("invalid release binding field {field}")]
    InvalidReleaseBinding {
        /// Binding field that failed validation.
        field: &'static str,
    },
    /// An encoded release receipt is malformed.
    #[error("invalid release fence receipt: {message}")]
    InvalidReleaseReceipt {
        /// Receipt validation failure detail.
        message: String,
    },
    /// Durable local release evidence cannot resolve the retained journal state.
    #[error("release recovery evidence refused: {message}")]
    RecoveryEvidence {
        /// Exact recovery refusal detail.
        message: String,
    },
    /// The operating system random source could not create a grant nonce.
    #[error("release grant nonce generation failed: {message}")]
    Nonce {
        /// Random-source failure detail.
        message: String,
    },
    /// The tagged forkchoice operation itself failed.
    #[error("tagged forkchoice update failed: {message}")]
    Forkchoice {
        /// Tagged forkchoice processing failure detail.
        message: String,
    },
}

/// Exact immutable identity of one local randomness release plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseBinding {
    canonical_parent: BlockNumHash,
    release_digest: B256,
    plan_digest: B256,
}

impl ReleaseBinding {
    /// Build a release binding with nonzero release and plan digests.
    pub fn new(
        canonical_parent: BlockNumHash,
        release_digest: B256,
        plan_digest: B256,
    ) -> Result<Self, WriterFenceError> {
        if release_digest == B256::ZERO {
            return Err(WriterFenceError::InvalidReleaseBinding { field: "release_digest" });
        }
        if plan_digest == B256::ZERO {
            return Err(WriterFenceError::InvalidReleaseBinding { field: "plan_digest" });
        }
        Ok(Self { canonical_parent, release_digest, plan_digest })
    }

    const fn clean() -> Self {
        Self {
            canonical_parent: BlockNumHash { number: 0, hash: B256::ZERO },
            release_digest: B256::ZERO,
            plan_digest: B256::ZERO,
        }
    }

    /// Exact canonical parent excluded by the writer fence.
    pub const fn canonical_parent(&self) -> BlockNumHash {
        self.canonical_parent
    }

    /// Digest of the exact release record and emitted bytes.
    pub const fn release_digest(&self) -> B256 {
        self.release_digest
    }

    /// Digest of the complete admitted callback plan.
    pub const fn plan_digest(&self) -> B256 {
        self.plan_digest
    }
}

/// Opaque immutable receipt stored inside the node's durable local release record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseFenceReceipt {
    actor: u64,
    operation: u64,
    binding: ReleaseBinding,
    nonce: B256,
}

impl ReleaseFenceReceipt {
    /// Fixed encoded receipt length.
    pub const ENCODED_LEN: usize = RELEASE_RECEIPT_LEN;

    const fn new(actor: u64, operation: u64, binding: ReleaseBinding, nonce: B256) -> Self {
        Self { actor, operation, binding, nonce }
    }

    /// Encode the exact prior actor, operation and release binding with a checksum.
    pub fn encode(self) -> [u8; RELEASE_RECEIPT_LEN] {
        let mut bytes = [0u8; RELEASE_RECEIPT_LEN];
        bytes[..8].copy_from_slice(RECEIPT_MAGIC);
        bytes[8..16].copy_from_slice(&self.actor.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.operation.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.binding.canonical_parent.number.to_le_bytes());
        bytes[32..64].copy_from_slice(self.binding.canonical_parent.hash.as_slice());
        bytes[64..96].copy_from_slice(self.binding.release_digest.as_slice());
        bytes[96..128].copy_from_slice(self.binding.plan_digest.as_slice());
        bytes[128..160].copy_from_slice(self.nonce.as_slice());
        let checksum = keccak256(&bytes[..RELEASE_RECEIPT_LEN - 32]);
        bytes[RELEASE_RECEIPT_LEN - 32..].copy_from_slice(checksum.as_slice());
        bytes
    }

    /// Decode and validate a receipt read from the node's durable local release record.
    pub fn decode(bytes: &[u8]) -> Result<Self, WriterFenceError> {
        if bytes.len() != RELEASE_RECEIPT_LEN {
            return Err(WriterFenceError::InvalidReleaseReceipt {
                message: "wrong encoded length".to_owned(),
            });
        }
        if &bytes[..8] != RECEIPT_MAGIC {
            return Err(WriterFenceError::InvalidReleaseReceipt {
                message: "wrong encoding version".to_owned(),
            });
        }
        if keccak256(&bytes[..RELEASE_RECEIPT_LEN - 32]).as_slice()
            != &bytes[RELEASE_RECEIPT_LEN - 32..]
        {
            return Err(WriterFenceError::InvalidReleaseReceipt {
                message: "checksum mismatch".to_owned(),
            });
        }
        let actor = u64::from_le_bytes(bytes[8..16].try_into().expect("fixed actor bytes"));
        let operation =
            u64::from_le_bytes(bytes[16..24].try_into().expect("fixed operation bytes"));
        if actor == 0 || operation == 0 {
            return Err(WriterFenceError::InvalidReleaseReceipt {
                message: "zero actor or operation".to_owned(),
            });
        }
        let number = u64::from_le_bytes(bytes[24..32].try_into().expect("fixed number bytes"));
        let canonical_parent = BlockNumHash::new(number, B256::from_slice(&bytes[32..64]));
        let binding = ReleaseBinding::new(
            canonical_parent,
            B256::from_slice(&bytes[64..96]),
            B256::from_slice(&bytes[96..128]),
        )?;
        let nonce = B256::from_slice(&bytes[128..160]);
        Ok(Self { actor, operation, binding, nonce })
    }

    /// Exact release binding stored by this receipt.
    pub const fn binding(&self) -> ReleaseBinding {
        self.binding
    }

    /// Stable node-store lookup key without revealing the grant nonce or receipt.
    pub fn record_key(&self) -> B256 {
        let encoded = self.encode();
        let mut bytes = Vec::with_capacity(RECORD_KEY_DOMAIN.len() + encoded.len());
        bytes.extend_from_slice(RECORD_KEY_DOMAIN);
        bytes.extend_from_slice(&encoded);
        keccak256(bytes)
    }

    pub(crate) const fn operation(&self) -> u64 {
        self.operation
    }
}

/// Opaque request processed only by the concrete engine-tree actor.
#[derive(Debug)]
pub struct WriterFenceRequest<T: PayloadTypes> {
    command: WriterFenceCommand<T>,
}

impl<T: PayloadTypes> WriterFenceRequest<T> {
    const fn new(command: WriterFenceCommand<T>) -> Self {
        Self { command }
    }

    pub(crate) fn into_command(self) -> WriterFenceCommand<T> {
        self.command
    }
}

/// Commands have crate visibility so actor identity and operation IDs cannot be forged by users.
#[derive(Debug)]
pub(crate) enum WriterFenceCommand<T: PayloadTypes> {
    BeginPublication {
        actor: u64,
        parent: BlockNumHash,
        child: BlockNumHash,
        forkchoice: ForkchoiceState,
        response: oneshot::Sender<Result<u64, WriterFenceError>>,
    },
    TaggedForkchoice {
        actor: u64,
        operation: u64,
        state: ForkchoiceState,
        payload_attrs: Option<T::PayloadAttributes>,
        response: oneshot::Sender<Result<TreeOutcome<OnForkChoiceUpdated>, WriterFenceError>>,
    },
    FinishPublication {
        actor: u64,
        operation: u64,
        child: BlockNumHash,
        response: oneshot::Sender<Result<(), WriterFenceError>>,
    },
    AcquireRelease {
        actor: u64,
        binding: ReleaseBinding,
        response: oneshot::Sender<Result<ReleaseFenceReceipt, WriterFenceError>>,
    },
    AbortRelease {
        capability: ReleaseFenceReceipt,
        response: oneshot::Sender<Result<(), WriterFenceError>>,
    },
    ArmRelease {
        capability: ReleaseFenceReceipt,
        response: oneshot::Sender<Result<(), WriterFenceError>>,
    },
    CompleteRelease {
        capability: ReleaseFenceReceipt,
        committed: ReleaseFenceReceipt,
        response: oneshot::Sender<Result<(), WriterFenceError>>,
    },
    AbandonRelease {
        capability: ReleaseFenceReceipt,
        abandoned: ReleaseFenceReceipt,
        response: oneshot::Sender<Result<(), WriterFenceError>>,
    },
    ReserveBackfill {
        actor: u64,
        response: oneshot::Sender<Result<u64, WriterFenceError>>,
    },
    OpenQualifiedIngress {
        actor: u64,
        response: oneshot::Sender<Result<(), WriterFenceError>>,
    },
    CheckReleaseReplay {
        actor: u64,
        expected: BlockNumHash,
        response: oneshot::Sender<Result<(), WriterFenceError>>,
    },
}

/// Handle bound to one running engine-tree actor.
#[derive(Debug)]
pub struct WriterFenceHandle<T: PayloadTypes> {
    sender: Sender<WriterFenceRequest<T>>,
    actor: u64,
}

impl<T: PayloadTypes> Clone for WriterFenceHandle<T> {
    fn clone(&self) -> Self {
        Self { sender: self.sender.clone(), actor: self.actor }
    }
}

impl<T: PayloadTypes> WriterFenceHandle<T> {
    const CONTROL_CAPACITY: usize = 32;

    pub(crate) const fn new(sender: Sender<WriterFenceRequest<T>>, actor: u64) -> Self {
        Self { sender, actor }
    }

    pub(crate) const fn actor(&self) -> u64 {
        self.actor
    }

    fn send(&self, command: WriterFenceCommand<T>) -> Result<(), WriterFenceError> {
        match self.sender.try_send(WriterFenceRequest::new(command)) {
            Ok(()) => Ok(()),
            Err(crossbeam_channel::TrySendError::Full(_)) => {
                Err(WriterFenceError::QueueFull { capacity: Self::CONTROL_CAPACITY })
            }
            Err(crossbeam_channel::TrySendError::Disconnected(_)) => {
                Err(WriterFenceError::EngineUnavailable)
            }
        }
    }

    /// Reserve an exact publication transition. The returned session is once-owned.
    pub async fn begin_publication(
        &self,
        parent: BlockNumHash,
        child: BlockNumHash,
        forkchoice: ForkchoiceState,
    ) -> Result<PublicationSession<T>, WriterFenceError> {
        let (response, receiver) = oneshot::channel();
        self.send(WriterFenceCommand::BeginPublication {
            actor: self.actor,
            parent,
            child,
            forkchoice,
            response,
        })?;
        let operation = receiver.await.map_err(|_| WriterFenceError::AcknowledgementDropped)??;
        Ok(PublicationSession {
            handle: self.clone(),
            operation,
            parent,
            child,
            forkchoice,
            forkchoice_admitted: false,
        })
    }

    /// Acquire an exact release fence after prior canonical persistence is drained.
    pub async fn acquire_release(
        &self,
        binding: ReleaseBinding,
    ) -> Result<AbortableRelease<T>, WriterFenceError> {
        let (response, receiver) = oneshot::channel();
        self.send(WriterFenceCommand::AcquireRelease { actor: self.actor, binding, response })?;
        let receipt = receiver.await.map_err(|_| WriterFenceError::AcknowledgementDropped)??;
        Ok(AbortableRelease { handle: self.clone(), receipt })
    }

    /// Check that a durable share may be replayed after all actor obligations resolve.
    ///
    /// This grants no release capability and changes no journal state. An armed
    /// or otherwise busy actor rejects replay, including after a lost completion
    /// acknowledgement, until completion or authenticated startup recovery wins.
    pub async fn ensure_release_replay_ready(
        &self,
        expected: BlockNumHash,
    ) -> Result<(), WriterFenceError> {
        let (response, receiver) = oneshot::channel();
        self.send(WriterFenceCommand::CheckReleaseReplay {
            actor: self.actor,
            expected,
            response,
        })?;
        receiver.await.map_err(|_| WriterFenceError::AcknowledgementDropped)?
    }

    /// Reserve startup backfill before the pipeline task is allowed to spawn.
    pub async fn reserve_backfill_start(&self) -> Result<BackfillStartPermit, WriterFenceError> {
        let (response, receiver) = oneshot::channel();
        self.send(WriterFenceCommand::ReserveBackfill { actor: self.actor, response })?;
        let operation = receiver.await.map_err(|_| WriterFenceError::AcknowledgementDropped)??;
        Ok(BackfillStartPermit { actor: self.actor, operation })
    }

    /// Open release-capable ingress after startup has no pipeline work pending.
    pub async fn open_qualified_ingress(&self) -> Result<(), WriterFenceError> {
        let (response, receiver) = oneshot::channel();
        self.send(WriterFenceCommand::OpenQualifiedIngress { actor: self.actor, response })?;
        receiver.await.map_err(|_| WriterFenceError::AcknowledgementDropped)?
    }
}

/// Once-owned capability for a reserved native publication.
#[derive(Debug)]
pub struct PublicationSession<T: PayloadTypes> {
    handle: WriterFenceHandle<T>,
    operation: u64,
    parent: BlockNumHash,
    child: BlockNumHash,
    forkchoice: ForkchoiceState,
    forkchoice_admitted: bool,
}

impl<T: PayloadTypes> PublicationSession<T> {
    /// Submit the exact reserved FCU through the private actor-bound path.
    pub async fn forkchoice_updated(
        &mut self,
        payload_attrs: Option<T::PayloadAttributes>,
    ) -> Result<ForkchoiceUpdated, WriterFenceError> {
        if payload_attrs.is_some() {
            return Err(WriterFenceError::PayloadAttributesUnsupported);
        }
        if self.forkchoice_admitted {
            return Err(WriterFenceError::InvalidTransition { phase: "publication-admitted" });
        }
        let (response, receiver) = oneshot::channel();
        self.handle.send(WriterFenceCommand::TaggedForkchoice {
            actor: self.handle.actor,
            operation: self.operation,
            state: self.forkchoice,
            payload_attrs,
            response,
        })?;
        let outcome = receiver.await.map_err(|_| WriterFenceError::AcknowledgementDropped)??;
        let result = outcome
            .outcome
            .await
            .map_err(|error| WriterFenceError::Forkchoice { message: error.to_string() })?;
        if result.payload_status.is_valid() {
            self.forkchoice_admitted = true;
        }
        Ok(result)
    }

    /// Finish only after process effects, intent, overlay and parent handoff are complete.
    pub async fn finish(self, child: BlockNumHash) -> Result<(), WriterFenceError> {
        let (response, receiver) = oneshot::channel();
        self.handle.send(WriterFenceCommand::FinishPublication {
            actor: self.handle.actor,
            operation: self.operation,
            child,
            response,
        })?;
        receiver.await.map_err(|_| WriterFenceError::AcknowledgementDropped)?
    }

    /// Exact parent reserved by this session.
    pub const fn parent(&self) -> BlockNumHash {
        self.parent
    }

    /// Exact child reserved by this session.
    pub const fn child(&self) -> BlockNumHash {
        self.child
    }
}

/// Release ownership that can still be explicitly aborted.
#[derive(Debug)]
pub struct AbortableRelease<T: PayloadTypes> {
    handle: WriterFenceHandle<T>,
    receipt: ReleaseFenceReceipt,
}

impl<T: PayloadTypes> AbortableRelease<T> {
    /// Abort before any local durable release effect starts.
    pub async fn abort(self) -> Result<(), WriterFenceError> {
        let (response, receiver) = oneshot::channel();
        self.handle
            .send(WriterFenceCommand::AbortRelease { capability: self.receipt, response })?;
        receiver.await.map_err(|_| WriterFenceError::AcknowledgementDropped)?
    }

    /// Irreversibly arm the operation before the first local durable release write.
    pub async fn arm_commit(self) -> Result<ArmedRelease<T>, WriterFenceError> {
        let (response, receiver) = oneshot::channel();
        self.handle.send(WriterFenceCommand::ArmRelease { capability: self.receipt, response })?;
        receiver.await.map_err(|_| WriterFenceError::AcknowledgementDropped)??;
        Ok(ArmedRelease { handle: self.handle, receipt: self.receipt })
    }

    /// Exact release binding carried by this capability.
    pub const fn binding(&self) -> ReleaseBinding {
        self.receipt.binding
    }
}

/// Non-abortable release ownership after the durable boundary is armed.
#[derive(Debug)]
pub struct ArmedRelease<T: PayloadTypes> {
    handle: WriterFenceHandle<T>,
    receipt: ReleaseFenceReceipt,
}

impl<T: PayloadTypes> ArmedRelease<T> {
    /// Complete after the exact local release record is durable.
    pub async fn complete(self, committed: ReleaseFenceReceipt) -> Result<(), WriterFenceError> {
        let (response, receiver) = oneshot::channel();
        self.handle.send(WriterFenceCommand::CompleteRelease {
            capability: self.receipt,
            committed,
            response,
        })?;
        receiver.await.map_err(|_| WriterFenceError::AcknowledgementDropped)?
    }

    /// Exact release binding carried by this capability.
    pub const fn binding(&self) -> ReleaseBinding {
        self.receipt.binding
    }

    /// Opaque receipt that must match the exact committed local release record.
    pub const fn receipt(&self) -> ReleaseFenceReceipt {
        self.receipt
    }

    /// Resolve an armed release after the node durably commits an irrevocable tombstone.
    pub async fn abandon(self, abandoned: ReleaseFenceReceipt) -> Result<(), WriterFenceError> {
        let (response, receiver) = oneshot::channel();
        self.handle.send(WriterFenceCommand::AbandonRelease {
            capability: self.receipt,
            abandoned,
            response,
        })?;
        receiver.await.map_err(|_| WriterFenceError::AcknowledgementDropped)?
    }
}

/// Once-owned actor authorization to spawn one backfill pipeline.
#[derive(Debug)]
pub struct BackfillStartPermit {
    actor: u64,
    operation: u64,
}

impl BackfillStartPermit {
    pub(crate) fn authorize(self, expected_actor: u64) -> Result<u64, WriterFenceError> {
        if self.actor != expected_actor {
            return Err(WriterFenceError::StaleCapability);
        }
        Ok(self.operation)
    }

    #[cfg(test)]
    pub(crate) const fn new_for_test(actor: u64, operation: u64) -> Self {
        Self { actor, operation }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JournalState {
    Clean = 0,
    Intent = 1,
    Armed = 2,
    ResolvedAbort = 3,
    ResolvedCommit = 4,
    ResolvedAbandon = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JournalRecord {
    state: JournalState,
    actor: u64,
    operation: u64,
    binding: ReleaseBinding,
    nonce: B256,
}

impl JournalRecord {
    const fn clean() -> Self {
        Self {
            state: JournalState::Clean,
            actor: 0,
            operation: 0,
            binding: ReleaseBinding::clean(),
            nonce: B256::ZERO,
        }
    }

    const fn receipt(self) -> ReleaseFenceReceipt {
        ReleaseFenceReceipt::new(self.actor, self.operation, self.binding, self.nonce)
    }

    fn validate(self) -> Result<Self, WriterFenceError> {
        if self.state == JournalState::Clean {
            if self == Self::clean() {
                return Ok(self);
            }
            return Err(WriterFenceError::Journal {
                message: "clean fence record contains release identity".to_owned(),
            });
        }
        if self.actor == 0 || self.operation == 0 {
            return Err(WriterFenceError::Journal {
                message: "non-clean fence record has zero actor or operation".to_owned(),
            });
        }
        if self.nonce == B256::ZERO {
            return Err(WriterFenceError::Journal {
                message: "non-clean fence record has zero grant nonce".to_owned(),
            });
        }
        ReleaseBinding::new(
            self.binding.canonical_parent,
            self.binding.release_digest,
            self.binding.plan_digest,
        )?;
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct V1JournalRecord {
    state: JournalState,
    actor: u64,
    operation: u64,
    head: BlockNumHash,
}

impl V1JournalRecord {
    const fn clean() -> Self {
        Self {
            state: JournalState::Clean,
            actor: 0,
            operation: 0,
            head: BlockNumHash { number: 0, hash: B256::ZERO },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JournalRecordOnDisk {
    V1(V1JournalRecord),
    V2(JournalRecord),
}

/// Crash-safe local intent retained before a release capability is granted.
#[derive(Debug)]
pub(crate) struct ReleaseFenceJournal {
    path: PathBuf,
    parent: PathBuf,
    lock_path: PathBuf,
    #[cfg(unix)]
    parent_device: u64,
    #[cfg(unix)]
    parent_inode: u64,
    identity: B256,
    _lock: File,
}

impl ReleaseFenceJournal {
    fn acquire(path: PathBuf) -> Result<(Self, JournalRecord), WriterFenceError> {
        let parent = path
            .parent()
            .ok_or_else(|| WriterFenceError::Journal {
                message: format!("fence journal has no parent: {}", path.display()),
            })?
            .to_path_buf();
        fs::create_dir_all(&parent).map_err(|error| WriterFenceError::Journal {
            message: format!("create journal parent {}: {error}", parent.display()),
        })?;
        let parent_metadata =
            fs::symlink_metadata(&parent).map_err(|error| WriterFenceError::Journal {
                message: format!("inspect journal parent {}: {error}", parent.display()),
            })?;
        if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
            return Err(WriterFenceError::Journal {
                message: format!(
                    "journal parent is not a concrete directory: {}",
                    parent.display()
                ),
            });
        }

        let identity = journal_identity(&parent, &parent_metadata);
        let lock_path = journal_lock_path(&path);
        reject_symlink(&lock_path)?;
        let (lock, initialized) =
            match OpenOptions::new().create_new(true).read(true).write(true).open(&lock_path) {
                Ok(lock) => (lock, false),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (
                    OpenOptions::new().read(true).write(true).open(&lock_path).map_err(
                        |error| WriterFenceError::Journal {
                            message: format!("open journal lock {}: {error}", lock_path.display()),
                        },
                    )?,
                    true,
                ),
                Err(error) => {
                    return Err(WriterFenceError::Journal {
                        message: format!("create journal lock {}: {error}", lock_path.display()),
                    })
                }
            };
        verify_open_identity(&lock_path, &lock)?;
        lock_exclusive_nonblocking(&lock).map_err(|error| WriterFenceError::Journal {
            message: format!("lock journal owner {}: {error}", lock_path.display()),
        })?;
        verify_open_identity(&lock_path, &lock)?;
        if !initialized {
            lock.sync_all().map_err(|error| WriterFenceError::Journal {
                message: format!("fsync journal lock {}: {error}", lock_path.display()),
            })?;
            sync_directory(&parent).map_err(|error| WriterFenceError::Journal {
                message: format!("sync journal lock parent {}: {error}", parent.display()),
            })?;
        }

        let journal = Self {
            path,
            parent,
            lock_path,
            #[cfg(unix)]
            parent_device: parent_metadata.dev(),
            #[cfg(unix)]
            parent_inode: parent_metadata.ino(),
            identity,
            _lock: lock,
        };
        journal.verify_parent()?;
        reject_symlink(&journal.path)?;
        let record = match journal.load_any()? {
            None if initialized => Err(WriterFenceError::Journal {
                message: format!(
                    "initialized writer-fence journal record is missing at {}",
                    journal.path.display()
                ),
            }),
            None => {
                journal.persist(JournalRecord::clean())?;
                Ok(JournalRecord::clean())
            }
            Some(JournalRecordOnDisk::V2(record)) => Ok(record),
            Some(JournalRecordOnDisk::V1(record)) if record == V1JournalRecord::clean() => {
                // V1 has no release or plan digest. Only its exact Clean record can migrate,
                // while this startup path owns the retained exclusive lock and no writer exists.
                journal.persist(JournalRecord::clean())?;
                Ok(JournalRecord::clean())
            }
            Some(JournalRecordOnDisk::V1(record)) => Err(WriterFenceError::Journal {
                message: format!(
                    "unresolved V1 release fence record {:?} for operation {} at {:?} has no release binding",
                    record.state, record.operation, record.head,
                ),
            }),
        }?;
        Ok((journal, record))
    }

    fn load_any(&self) -> Result<Option<JournalRecordOnDisk>, WriterFenceError> {
        self.verify_parent()?;
        reject_symlink(&self.path)?;
        let mut file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(self.error("open", error)),
        };
        verify_open_identity(&self.path, &file)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((JOURNAL_LEN + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| self.error("read", error))?;
        let (version, encoded_len) = match (bytes.get(..8), bytes.len()) {
            (Some(magic), V1_JOURNAL_LEN) if magic == V1_JOURNAL_MAGIC => (1, V1_JOURNAL_LEN),
            (Some(magic), JOURNAL_LEN) if magic == JOURNAL_MAGIC => (2, JOURNAL_LEN),
            _ => {
                return Err(WriterFenceError::Journal {
                    message: format!("corrupt fence record at {}", self.path.display()),
                })
            }
        };
        let checksum = keccak256(&bytes[..encoded_len - 32]);
        if checksum.as_slice() != &bytes[encoded_len - 32..] {
            return Err(WriterFenceError::Journal {
                message: format!("fence record checksum mismatch at {}", self.path.display()),
            });
        }
        let state = decode_journal_state(bytes[8], &self.path)?;
        let actor = u64::from_le_bytes(bytes[9..17].try_into().expect("fixed actor bytes"));
        let operation =
            u64::from_le_bytes(bytes[17..25].try_into().expect("fixed operation bytes"));
        let number = u64::from_le_bytes(bytes[25..33].try_into().expect("fixed number bytes"));
        let head = BlockNumHash::new(number, B256::from_slice(&bytes[33..65]));
        if version == 1 {
            let identity = B256::from_slice(&bytes[65..97]);
            if identity != self.identity {
                return Err(WriterFenceError::Journal {
                    message: format!(
                        "journal datadir identity mismatch at {}",
                        self.path.display()
                    ),
                });
            }
            return Ok(Some(JournalRecordOnDisk::V1(V1JournalRecord {
                state,
                actor,
                operation,
                head,
            })));
        }
        let release_digest = B256::from_slice(&bytes[65..97]);
        let plan_digest = B256::from_slice(&bytes[97..129]);
        let nonce = B256::from_slice(&bytes[129..161]);
        let identity = B256::from_slice(&bytes[161..193]);
        if identity != self.identity {
            return Err(WriterFenceError::Journal {
                message: format!("journal datadir identity mismatch at {}", self.path.display()),
            });
        }
        Ok(Some(JournalRecordOnDisk::V2(
            JournalRecord {
                state,
                actor,
                operation,
                binding: ReleaseBinding { canonical_parent: head, release_digest, plan_digest },
                nonce,
            }
            .validate()?,
        )))
    }

    fn load(&self) -> Result<Option<JournalRecord>, WriterFenceError> {
        match self.load_any()? {
            None => Ok(None),
            Some(JournalRecordOnDisk::V2(record)) => Ok(Some(record)),
            Some(JournalRecordOnDisk::V1(_)) => Err(WriterFenceError::Journal {
                message: format!(
                    "V1 fence record cannot participate in V2 transitions at {}",
                    self.path.display()
                ),
            }),
        }
    }

    fn persist(&self, record: JournalRecord) -> Result<(), WriterFenceError> {
        let record = record.validate()?;
        self.verify_parent()?;
        reject_symlink(&self.path)?;
        let mut bytes = Vec::with_capacity(JOURNAL_LEN);
        bytes.extend_from_slice(JOURNAL_MAGIC);
        bytes.push(record.state as u8);
        bytes.extend_from_slice(&record.actor.to_le_bytes());
        bytes.extend_from_slice(&record.operation.to_le_bytes());
        bytes.extend_from_slice(&record.binding.canonical_parent.number.to_le_bytes());
        bytes.extend_from_slice(record.binding.canonical_parent.hash.as_slice());
        bytes.extend_from_slice(record.binding.release_digest.as_slice());
        bytes.extend_from_slice(record.binding.plan_digest.as_slice());
        bytes.extend_from_slice(record.nonce.as_slice());
        bytes.extend_from_slice(self.identity.as_slice());
        bytes.extend_from_slice(keccak256(&bytes).as_slice());
        let temporary = self.unique_temporary_path();
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| self.error("create unique temporary", error))?;
        file.write_all(&bytes).map_err(|error| self.error("write", error))?;
        file.sync_all().map_err(|error| self.error("fsync", error))?;
        self.verify_parent()?;
        reject_symlink(&self.path)?;
        fs::rename(&temporary, &self.path).map_err(|error| self.error("rename", error))?;
        sync_directory(&self.parent).map_err(|error| self.error("sync parent", error))
    }

    fn transition(
        &self,
        expected: JournalRecord,
        next: JournalRecord,
    ) -> Result<(), WriterFenceError> {
        match self.load()? {
            Some(actual) if actual == expected => self.persist(next),
            Some(actual) => Err(WriterFenceError::Journal {
                message: format!(
                    "release fence record mismatch at {}: expected {expected:?}, actual {actual:?}",
                    self.path.display()
                ),
            }),
            None => Err(WriterFenceError::Journal {
                message: format!("required fence record is missing at {}", self.path.display()),
            }),
        }
    }

    fn mark_clean_required(&self, expected: JournalRecord) -> Result<(), WriterFenceError> {
        self.transition(expected, JournalRecord::clean())
    }

    fn unique_temporary_path(&self) -> PathBuf {
        let sequence = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
        let name = self.path.file_name().and_then(|name| name.to_str()).unwrap_or("writer-fence");
        self.parent.join(format!(".{name}.tmp-{}-{sequence}", std::process::id()))
    }

    fn verify_parent(&self) -> Result<(), WriterFenceError> {
        verify_open_identity(&self.lock_path, &self._lock)?;
        let metadata =
            fs::symlink_metadata(&self.parent).map_err(|error| WriterFenceError::Journal {
                message: format!("inspect journal parent {}: {error}", self.parent.display()),
            })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(WriterFenceError::Journal {
                message: format!("journal parent changed type: {}", self.parent.display()),
            });
        }
        #[cfg(unix)]
        if metadata.dev() != self.parent_device || metadata.ino() != self.parent_inode {
            return Err(WriterFenceError::Journal {
                message: format!("journal parent identity changed: {}", self.parent.display()),
            });
        }
        Ok(())
    }

    fn error(&self, operation: &str, error: std::io::Error) -> WriterFenceError {
        WriterFenceError::Journal {
            message: format!("{operation} {}: {error}", self.path.display()),
        }
    }
}

fn decode_journal_state(value: u8, path: &Path) -> Result<JournalState, WriterFenceError> {
    match value {
        0 => Ok(JournalState::Clean),
        1 => Ok(JournalState::Intent),
        2 => Ok(JournalState::Armed),
        3 => Ok(JournalState::ResolvedAbort),
        4 => Ok(JournalState::ResolvedCommit),
        5 => Ok(JournalState::ResolvedAbandon),
        _ => Err(WriterFenceError::Journal {
            message: format!("unknown fence record state at {}", path.display()),
        }),
    }
}

fn release_grant_nonce() -> Result<B256, WriterFenceError> {
    let mut nonce = [0u8; 32];
    for _ in 0..2 {
        rand_08::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|error| WriterFenceError::Nonce { message: error.to_string() })?;
        let nonce = B256::from(nonce);
        if nonce != B256::ZERO {
            return Ok(nonce);
        }
    }
    Err(WriterFenceError::Nonce { message: "operating system returned two zero nonces".to_owned() })
}

fn journal_lock_path(path: &Path) -> PathBuf {
    let mut lock_name = path.as_os_str().to_os_string();
    lock_name.push(".writer-lock");
    PathBuf::from(lock_name)
}

#[cfg(unix)]
fn journal_identity(parent: &Path, metadata: &fs::Metadata) -> B256 {
    use std::os::unix::ffi::OsStrExt;
    let mut bytes = parent.as_os_str().as_bytes().to_vec();
    bytes.extend_from_slice(&metadata.dev().to_le_bytes());
    bytes.extend_from_slice(&metadata.ino().to_le_bytes());
    keccak256(bytes)
}

#[cfg(not(unix))]
fn journal_identity(parent: &Path, _metadata: &fs::Metadata) -> B256 {
    keccak256(parent.to_string_lossy().as_bytes())
}

fn reject_symlink(path: &Path) -> Result<(), WriterFenceError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(WriterFenceError::Journal {
            message: format!("journal path is a symlink: {}", path.display()),
        }),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(WriterFenceError::Journal {
            message: format!("inspect journal path {}: {error}", path.display()),
        }),
    }
}

fn verify_open_identity(path: &Path, file: &File) -> Result<(), WriterFenceError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|error| WriterFenceError::Journal {
        message: format!("inspect open journal path {}: {error}", path.display()),
    })?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(WriterFenceError::Journal {
            message: format!("open journal path is not a concrete file: {}", path.display()),
        });
    }
    #[cfg(unix)]
    {
        let file_metadata = file.metadata().map_err(|error| WriterFenceError::Journal {
            message: format!("inspect open journal file {}: {error}", path.display()),
        })?;
        if path_metadata.dev() != file_metadata.dev() || path_metadata.ino() != file_metadata.ino()
        {
            return Err(WriterFenceError::Journal {
                message: format!("journal path identity changed while opening: {}", path.display()),
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
fn lock_exclusive_nonblocking(file: &File) -> std::io::Result<()> {
    unsafe extern "C" {
        fn flock(fd: std::os::raw::c_int, operation: std::os::raw::c_int) -> std::os::raw::c_int;
    }
    const LOCK_EX: std::os::raw::c_int = 2;
    const LOCK_NB: std::os::raw::c_int = 4;
    // SAFETY: `file` owns a valid descriptor for the duration of the call. The lock is released
    // automatically when the retained file is dropped.
    if unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn lock_exclusive_nonblocking(_file: &File) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "release fence journal locking requires unix flock",
    ))
}

/// Early startup ownership of the release journal and its process lock.
#[derive(Debug)]
pub struct WriterFenceBootstrap {
    journal: ReleaseFenceJournal,
}

/// Startup result while the journal owner lock is retained.
#[derive(Debug)]
pub enum WriterFenceStartup {
    /// The journal is clean and can seed a closed engine actor.
    Ready(WriterFenceBootstrap),
    /// A prior release must be reconciled before any writer starts.
    Pending(PendingReleaseRecovery),
}

/// Durable release phase retained from the prior process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseRecoveryPhase {
    /// The writer fence was acquired, but the durable effect was not armed.
    Intent,
    /// The durable effect was armed and cannot be treated as abortable.
    Armed,
    /// Abort was durably resolved before the persistence barrier acknowledgement.
    ResolvedAbort,
    /// Commit was durably resolved before the persistence barrier acknowledgement.
    ResolvedCommit,
    /// A post-arm tombstone was durably resolved before barrier release acknowledgement.
    ResolvedAbandon,
}

/// Immutable query passed to the node-owned durable release source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseRecoveryQuery {
    phase: ReleaseRecoveryPhase,
    binding: ReleaseBinding,
    record_key: B256,
}

impl ReleaseRecoveryQuery {
    /// Prior durable Reth phase.
    pub const fn phase(&self) -> ReleaseRecoveryPhase {
        self.phase
    }

    /// Exact canonical release binding, without prior actor, operation or grant nonce.
    pub const fn binding(&self) -> ReleaseBinding {
        self.binding
    }

    /// Domain-separated digest used to find only the current grant's local record.
    pub const fn record_key(&self) -> B256 {
        self.record_key
    }
}

/// Exhaustive local release-store observation made under node-owned writer ownership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalReleaseRecovery {
    /// No durable release record or committed outbox entry exists for the query.
    Absent,
    /// One durable committed release record contains these encoded receipt bytes.
    Committed(Vec<u8>),
    /// One irrevocable abandonment tombstone contains these encoded receipt bytes.
    Abandoned(Vec<u8>),
    /// The local store contains corrupt, duplicate or conflicting evidence.
    Conflicting,
}

/// Trusted node-owned inspection of the complete local release store and committed outbox.
pub trait ReleaseRecoverySource {
    /// Inspection failure type.
    type Error: std::fmt::Display;

    /// Inspect the local store for exactly one prior Reth release query.
    fn inspect(&mut self, query: ReleaseRecoveryQuery)
        -> Result<LocalReleaseRecovery, Self::Error>;
}

/// Exclusive startup ownership of one unresolved V2 release journal record.
#[derive(Debug)]
pub struct PendingReleaseRecovery {
    journal: ReleaseFenceJournal,
    record: JournalRecord,
}

impl PendingReleaseRecovery {
    /// Exact immutable query that the node-owned source must inspect.
    pub fn query(&self) -> ReleaseRecoveryQuery {
        let phase = match self.record.state {
            JournalState::Intent => ReleaseRecoveryPhase::Intent,
            JournalState::Armed => ReleaseRecoveryPhase::Armed,
            JournalState::ResolvedAbort => ReleaseRecoveryPhase::ResolvedAbort,
            JournalState::ResolvedCommit => ReleaseRecoveryPhase::ResolvedCommit,
            JournalState::ResolvedAbandon => ReleaseRecoveryPhase::ResolvedAbandon,
            JournalState::Clean => unreachable!("clean records never create pending recovery"),
        };
        let receipt = self.record.receipt();
        ReleaseRecoveryQuery {
            phase,
            binding: self.record.binding,
            record_key: receipt.record_key(),
        }
    }

    /// Reconcile exact typed local evidence while retaining the journal owner lock.
    pub fn reconcile<S: ReleaseRecoverySource>(
        self,
        source: &mut S,
    ) -> Result<WriterFenceBootstrap, WriterFenceError> {
        let query = self.query();
        let observation = source
            .inspect(query)
            .map_err(|error| WriterFenceError::RecoveryEvidence { message: error.to_string() })?;
        let exact = self.record.receipt();
        let resolved = match (query.phase, observation) {
            (ReleaseRecoveryPhase::Intent, LocalReleaseRecovery::Absent) => {
                let resolved = JournalRecord { state: JournalState::ResolvedAbort, ..self.record };
                self.journal.transition(self.record, resolved)?;
                resolved
            }
            (ReleaseRecoveryPhase::Armed, LocalReleaseRecovery::Committed(bytes))
                if ReleaseFenceReceipt::decode(&bytes).is_ok_and(|receipt| receipt == exact) =>
            {
                let resolved = JournalRecord { state: JournalState::ResolvedCommit, ..self.record };
                self.journal.transition(self.record, resolved)?;
                resolved
            }
            (ReleaseRecoveryPhase::Armed, LocalReleaseRecovery::Abandoned(bytes))
                if ReleaseFenceReceipt::decode(&bytes).is_ok_and(|receipt| receipt == exact) =>
            {
                let resolved =
                    JournalRecord { state: JournalState::ResolvedAbandon, ..self.record };
                self.journal.transition(self.record, resolved)?;
                resolved
            }
            (ReleaseRecoveryPhase::ResolvedAbort, LocalReleaseRecovery::Absent) => self.record,
            (ReleaseRecoveryPhase::ResolvedCommit, LocalReleaseRecovery::Committed(bytes))
                if ReleaseFenceReceipt::decode(&bytes).is_ok_and(|receipt| receipt == exact) =>
            {
                self.record
            }
            (ReleaseRecoveryPhase::ResolvedAbandon, LocalReleaseRecovery::Abandoned(bytes))
                if ReleaseFenceReceipt::decode(&bytes).is_ok_and(|receipt| receipt == exact) =>
            {
                self.record
            }
            (phase, observation) => {
                return Err(WriterFenceError::RecoveryEvidence {
                    message: format!(
                        "local observation {observation:?} cannot resolve retained phase {phase:?}"
                    ),
                })
            }
        };
        self.journal.mark_clean_required(resolved)?;
        Ok(WriterFenceBootstrap { journal: self.journal })
    }
}

impl WriterFenceBootstrap {
    /// Lock and validate a clean journal before any node startup writer runs.
    pub fn acquire(path: PathBuf) -> Result<Self, WriterFenceError> {
        match Self::inspect(path)? {
            WriterFenceStartup::Ready(bootstrap) => Ok(bootstrap),
            WriterFenceStartup::Pending(recovery) => {
                let query = recovery.query();
                Err(WriterFenceError::Journal {
                    message: format!(
                        "unresolved release fence record {:?} for operation {} at {:?}",
                        query.phase,
                        recovery.record.operation,
                        recovery.record.binding.canonical_parent,
                    ),
                })
            }
        }
    }

    /// Lock and inspect the journal before any startup writer runs.
    pub fn inspect(path: PathBuf) -> Result<WriterFenceStartup, WriterFenceError> {
        let (journal, record) = ReleaseFenceJournal::acquire(path)?;
        if record == JournalRecord::clean() {
            Ok(WriterFenceStartup::Ready(Self { journal }))
        } else {
            Ok(WriterFenceStartup::Pending(PendingReleaseRecovery { journal, record }))
        }
    }

    /// Exact path retained under the bootstrap's exclusive owner lock.
    pub fn journal_path(&self) -> &Path {
        &self.journal.path
    }

    /// Re-verify the retained lock and parent-directory identity and confirm the journal still
    /// holds the exact Clean record, immediately before a launcher consumes this bootstrap.
    pub fn recheck_clean(&self) -> Result<(), WriterFenceError> {
        self.journal.verify_parent()?;
        reject_symlink(&self.journal.path)?;
        match self.journal.load()? {
            Some(record) if record == JournalRecord::clean() => Ok(()),
            Some(record) => Err(WriterFenceError::Journal {
                message: format!(
                    "writer-fence bootstrap is no longer clean: {:?} for operation {} at {}",
                    record.state,
                    record.operation,
                    self.journal.path.display()
                ),
            }),
            None => Err(WriterFenceError::Journal {
                message: format!(
                    "writer-fence journal record vanished at {}",
                    self.journal.path.display()
                ),
            }),
        }
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "release fence directory synchronization requires unix fsync",
    ))
}

#[derive(Debug)]
pub(crate) enum WriterFencePhase {
    BootClosed,
    Idle,
    Publication {
        operation: u64,
        parent: BlockNumHash,
        child: BlockNumHash,
        forkchoice: ForkchoiceState,
        admitted: bool,
    },
    BackfillPending {
        operation: u64,
    },
    BackfillActive {
        operation: u64,
    },
    ReleaseDraining {
        operation: u64,
        binding: ReleaseBinding,
    },
    ReleaseHeldAbortable {
        operation: u64,
        binding: ReleaseBinding,
        nonce: B256,
    },
    ReleaseCommitArmed {
        operation: u64,
        binding: ReleaseBinding,
        nonce: B256,
    },
    ReleaseResolvedAbort {
        operation: u64,
        binding: ReleaseBinding,
        nonce: B256,
    },
    ReleaseResolvedCommit {
        operation: u64,
        binding: ReleaseBinding,
        nonce: B256,
    },
    ReleaseResolvedAbandon {
        operation: u64,
        binding: ReleaseBinding,
        nonce: B256,
    },
    Faulted,
}

impl WriterFencePhase {
    pub(crate) const fn name(&self) -> &'static str {
        match self {
            Self::BootClosed => "boot-closed",
            Self::Idle => "idle",
            Self::Publication { admitted: false, .. } => "publication-reserved",
            Self::Publication { admitted: true, .. } => "publication-admitted",
            Self::BackfillPending { .. } => "backfill-pending",
            Self::BackfillActive { .. } => "backfill-active",
            Self::ReleaseDraining { .. } => "release-draining",
            Self::ReleaseHeldAbortable { .. } => "release-held-abortable",
            Self::ReleaseCommitArmed { .. } => "release-commit-armed",
            Self::ReleaseResolvedAbort { .. } => "release-resolved-abort",
            Self::ReleaseResolvedCommit { .. } => "release-resolved-commit",
            Self::ReleaseResolvedAbandon { .. } => "release-resolved-abandon",
            Self::Faulted => "faulted",
        }
    }
}

#[derive(Debug)]
pub(crate) struct WriterFenceState {
    actor: u64,
    next_operation: u64,
    phase: WriterFencePhase,
    journal: ReleaseFenceJournal,
    qualified_mode: bool,
    _not_sendable_capability: PhantomData<*mut ()>,
}

// State never leaves the single engine thread. The marker prevents capability-like state from
// accidentally becoming Sync while still allowing the enclosing actor to be moved to its thread.
unsafe impl Send for WriterFenceState {}

impl WriterFenceState {
    pub(crate) fn from_bootstrap(bootstrap: WriterFenceBootstrap) -> Self {
        let actor = NEXT_ACTOR_INCARNATION.fetch_add(1, Ordering::Relaxed);
        Self {
            actor,
            next_operation: 1,
            phase: WriterFencePhase::BootClosed,
            journal: bootstrap.journal,
            qualified_mode: true,
            _not_sendable_capability: PhantomData,
        }
    }

    #[cfg(test)]
    pub(crate) fn ephemeral() -> Self {
        let path = std::env::temp_dir().join(format!(
            "reth-writer-fence-test-{}-{}",
            std::process::id(),
            NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
        ));
        let bootstrap = WriterFenceBootstrap::acquire(path).expect("unique test journal is clean");
        let mut state = Self::from_bootstrap(bootstrap);
        state.phase = WriterFencePhase::Idle;
        state.qualified_mode = false;
        state
    }

    #[cfg(test)]
    pub(crate) fn enable_qualified_for_test(&mut self) {
        self.qualified_mode = true;
    }

    pub(crate) const fn actor(&self) -> u64 {
        self.actor
    }

    pub(crate) const fn phase(&self) -> &WriterFencePhase {
        &self.phase
    }

    pub(crate) const fn canonical_mutation_allowed(&self) -> bool {
        matches!(self.phase, WriterFencePhase::Idle | WriterFencePhase::Publication { .. })
    }

    pub(crate) const fn ordinary_persistence_allowed(&self) -> bool {
        matches!(self.phase, WriterFencePhase::Idle | WriterFencePhase::Publication { .. })
    }

    pub(crate) const fn admitted_publication_child(&self) -> Option<BlockNumHash> {
        match self.phase {
            WriterFencePhase::Publication { child, admitted: true, .. } => Some(child),
            _ => None,
        }
    }

    pub(crate) const fn direct_insert_allowed(&self) -> bool {
        matches!(self.phase, WriterFencePhase::Idle)
    }

    pub(crate) const fn untagged_forkchoice_allowed(&self) -> bool {
        !self.qualified_mode && matches!(self.phase, WriterFencePhase::Idle)
    }

    fn operation(&mut self) -> Result<u64, WriterFenceError> {
        let operation = self.next_operation;
        let Some(next_operation) = self.next_operation.checked_add(1) else {
            self.phase = WriterFencePhase::Faulted;
            return Err(WriterFenceError::Busy { phase: "faulted" });
        };
        self.next_operation = next_operation;
        Ok(operation)
    }

    fn ensure_actor(&self, actor: u64) -> Result<(), WriterFenceError> {
        if actor == self.actor {
            Ok(())
        } else {
            Err(WriterFenceError::StaleCapability)
        }
    }

    pub(crate) fn open_qualified(&mut self, actor: u64) -> Result<(), WriterFenceError> {
        self.ensure_actor(actor)?;
        match self.phase {
            WriterFencePhase::BootClosed => {
                self.qualified_mode = true;
                self.phase = WriterFencePhase::Idle;
                Ok(())
            }
            _ => Err(WriterFenceError::Busy { phase: self.phase.name() }),
        }
    }

    pub(crate) fn ensure_release_replay_ready(&self, actor: u64) -> Result<(), WriterFenceError> {
        self.ensure_actor(actor)?;
        if !self.qualified_mode {
            return Err(WriterFenceError::RecoveryFenced);
        }
        if !matches!(self.phase, WriterFencePhase::Idle) {
            return Err(WriterFenceError::Busy { phase: self.phase.name() });
        }
        Ok(())
    }

    pub(crate) fn begin_publication(
        &mut self,
        actor: u64,
        parent: BlockNumHash,
        child: BlockNumHash,
        forkchoice: ForkchoiceState,
        actual: BlockNumHash,
    ) -> Result<u64, WriterFenceError> {
        self.ensure_actor(actor)?;
        if !self.qualified_mode {
            return Err(WriterFenceError::RecoveryFenced);
        }
        if !matches!(self.phase, WriterFencePhase::Idle) {
            return Err(WriterFenceError::Busy { phase: self.phase.name() });
        }
        if actual != parent {
            return Err(WriterFenceError::HeadMismatch { expected: parent, actual });
        }
        // Recovery, replay and finality-only FCUs can target an existing ancestor or the same
        // head. The actor binds the exact target and verifies the resulting head after mutation;
        // it does not infer a direct-child relation from block numbers.
        if forkchoice.head_block_hash != child.hash {
            return Err(WriterFenceError::PublicationMismatch);
        }
        let operation = self.operation()?;
        self.phase =
            WriterFencePhase::Publication { operation, parent, child, forkchoice, admitted: false };
        Ok(operation)
    }

    pub(crate) fn authorize_tagged_forkchoice(
        &self,
        actor: u64,
        operation: u64,
        state: ForkchoiceState,
    ) -> Result<(), WriterFenceError> {
        self.ensure_actor(actor)?;
        match self.phase {
            WriterFencePhase::Publication {
                operation: active,
                forkchoice,
                admitted: false,
                ..
            } if active == operation && forkchoice == state => Ok(()),
            WriterFencePhase::Publication { .. } => Err(WriterFenceError::PublicationMismatch),
            _ => Err(WriterFenceError::InvalidTransition { phase: self.phase.name() }),
        }
    }

    pub(crate) fn publication_target(
        &self,
        actor: u64,
        operation: u64,
        state: ForkchoiceState,
    ) -> Result<(BlockNumHash, BlockNumHash), WriterFenceError> {
        self.ensure_actor(actor)?;
        match self.phase {
            WriterFencePhase::Publication {
                operation: active,
                parent,
                child,
                forkchoice,
                admitted: false,
            } if active == operation && forkchoice == state => Ok((parent, child)),
            WriterFencePhase::Publication { .. } => Err(WriterFenceError::PublicationMismatch),
            _ => Err(WriterFenceError::InvalidTransition { phase: self.phase.name() }),
        }
    }

    pub(crate) fn mark_publication_admitted(
        &mut self,
        actor: u64,
        operation: u64,
        actual: BlockNumHash,
    ) -> Result<(), WriterFenceError> {
        self.ensure_actor(actor)?;
        match &mut self.phase {
            WriterFencePhase::Publication { operation: active, child, admitted, .. }
                if *active == operation && *child == actual =>
            {
                *admitted = true;
                Ok(())
            }
            _ => Err(WriterFenceError::InvalidTransition { phase: self.phase.name() }),
        }
    }

    pub(crate) fn finish_publication(
        &mut self,
        actor: u64,
        operation: u64,
        child: BlockNumHash,
        actual: BlockNumHash,
    ) -> Result<(), WriterFenceError> {
        self.ensure_actor(actor)?;
        match self.phase {
            WriterFencePhase::Publication {
                operation: active,
                child: reserved,
                admitted: true,
                ..
            } if active == operation && reserved == child && actual == child => {
                self.phase = WriterFencePhase::Idle;
                Ok(())
            }
            _ => Err(WriterFenceError::InvalidTransition { phase: self.phase.name() }),
        }
    }

    pub(crate) fn begin_release_draining(
        &mut self,
        actor: u64,
        binding: ReleaseBinding,
        actual: BlockNumHash,
    ) -> Result<u64, WriterFenceError> {
        self.ensure_actor(actor)?;
        if !self.qualified_mode {
            return Err(WriterFenceError::RecoveryFenced);
        }
        if !matches!(self.phase, WriterFencePhase::Idle) {
            return Err(WriterFenceError::Busy { phase: self.phase.name() });
        }
        if binding.canonical_parent != actual {
            return Err(WriterFenceError::HeadMismatch {
                expected: binding.canonical_parent,
                actual,
            });
        }
        let operation = self.operation()?;
        self.phase = WriterFencePhase::ReleaseDraining { operation, binding };
        Ok(operation)
    }

    pub(crate) fn grant_release(
        &mut self,
        operation: u64,
        binding: ReleaseBinding,
    ) -> Result<ReleaseFenceReceipt, WriterFenceError> {
        match self.phase {
            WriterFencePhase::ReleaseDraining { operation: active, binding: expected }
                if active == operation && expected == binding =>
            {
                let nonce = release_grant_nonce()?;
                let receipt = ReleaseFenceReceipt::new(self.actor, operation, binding, nonce);
                self.journal.transition(
                    JournalRecord::clean(),
                    JournalRecord {
                        state: JournalState::Intent,
                        actor: self.actor,
                        operation,
                        binding,
                        nonce,
                    },
                )?;
                self.phase = WriterFencePhase::ReleaseHeldAbortable { operation, binding, nonce };
                Ok(receipt)
            }
            WriterFencePhase::ReleaseDraining { .. } => Err(WriterFenceError::StaleCapability),
            _ => Err(WriterFenceError::InvalidTransition { phase: self.phase.name() }),
        }
    }

    pub(crate) fn cancel_release_draining(
        &mut self,
        operation: u64,
        binding: ReleaseBinding,
    ) -> Result<(), WriterFenceError> {
        match self.phase {
            WriterFencePhase::ReleaseDraining { operation: active, binding: expected }
                if active == operation && expected == binding =>
            {
                self.phase = WriterFencePhase::Idle;
                Ok(())
            }
            _ => Err(WriterFenceError::InvalidTransition { phase: self.phase.name() }),
        }
    }

    pub(crate) fn prepare_abort_release(
        &mut self,
        capability: ReleaseFenceReceipt,
    ) -> Result<(), WriterFenceError> {
        self.ensure_actor(capability.actor)?;
        match self.phase {
            WriterFencePhase::ReleaseHeldAbortable { operation, binding, nonce }
                if capability
                    == ReleaseFenceReceipt::new(self.actor, operation, binding, nonce) =>
            {
                self.journal.transition(
                    JournalRecord {
                        state: JournalState::Intent,
                        actor: self.actor,
                        operation,
                        binding,
                        nonce,
                    },
                    JournalRecord {
                        state: JournalState::ResolvedAbort,
                        actor: self.actor,
                        operation,
                        binding,
                        nonce,
                    },
                )?;
                self.phase = WriterFencePhase::ReleaseResolvedAbort { operation, binding, nonce };
                Ok(())
            }
            WriterFencePhase::ReleaseHeldAbortable { .. } => Err(WriterFenceError::StaleCapability),
            _ => Err(WriterFenceError::InvalidTransition { phase: self.phase.name() }),
        }
    }

    /// Side-effect-free pre-check: a mismatched receipt is refused as `StaleCapability`
    /// without changing the held phase; only a wrong phase is an invalid transition.
    pub(crate) fn authorize_abort(
        &self,
        capability: ReleaseFenceReceipt,
    ) -> Result<(), WriterFenceError> {
        self.ensure_actor(capability.actor)?;
        match self.phase {
            WriterFencePhase::ReleaseHeldAbortable { operation, binding, nonce } => {
                if capability == ReleaseFenceReceipt::new(self.actor, operation, binding, nonce) {
                    Ok(())
                } else {
                    Err(WriterFenceError::StaleCapability)
                }
            }
            _ => Err(WriterFenceError::InvalidTransition { phase: self.phase.name() }),
        }
    }

    pub(crate) fn arm_release(
        &mut self,
        capability: ReleaseFenceReceipt,
    ) -> Result<(), WriterFenceError> {
        self.ensure_actor(capability.actor)?;
        match self.phase {
            WriterFencePhase::ReleaseHeldAbortable { operation, binding, nonce }
                if capability
                    == ReleaseFenceReceipt::new(self.actor, operation, binding, nonce) =>
            {
                self.journal.transition(
                    JournalRecord {
                        state: JournalState::Intent,
                        actor: self.actor,
                        operation,
                        binding,
                        nonce,
                    },
                    JournalRecord {
                        state: JournalState::Armed,
                        actor: self.actor,
                        operation,
                        binding,
                        nonce,
                    },
                )?;
                self.phase = WriterFencePhase::ReleaseCommitArmed { operation, binding, nonce };
                Ok(())
            }
            WriterFencePhase::ReleaseHeldAbortable { .. } => Err(WriterFenceError::StaleCapability),
            _ => Err(WriterFenceError::InvalidTransition { phase: self.phase.name() }),
        }
    }

    pub(crate) fn prepare_complete_release(
        &mut self,
        capability: ReleaseFenceReceipt,
        committed: ReleaseFenceReceipt,
        actual: BlockNumHash,
    ) -> Result<(), WriterFenceError> {
        self.ensure_actor(capability.actor)?;
        match self.phase {
            WriterFencePhase::ReleaseCommitArmed { operation, binding, nonce }
                if capability
                    == ReleaseFenceReceipt::new(self.actor, operation, binding, nonce)
                    && committed == capability
                    && actual == binding.canonical_parent =>
            {
                self.journal.transition(
                    JournalRecord {
                        state: JournalState::Armed,
                        actor: self.actor,
                        operation,
                        binding,
                        nonce,
                    },
                    JournalRecord {
                        state: JournalState::ResolvedCommit,
                        actor: self.actor,
                        operation,
                        binding,
                        nonce,
                    },
                )?;
                self.phase = WriterFencePhase::ReleaseResolvedCommit { operation, binding, nonce };
                Ok(())
            }
            WriterFencePhase::ReleaseCommitArmed { .. } => Err(WriterFenceError::StaleCapability),
            _ => Err(WriterFenceError::InvalidTransition { phase: self.phase.name() }),
        }
    }

    pub(crate) fn finish_resolved_release(
        &mut self,
        capability: ReleaseFenceReceipt,
    ) -> Result<(), WriterFenceError> {
        self.ensure_actor(capability.actor)?;
        let (state, operation, binding, nonce) = match self.phase {
            WriterFencePhase::ReleaseResolvedAbort { operation, binding, nonce }
                if capability
                    == ReleaseFenceReceipt::new(self.actor, operation, binding, nonce) =>
            {
                (JournalState::ResolvedAbort, operation, binding, nonce)
            }
            WriterFencePhase::ReleaseResolvedCommit { operation, binding, nonce }
                if capability
                    == ReleaseFenceReceipt::new(self.actor, operation, binding, nonce) =>
            {
                (JournalState::ResolvedCommit, operation, binding, nonce)
            }
            WriterFencePhase::ReleaseResolvedAbandon { operation, binding, nonce }
                if capability
                    == ReleaseFenceReceipt::new(self.actor, operation, binding, nonce) =>
            {
                (JournalState::ResolvedAbandon, operation, binding, nonce)
            }
            _ => return Err(WriterFenceError::InvalidTransition { phase: self.phase.name() }),
        };
        self.journal.mark_clean_required(JournalRecord {
            state,
            actor: self.actor,
            operation,
            binding,
            nonce,
        })?;
        self.phase = WriterFencePhase::Idle;
        Ok(())
    }

    /// Side-effect-free pre-check: a receipt that is not exactly the armed grant, or a
    /// committed record that is not exactly that receipt, is refused as `StaleCapability`
    /// and leaves the release armed. A moved canonical head is a head mismatch.
    pub(crate) fn authorize_complete(
        &self,
        capability: ReleaseFenceReceipt,
        committed: ReleaseFenceReceipt,
        actual: BlockNumHash,
    ) -> Result<(), WriterFenceError> {
        self.ensure_actor(capability.actor)?;
        match self.phase {
            WriterFencePhase::ReleaseCommitArmed { operation, binding, nonce } => {
                if capability != ReleaseFenceReceipt::new(self.actor, operation, binding, nonce)
                    || committed != capability
                {
                    return Err(WriterFenceError::StaleCapability);
                }
                if actual != binding.canonical_parent {
                    return Err(WriterFenceError::HeadMismatch {
                        expected: binding.canonical_parent,
                        actual,
                    });
                }
                Ok(())
            }
            _ => Err(WriterFenceError::InvalidTransition { phase: self.phase.name() }),
        }
    }

    /// Side-effect-free pre-check with the same refusal classes as `authorize_complete`.
    pub(crate) fn authorize_abandon(
        &self,
        capability: ReleaseFenceReceipt,
        abandoned: ReleaseFenceReceipt,
    ) -> Result<(), WriterFenceError> {
        self.ensure_actor(capability.actor)?;
        match self.phase {
            WriterFencePhase::ReleaseCommitArmed { operation, binding, nonce } => {
                if capability == ReleaseFenceReceipt::new(self.actor, operation, binding, nonce)
                    && abandoned == capability
                {
                    Ok(())
                } else {
                    Err(WriterFenceError::StaleCapability)
                }
            }
            _ => Err(WriterFenceError::InvalidTransition { phase: self.phase.name() }),
        }
    }

    pub(crate) fn prepare_abandon_release(
        &mut self,
        capability: ReleaseFenceReceipt,
        abandoned: ReleaseFenceReceipt,
    ) -> Result<(), WriterFenceError> {
        self.authorize_abandon(capability, abandoned)?;
        let operation = capability.operation;
        let binding = capability.binding;
        let nonce = capability.nonce;
        self.journal.transition(
            JournalRecord {
                state: JournalState::Armed,
                actor: self.actor,
                operation,
                binding,
                nonce,
            },
            JournalRecord {
                state: JournalState::ResolvedAbandon,
                actor: self.actor,
                operation,
                binding,
                nonce,
            },
        )?;
        self.phase = WriterFencePhase::ReleaseResolvedAbandon { operation, binding, nonce };
        Ok(())
    }

    pub(crate) fn reserve_backfill(&mut self, actor: u64) -> Result<u64, WriterFenceError> {
        self.ensure_actor(actor)?;
        if !matches!(self.phase, WriterFencePhase::BootClosed | WriterFencePhase::Idle) {
            return Err(WriterFenceError::Busy { phase: self.phase.name() });
        }
        let operation = self.operation()?;
        self.phase = WriterFencePhase::BackfillPending { operation };
        Ok(operation)
    }

    pub(crate) fn backfill_started(&mut self) -> Result<(), WriterFenceError> {
        if !self.qualified_mode && matches!(self.phase, WriterFencePhase::Idle) {
            return Ok(());
        }
        match self.phase {
            WriterFencePhase::BackfillPending { operation } => {
                self.phase = WriterFencePhase::BackfillActive { operation };
                Ok(())
            }
            _ => Err(WriterFenceError::InvalidTransition { phase: self.phase.name() }),
        }
    }

    pub(crate) fn backfill_finished(&mut self) -> Result<(), WriterFenceError> {
        if !self.qualified_mode && matches!(self.phase, WriterFencePhase::Idle) {
            return Ok(());
        }
        match self.phase {
            WriterFencePhase::BackfillActive { operation } => {
                let _completed_operation = operation;
                self.phase = WriterFencePhase::Idle;
                Ok(())
            }
            _ => Err(WriterFenceError::InvalidTransition { phase: self.phase.name() }),
        }
    }

    pub(crate) fn fault(&mut self) {
        self.phase = WriterFencePhase::Faulted;
    }
}

/// Return the actor identity and initial state for an early-acquired production journal.
pub(crate) fn production_writer_fence(bootstrap: WriterFenceBootstrap) -> WriterFenceState {
    WriterFenceState::from_bootstrap(bootstrap)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(head: BlockNumHash, release: u8, plan: u8) -> ReleaseBinding {
        ReleaseBinding::new(head, B256::repeat_byte(release), B256::repeat_byte(plan)).unwrap()
    }

    #[derive(Debug)]
    struct FixedRecovery(Result<LocalReleaseRecovery, &'static str>);

    impl ReleaseRecoverySource for FixedRecovery {
        type Error = &'static str;

        fn inspect(
            &mut self,
            _query: ReleaseRecoveryQuery,
        ) -> Result<LocalReleaseRecovery, Self::Error> {
            self.0.clone()
        }
    }

    fn journal_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "reth-writer-fence-{name}-{}-{}",
            std::process::id(),
            NEXT_ACTOR_INCARNATION.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn cleanup(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(journal_lock_path(path));
    }

    fn ready(path: PathBuf) -> WriterFenceBootstrap {
        match WriterFenceBootstrap::inspect(path).unwrap() {
            WriterFenceStartup::Ready(bootstrap) => bootstrap,
            WriterFenceStartup::Pending(_) => panic!("fresh journal must be ready"),
        }
    }

    fn pending(path: PathBuf) -> PendingReleaseRecovery {
        match WriterFenceBootstrap::inspect(path).unwrap() {
            WriterFenceStartup::Pending(recovery) => recovery,
            WriterFenceStartup::Ready(_) => panic!("unresolved journal must require recovery"),
        }
    }

    #[test]
    fn release_binding_rejects_zero_digests() {
        let head = BlockNumHash::new(1, B256::repeat_byte(0x11));
        assert_matches::assert_matches!(
            ReleaseBinding::new(head, B256::ZERO, B256::repeat_byte(0x22)),
            Err(WriterFenceError::InvalidReleaseBinding { field: "release_digest" })
        );
        assert_matches::assert_matches!(
            ReleaseBinding::new(head, B256::repeat_byte(0x22), B256::ZERO),
            Err(WriterFenceError::InvalidReleaseBinding { field: "plan_digest" })
        );
    }

    #[test]
    fn release_receipt_round_trips_and_rejects_corruption() {
        let receipt = ReleaseFenceReceipt {
            actor: 17,
            operation: 23,
            binding: binding(BlockNumHash::new(29, B256::repeat_byte(0x31)), 0x41, 0x51),
            nonce: B256::repeat_byte(0x61),
        };
        let encoded = receipt.encode();
        assert_eq!(ReleaseFenceReceipt::decode(&encoded).unwrap(), receipt);
        assert_eq!(
            ReleaseFenceReceipt::decode(&encoded[..encoded.len() - 1]),
            Err(WriterFenceError::InvalidReleaseReceipt {
                message: "wrong encoded length".to_owned()
            })
        );
        let mut corrupt = encoded;
        corrupt[65] ^= 1;
        assert_matches::assert_matches!(
            ReleaseFenceReceipt::decode(&corrupt),
            Err(WriterFenceError::InvalidReleaseReceipt { .. })
        );
    }

    #[test]
    fn v2_journal_persists_the_full_release_binding() {
        let path = journal_path("v2-binding");
        let head = BlockNumHash::new(31, B256::repeat_byte(0x32));
        let binding = binding(head, 0x33, 0x34);
        let bootstrap = ready(path.clone());
        let mut state = WriterFenceState::from_bootstrap(bootstrap);
        let actor = state.actor();
        state.open_qualified(actor).unwrap();
        let operation = state.begin_release_draining(actor, binding, head).unwrap();
        let receipt = state.grant_release(operation, binding).unwrap();

        let intent = fs::read(&path).unwrap();
        assert_eq!(intent.len(), 225);
        assert_eq!(&intent[..8], b"RWFENCE2");
        assert_eq!(intent[8], JournalState::Intent as u8);
        assert_eq!(&intent[65..97], binding.release_digest().as_slice());
        assert_eq!(&intent[97..129], binding.plan_digest().as_slice());
        assert_eq!(&intent[129..161], receipt.nonce.as_slice());
        assert_eq!(&intent[193..], keccak256(&intent[..193]).as_slice());

        state.arm_release(receipt).unwrap();
        let armed = fs::read(&path).unwrap();
        assert_eq!(armed[8], JournalState::Armed as u8);
        assert_eq!(&armed[65..97], binding.release_digest().as_slice());
        assert_eq!(&armed[97..129], binding.plan_digest().as_slice());
        drop(state);
        cleanup(&path);
    }

    #[test]
    fn same_head_with_another_plan_or_release_never_matches() {
        let path = journal_path("binding-mismatch");
        let head = BlockNumHash::new(41, B256::repeat_byte(0x42));
        let expected = binding(head, 0x43, 0x44);
        let bootstrap = ready(path.clone());
        let mut state = WriterFenceState::from_bootstrap(bootstrap);
        let actor = state.actor();
        state.open_qualified(actor).unwrap();
        let operation = state.begin_release_draining(actor, expected, head).unwrap();
        let receipt = state.grant_release(operation, expected).unwrap();
        assert_eq!(
            state
                .arm_release(ReleaseFenceReceipt { binding: binding(head, 0x43, 0x45), ..receipt }),
            Err(WriterFenceError::StaleCapability)
        );
        assert_eq!(
            state
                .arm_release(ReleaseFenceReceipt { binding: binding(head, 0x46, 0x44), ..receipt }),
            Err(WriterFenceError::StaleCapability)
        );
        assert!(matches!(state.phase(), WriterFencePhase::ReleaseHeldAbortable { .. }));
        drop(state);
        cleanup(&path);
    }

    #[test]
    fn restart_reconciles_only_the_exact_state_and_prior_receipt() {
        let path = journal_path("exact-recovery");
        let head = BlockNumHash::new(51, B256::repeat_byte(0x52));
        let binding = binding(head, 0x53, 0x54);
        let bootstrap = ready(path.clone());
        let mut state = WriterFenceState::from_bootstrap(bootstrap);
        let actor = state.actor();
        state.open_qualified(actor).unwrap();
        let operation = state.begin_release_draining(actor, binding, head).unwrap();
        let receipt = state.grant_release(operation, binding).unwrap();
        state.arm_release(receipt).unwrap();
        drop(state);

        let recovery = pending(path.clone());
        assert_eq!(recovery.query().phase(), ReleaseRecoveryPhase::Armed);
        assert_eq!(recovery.query().binding(), binding);
        assert_eq!(recovery.query().record_key(), receipt.record_key());
        let mut source =
            FixedRecovery(Ok(LocalReleaseRecovery::Committed(receipt.encode().to_vec())));
        let bootstrap = recovery.reconcile(&mut source).unwrap();
        let restarted = WriterFenceState::from_bootstrap(bootstrap);
        assert_ne!(restarted.actor(), actor);
        assert!(matches!(restarted.phase(), WriterFencePhase::BootClosed));
        drop(restarted);
        cleanup(&path);
    }

    #[test]
    fn armed_absence_and_wrong_receipt_remain_fenced() {
        let path = journal_path("ambiguous-recovery");
        let head = BlockNumHash::new(61, B256::repeat_byte(0x62));
        let expected_binding = binding(head, 0x63, 0x64);
        let bootstrap = ready(path.clone());
        let mut state = WriterFenceState::from_bootstrap(bootstrap);
        let actor = state.actor();
        state.open_qualified(actor).unwrap();
        let operation = state.begin_release_draining(actor, expected_binding, head).unwrap();
        let receipt = state.grant_release(operation, expected_binding).unwrap();
        state.arm_release(receipt).unwrap();
        drop(state);

        let recovery = pending(path.clone());
        let mut absent = FixedRecovery(Ok(LocalReleaseRecovery::Absent));
        assert_matches::assert_matches!(
            recovery.reconcile(&mut absent),
            Err(WriterFenceError::RecoveryEvidence { .. })
        );

        let recovery = pending(path.clone());
        let wrong = ReleaseFenceReceipt { binding: binding(head, 0x63, 0x65), ..receipt };
        let mut mismatched =
            FixedRecovery(Ok(LocalReleaseRecovery::Committed(wrong.encode().to_vec())));
        assert_matches::assert_matches!(
            recovery.reconcile(&mut mismatched),
            Err(WriterFenceError::RecoveryEvidence { .. })
        );
        assert_eq!(pending(path.clone()).query().phase(), ReleaseRecoveryPhase::Armed);
        cleanup(&path);
    }

    #[test]
    fn intent_absence_resolves_abort_but_committed_evidence_is_rejected() {
        let path = journal_path("intent-recovery");
        let head = BlockNumHash::new(71, B256::repeat_byte(0x72));
        let binding = binding(head, 0x73, 0x74);
        let bootstrap = ready(path.clone());
        let mut state = WriterFenceState::from_bootstrap(bootstrap);
        let actor = state.actor();
        state.open_qualified(actor).unwrap();
        let operation = state.begin_release_draining(actor, binding, head).unwrap();
        let receipt = state.grant_release(operation, binding).unwrap();
        drop(state);

        let recovery = pending(path.clone());
        let mut committed =
            FixedRecovery(Ok(LocalReleaseRecovery::Committed(receipt.encode().to_vec())));
        assert_matches::assert_matches!(
            recovery.reconcile(&mut committed),
            Err(WriterFenceError::RecoveryEvidence { .. })
        );
        let recovery = pending(path.clone());
        let mut absent = FixedRecovery(Ok(LocalReleaseRecovery::Absent));
        drop(recovery.reconcile(&mut absent).unwrap());
        assert_matches::assert_matches!(
            WriterFenceBootstrap::inspect(path.clone()).unwrap(),
            WriterFenceStartup::Ready(_)
        );
        cleanup(&path);
    }

    #[test]
    fn armed_exact_abandonment_reconciles_through_a_distinct_state() {
        let path = journal_path("armed-abandoned");
        let head = BlockNumHash::new(75, B256::repeat_byte(0x76));
        let binding = binding(head, 0x77, 0x78);
        let bootstrap = ready(path.clone());
        let mut state = WriterFenceState::from_bootstrap(bootstrap);
        let actor = state.actor();
        state.open_qualified(actor).unwrap();
        let operation = state.begin_release_draining(actor, binding, head).unwrap();
        let receipt = state.grant_release(operation, binding).unwrap();
        state.arm_release(receipt).unwrap();
        drop(state);

        let recovery = pending(path.clone());
        let mut abandoned =
            FixedRecovery(Ok(LocalReleaseRecovery::Abandoned(receipt.encode().to_vec())));
        drop(recovery.reconcile(&mut abandoned).unwrap());
        assert_matches::assert_matches!(
            WriterFenceBootstrap::inspect(path.clone()).unwrap(),
            WriterFenceStartup::Ready(_)
        );
        cleanup(&path);
    }

    #[test]
    fn grant_nonce_separates_reused_actor_operation_and_binding() {
        let binding = binding(BlockNumHash::new(81, B256::repeat_byte(0x82)), 0x83, 0x84);
        let first = ReleaseFenceReceipt::new(1, 1, binding, B256::repeat_byte(0x85));
        let restarted = ReleaseFenceReceipt::new(1, 1, binding, B256::repeat_byte(0x86));
        assert_ne!(first, restarted);
        assert_ne!(first.record_key(), restarted.record_key());
    }

    #[test]
    fn current_intent_absence_is_distinct_from_an_old_same_binding_tombstone() {
        let path = journal_path("old-tombstone");
        let head = BlockNumHash::new(91, B256::repeat_byte(0x92));
        let binding = binding(head, 0x93, 0x94);
        let old = ReleaseFenceReceipt::new(1, 1, binding, B256::repeat_byte(0x95));
        let bootstrap = ready(path.clone());
        let mut state = WriterFenceState::from_bootstrap(bootstrap);
        let actor = state.actor();
        state.open_qualified(actor).unwrap();
        let operation = state.begin_release_draining(actor, binding, head).unwrap();
        let current = state.grant_release(operation, binding).unwrap();
        assert_ne!(current.record_key(), old.record_key());
        drop(state);

        let recovery = pending(path.clone());
        assert_eq!(recovery.query().record_key(), current.record_key());
        let mut absent = FixedRecovery(Ok(LocalReleaseRecovery::Absent));
        drop(recovery.reconcile(&mut absent).unwrap());
        cleanup(&path);
    }

    #[test]
    fn restart_with_unresolved_intent_remains_quarantined() {
        let path = journal_path("intent");
        let head = BlockNumHash::new(7, B256::repeat_byte(0x77));
        let bootstrap = WriterFenceBootstrap::acquire(path.clone()).unwrap();
        let mut first = WriterFenceState::from_bootstrap(bootstrap);
        let first_actor = first.actor();
        first.open_qualified(first_actor).unwrap();
        let binding = binding(head, 0x78, 0x79);
        let operation = first.begin_release_draining(first_actor, binding, head).unwrap();
        first.grant_release(operation, binding).unwrap();
        drop(first);

        assert_matches::assert_matches!(
            WriterFenceBootstrap::acquire(path.clone()),
            Err(WriterFenceError::Journal { .. })
        );
        cleanup(&path);
    }

    #[test]
    fn armed_release_cannot_abort_and_restarts_closed() {
        let path = journal_path("armed");
        let head = BlockNumHash::new(9, B256::repeat_byte(0x99));
        let bootstrap = WriterFenceBootstrap::acquire(path.clone()).unwrap();
        let mut first = WriterFenceState::from_bootstrap(bootstrap);
        let actor = first.actor();
        first.open_qualified(actor).unwrap();
        let binding = binding(head, 0x9a, 0x9b);
        let operation = first.begin_release_draining(actor, binding, head).unwrap();
        let receipt = first.grant_release(operation, binding).unwrap();
        first.arm_release(receipt).unwrap();
        assert_matches::assert_matches!(
            first.prepare_abort_release(receipt),
            Err(WriterFenceError::InvalidTransition { phase: "release-commit-armed" })
        );
        drop(first);

        assert_matches::assert_matches!(
            WriterFenceBootstrap::acquire(path.clone()),
            Err(WriterFenceError::Journal { .. })
        );
        cleanup(&path);
    }

    #[test]
    fn corrupt_journal_never_opens_writer_ingress() {
        let path = journal_path("corrupt");
        fs::write(&path, b"not-a-valid-release-record").unwrap();
        assert_matches::assert_matches!(
            WriterFenceBootstrap::acquire(path.clone()),
            Err(WriterFenceError::Journal { .. })
        );
        cleanup(&path);
    }

    #[test]
    fn initialized_lock_marker_makes_missing_clean_record_fail_closed() {
        let path = journal_path("missing-clean");
        drop(WriterFenceBootstrap::acquire(path.clone()).unwrap());
        fs::remove_file(&path).unwrap();
        assert_matches::assert_matches!(
            WriterFenceBootstrap::acquire(path.clone()),
            Err(WriterFenceError::Journal { .. })
        );
        cleanup(&path);
    }

    #[test]
    fn journal_owner_lock_is_exclusive_and_retained() {
        let path = journal_path("lock");
        let owner = WriterFenceBootstrap::acquire(path.clone()).unwrap();
        assert_matches::assert_matches!(
            WriterFenceBootstrap::acquire(path.clone()),
            Err(WriterFenceError::Journal { .. })
        );
        drop(owner);
        drop(WriterFenceBootstrap::acquire(path.clone()).unwrap());
        cleanup(&path);
    }

    #[test]
    fn journal_name_ending_in_lock_uses_distinct_retained_lock_inode() {
        let path = journal_path("snapshot").with_extension("lock");
        let owner = WriterFenceBootstrap::acquire(path.clone()).unwrap();
        assert_ne!(path, journal_lock_path(&path));
        assert_matches::assert_matches!(
            WriterFenceBootstrap::acquire(path.clone()),
            Err(WriterFenceError::Journal { .. })
        );
        assert_eq!(owner.journal.load().unwrap().unwrap().state, JournalState::Clean);
        drop(owner);
        drop(WriterFenceBootstrap::acquire(path.clone()).unwrap());
        cleanup(&path);
    }

    #[test]
    fn abort_is_durably_resolved_before_barrier_release_and_clear() {
        let path = journal_path("resolved-abort");
        let head = BlockNumHash::new(11, B256::repeat_byte(0x11));
        let bootstrap = WriterFenceBootstrap::acquire(path.clone()).unwrap();
        let mut state = WriterFenceState::from_bootstrap(bootstrap);
        let actor = state.actor();
        state.open_qualified(actor).unwrap();
        let binding = binding(head, 0x12, 0x13);
        let operation = state.begin_release_draining(actor, binding, head).unwrap();
        let receipt = state.grant_release(operation, binding).unwrap();
        state.prepare_abort_release(receipt).unwrap();
        assert_eq!(state.journal.load().unwrap().unwrap().state, JournalState::ResolvedAbort);
        state.finish_resolved_release(receipt).unwrap();
        assert_eq!(state.journal.load().unwrap().unwrap().state, JournalState::Clean);
        drop(state);
        cleanup(&path);
    }
}
