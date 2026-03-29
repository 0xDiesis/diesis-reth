//! Pluggable state commitment trait for the engine's payload validation path.
//!
//! This module provides [`CommitmentValidator`], which abstracts over the mechanism
//! used to compute and persist state roots. By replacing the hard-wired MPT state root
//! computation, alternative commitment schemes (e.g. Verkle tries) can be plugged into
//! the engine without modifying core validation logic.

use alloy_primitives::{BlockNumber, B256};
use reth_db::transaction::DbTxMut;
use reth_revm::db::BundleState;

/// Error type for commitment operations.
#[derive(Debug, thiserror::Error)]
pub enum CommitmentError {
    /// Returned when the state root computation itself fails.
    #[error("commitment computation failed: {0}")]
    Computation(String),
    /// Returned when writing commitment data to the database fails.
    #[error("commitment persistence failed: {0}")]
    Persistence(String),
}

/// Validates state commitment for incoming blocks.
///
/// Replaces MPT state root computation in the engine's payload validation path.
/// Implementors provide the logic for computing a state root from a [`BundleState`]
/// and for persisting the resulting commitment data within a canonical commit
/// database transaction.
pub trait CommitmentValidator: Send + Sync {
    /// Opaque update data produced during [`compute_state_root`] and consumed by
    /// [`write_updates`].
    ///
    /// [`compute_state_root`]: CommitmentValidator::compute_state_root
    /// [`write_updates`]: CommitmentValidator::write_updates
    type Updates: Send + Sync + Clone;

    /// Compute the state root after applying the given execution output.
    ///
    /// Returns the computed state root hash together with any opaque update data
    /// that must later be persisted via [`write_updates`].
    ///
    /// # Parameters
    ///
    /// - `parent_block`: the block number of the parent block (i.e. the block whose
    ///   post-state is the starting point for this computation).
    /// - `bundle_state`: the EVM state diff produced by executing the block.
    ///
    /// [`write_updates`]: CommitmentValidator::write_updates
    fn compute_state_root(
        &self,
        parent_block: BlockNumber,
        bundle_state: &BundleState,
    ) -> Result<(B256, Self::Updates), CommitmentError>;

    /// Persist commitment updates within the block's canonical commit transaction.
    ///
    /// This method is called during the persistence phase, inside the same write
    /// transaction that records the canonical chain state, so that commitment data
    /// and chain data are committed atomically.
    ///
    /// # Parameters
    ///
    /// - `tx`: the mutable database transaction to write into.
    /// - `block_number`: the number of the block being committed.
    /// - `updates`: the update data returned by a prior call to [`compute_state_root`].
    ///
    /// [`compute_state_root`]: CommitmentValidator::compute_state_root
    fn write_updates(
        &self,
        tx: &impl DbTxMut,
        block_number: BlockNumber,
        updates: &Self::Updates,
    ) -> Result<(), CommitmentError>;
}
