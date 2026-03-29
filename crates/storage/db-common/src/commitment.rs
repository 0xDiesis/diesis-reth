//! Pluggable state commitment trait for genesis initialization.
//!
//! This module defines [`GenesisCommitmentProvider`], which allows Diesis to inject
//! a Verkle-tree-based genesis commitment in place of the default Merkle Patricia Trie.

use alloy_genesis::Genesis;
use alloy_primitives::B256;
use reth_db_api::transaction::DbTxMut;
use reth_provider::{DBProvider, StorageSettingsCache, TrieWriter};
use crate::init::{compute_state_root_for_commitment, InitStorageError};

/// Pluggable state commitment for genesis initialization.
///
/// MPT is the default in upstream reth; Diesis implements this with Verkle.
/// Implementors receive the genesis allocations and are responsible for:
/// 1. Computing the genesis state root.
/// 2. Persisting any commitment-specific data (e.g. trie nodes) via the provider.
pub trait GenesisCommitmentProvider: Send + Sync {
    /// Opaque commitment data produced by [`compute_genesis_root`] and consumed by
    /// [`write_genesis_commitment`]. Keeping it as an associated type avoids heap allocation for
    /// the common MPT case.
    ///
    /// [`compute_genesis_root`]: GenesisCommitmentProvider::compute_genesis_root
    /// [`write_genesis_commitment`]: GenesisCommitmentProvider::write_genesis_commitment
    type CommitmentData: Send + Sync;

    /// Compute the genesis state root from the hashed state that has already been written to the
    /// provider's database.
    ///
    /// Returns the state root hash and any associated commitment data that must later be
    /// persisted by [`write_genesis_commitment`].
    ///
    /// # Errors
    ///
    /// Returns [`InitStorageError`] if state root computation fails.
    ///
    /// [`write_genesis_commitment`]: GenesisCommitmentProvider::write_genesis_commitment
    fn compute_genesis_root<Provider>(
        &self,
        provider: &Provider,
        genesis: &Genesis,
    ) -> Result<(B256, Self::CommitmentData), InitStorageError>
    where
        Provider: DBProvider<Tx: DbTxMut> + TrieWriter + StorageSettingsCache;

    /// Persist commitment data within the already-open genesis MDBX transaction.
    ///
    /// Called after [`compute_genesis_root`] and before the transaction is committed.
    ///
    /// # Errors
    ///
    /// Returns [`InitStorageError`] if writing fails.
    ///
    /// [`compute_genesis_root`]: GenesisCommitmentProvider::compute_genesis_root
    fn write_genesis_commitment<Provider>(
        &self,
        provider: &Provider,
        data: Self::CommitmentData,
    ) -> Result<(), InitStorageError>
    where
        Provider: DBProvider<Tx: DbTxMut> + TrieWriter + StorageSettingsCache;
}

/// Default [`GenesisCommitmentProvider`] that uses the Merkle Patricia Trie (MPT).
///
/// Wraps the existing [`compute_state_root`] + [`write_trie_updates`] logic from `init.rs` and
/// acts as a drop-in default for chains that have not opted into Verkle trees.
///
/// [`compute_state_root`]: crate::init::compute_state_root_for_commitment
/// [`write_trie_updates`]: reth_provider::TrieWriter::write_trie_updates
#[derive(Debug, Default, Clone)]
pub struct MptGenesisCommitment;

impl GenesisCommitmentProvider for MptGenesisCommitment {
    /// The trie updates produced during state root computation, which must be flushed to the
    /// database after the root is computed.
    type CommitmentData = ();

    fn compute_genesis_root<Provider>(
        &self,
        provider: &Provider,
        _genesis: &Genesis,
    ) -> Result<(B256, Self::CommitmentData), InitStorageError>
    where
        Provider: DBProvider<Tx: DbTxMut> + TrieWriter + StorageSettingsCache,
    {
        // Delegate to the existing MPT state root computation in init.rs.
        // Trie writes happen inside compute_state_root_for_commitment, so no extra
        // CommitmentData needs to be stored here.
        let root = compute_state_root_for_commitment(provider, None)?;
        Ok((root, ()))
    }

    fn write_genesis_commitment<Provider>(
        &self,
        _provider: &Provider,
        _data: Self::CommitmentData,
    ) -> Result<(), InitStorageError>
    where
        Provider: DBProvider<Tx: DbTxMut> + TrieWriter + StorageSettingsCache,
    {
        // All trie updates were already written inside compute_state_root_for_commitment.
        Ok(())
    }
}
