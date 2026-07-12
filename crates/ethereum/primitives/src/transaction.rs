//! Diesis transaction primitives.
//!
//! This module keeps Reth's typed Ethereum transaction envelope API and extends it with
//! Diesis-only transaction type `0x70` for ML-DSA signatures. Ethereum-only callers can
//! convert supported variants into Alloy envelopes; consensus, receipt, and network paths use
//! [`DiesisTxType`] or [`Typed2718::ty`] so custom type bytes do not collapse into
//! [`TxType`].

use alloc::vec::Vec;
use alloy_consensus::{
    error::ValueError,
    transaction::{RlpEcdsaDecodableTx, RlpEcdsaEncodableTx, SignerRecoverable, TxHashRef},
    EthereumTxEnvelope, SignableTransaction, Signed, TransactionEnvelope, TxEip1559, TxEip2930,
    TxEip4844, TxEip4844Variant, TxEip4844WithSidecar, TxEip7702, TxLegacy, TxType, Typed2718,
};
use alloy_eips::{
    eip2718::{Decodable2718, Eip2718Error, Eip2718Result, Encodable2718, IsTyped2718},
    eip2930::AccessList,
    eip7594::BlobTransactionSidecarVariant,
    eip7702::SignedAuthorization,
};
use alloy_primitives::{
    bytes::BufMut, keccak256, Address, Bytes, ChainId, Signature, TxHash, TxKind, B256, U256,
};
#[cfg(feature = "reth-codec")]
use alloy_rlp::bytes;
use alloy_rlp::{Decodable, Encodable};
use core::hash::{Hash, Hasher};
use reth_primitives_traits::{
    crypto::secp256k1::{recover_signer, recover_signer_unchecked},
    sync::OnceLock,
    transaction::signed::RecoveryError,
    InMemorySize,
};

use crate::{
    tx_ml_dsa::{TxMlDsa, ML_DSA_TX_TYPE_ID},
    DiesisTxType,
};

/// A type alias for [`alloy_consensus::transaction::PooledTransaction`] that's also generic over
/// blob sidecar.
pub type PooledTransactionVariant =
    EthereumTxEnvelope<TxEip4844WithSidecar<BlobTransactionSidecarVariant>>;

macro_rules! delegate {
    ($self:expr => $tx:ident.$method:ident($($arg:expr),*)) => {
        match $self {
            Transaction::Legacy($tx) => $tx.$method($($arg),*),
            Transaction::Eip2930($tx) => $tx.$method($($arg),*),
            Transaction::Eip1559($tx) => $tx.$method($($arg),*),
            Transaction::Eip4844($tx) => $tx.$method($($arg),*),
            Transaction::Eip7702($tx) => $tx.$method($($arg),*),
            Transaction::MlDsa($tx) => $tx.$method($($arg),*),
        }
    };
}

/// Delegate to all ECDSA transaction variants (excludes ML-DSA).
macro_rules! delegate_ecdsa {
    ($self:expr => $tx:ident.$method:ident($($arg:expr),*)) => {
        match $self {
            Transaction::Legacy($tx) => $tx.$method($($arg),*),
            Transaction::Eip2930($tx) => $tx.$method($($arg),*),
            Transaction::Eip1559($tx) => $tx.$method($($arg),*),
            Transaction::Eip4844($tx) => $tx.$method($($arg),*),
            Transaction::Eip7702($tx) => $tx.$method($($arg),*),
            Transaction::MlDsa(_) => unreachable!("MlDsa handled before delegate_ecdsa"),
        }
    };
}

/// A raw transaction.
///
/// Transaction types were introduced in [EIP-2718](https://eips.ethereum.org/EIPS/eip-2718).
#[derive(Debug, Clone, PartialEq, Eq, Hash, derive_more::From)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::add_arbitrary_tests(compact))]
pub enum Transaction {
    /// Legacy transaction (type `0x0`).
    ///
    /// Traditional Ethereum transactions, containing parameters `nonce`, `gasPrice`, `gasLimit`,
    /// `to`, `value`, `data`, `v`, `r`, and `s`.
    ///
    /// These transactions do not utilize access lists nor do they incorporate EIP-1559 fee market
    /// changes.
    Legacy(TxLegacy),
    /// Transaction with an [`AccessList`] ([EIP-2930](https://eips.ethereum.org/EIPS/eip-2930)), type `0x1`.
    ///
    /// The `accessList` specifies an array of addresses and storage keys that the transaction
    /// plans to access, enabling gas savings on cross-contract calls by pre-declaring the accessed
    /// contract and storage slots.
    Eip2930(TxEip2930),
    /// A transaction with a priority fee ([EIP-1559](https://eips.ethereum.org/EIPS/eip-1559)), type `0x2`.
    ///
    /// Unlike traditional transactions, EIP-1559 transactions use an in-protocol, dynamically
    /// changing base fee per gas, adjusted at each block to manage network congestion.
    ///
    /// - `maxPriorityFeePerGas`, specifying the maximum fee above the base fee the sender is
    ///   willing to pay
    /// - `maxFeePerGas`, setting the maximum total fee the sender is willing to pay.
    ///
    /// The base fee is burned, while the priority fee is paid to the miner who includes the
    /// transaction, incentivizing miners to include transactions with higher priority fees per
    /// gas.
    Eip1559(TxEip1559),
    /// Shard Blob Transactions ([EIP-4844](https://eips.ethereum.org/EIPS/eip-4844)), type `0x3`.
    ///
    /// Shard Blob Transactions introduce a new transaction type called a blob-carrying transaction
    /// to reduce gas costs. These transactions are similar to regular Ethereum transactions but
    /// include additional data called a blob.
    ///
    /// Blobs are larger (~125 kB) and cheaper than the current calldata, providing an immutable
    /// and read-only memory for storing transaction data.
    ///
    /// EIP-4844, also known as proto-danksharding, implements the framework and logic of
    /// danksharding, introducing new transaction formats and verification rules.
    Eip4844(TxEip4844),
    /// EOA Set Code Transactions ([EIP-7702](https://eips.ethereum.org/EIPS/eip-7702)), type `0x4`.
    ///
    /// EOA Set Code Transactions give the ability to set contract code for an EOA in perpetuity
    /// until re-assigned by the same EOA. This allows for adding smart contract functionality to
    /// the EOA.
    Eip7702(TxEip7702),
    /// ML-DSA post-quantum transaction (type `0x70`).
    ///
    /// Uses ML-DSA (FIPS 204) signatures instead of ECDSA. The sender address and
    /// signature are embedded in the transaction body since ML-DSA does not support
    /// public key recovery.
    MlDsa(TxMlDsa),
}

impl Transaction {
    /// Returns the Diesis transaction type.
    pub const fn tx_type(&self) -> DiesisTxType {
        match self {
            Self::Legacy(_) => DiesisTxType::Legacy,
            Self::Eip2930(_) => DiesisTxType::Eip2930,
            Self::Eip1559(_) => DiesisTxType::Eip1559,
            Self::Eip4844(_) => DiesisTxType::Eip4844,
            Self::Eip7702(_) => DiesisTxType::Eip7702,
            Self::MlDsa(_) => DiesisTxType::MlDsa,
        }
    }

    /// Returns the standard Ethereum [`TxType`] for non-Diesis transactions.
    ///
    /// Returns `None` for [`Transaction::MlDsa`] because `TxType` has no
    /// representation for Diesis type `0x70`. Use [`Typed2718::ty()`] when the
    /// raw EIP-2718 type byte is required.
    pub const fn standard_tx_type(&self) -> Option<TxType> {
        self.tx_type().ethereum()
    }

    /// Returns the upstream Ethereum transaction type when this transaction is
    /// not a Diesis-only extension.
    pub const fn ethereum_tx_type(&self) -> Option<TxType> {
        self.tx_type().ethereum()
    }

    #[cfg(test)]
    const fn input_mut(&mut self) -> &mut Bytes {
        match self {
            Self::Legacy(tx) => &mut tx.input,
            Self::Eip2930(tx) => &mut tx.input,
            Self::Eip1559(tx) => &mut tx.input,
            Self::Eip4844(tx) => &mut tx.input,
            Self::Eip7702(tx) => &mut tx.input,
            Self::MlDsa(tx) => &mut tx.input,
        }
    }
}

impl Typed2718 for Transaction {
    fn ty(&self) -> u8 {
        delegate!(self => tx.ty())
    }
}

impl alloy_consensus::Transaction for Transaction {
    fn chain_id(&self) -> Option<ChainId> {
        delegate!(self => tx.chain_id())
    }

    fn nonce(&self) -> u64 {
        delegate!(self => tx.nonce())
    }

    fn gas_limit(&self) -> u64 {
        delegate!(self => tx.gas_limit())
    }

    fn gas_price(&self) -> Option<u128> {
        delegate!(self => tx.gas_price())
    }

    fn max_fee_per_gas(&self) -> u128 {
        delegate!(self => tx.max_fee_per_gas())
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        delegate!(self => tx.max_priority_fee_per_gas())
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        delegate!(self => tx.max_fee_per_blob_gas())
    }

    fn priority_fee_or_price(&self) -> u128 {
        delegate!(self => tx.priority_fee_or_price())
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        delegate!(self => tx.effective_gas_price(base_fee))
    }

    fn is_dynamic_fee(&self) -> bool {
        delegate!(self => tx.is_dynamic_fee())
    }

    fn kind(&self) -> alloy_primitives::TxKind {
        delegate!(self => tx.kind())
    }

    fn is_create(&self) -> bool {
        delegate!(self => tx.is_create())
    }

    fn value(&self) -> alloy_primitives::U256 {
        delegate!(self => tx.value())
    }

    fn input(&self) -> &alloy_primitives::Bytes {
        delegate!(self => tx.input())
    }

    fn access_list(&self) -> Option<&alloy_eips::eip2930::AccessList> {
        delegate!(self => tx.access_list())
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        delegate!(self => tx.blob_versioned_hashes())
    }

    fn authorization_list(&self) -> Option<&[alloy_eips::eip7702::SignedAuthorization]> {
        delegate!(self => tx.authorization_list())
    }
}

impl SignableTransaction<Signature> for Transaction {
    fn set_chain_id(&mut self, chain_id: alloy_primitives::ChainId) {
        delegate!(self => tx.set_chain_id(chain_id))
    }

    fn encode_for_signing(&self, out: &mut dyn alloy_rlp::BufMut) {
        delegate!(self => tx.encode_for_signing(out))
    }

    fn payload_len_for_signature(&self) -> usize {
        delegate!(self => tx.payload_len_for_signature())
    }

    fn into_signed(self, signature: Signature) -> Signed<Self> {
        // ML-DSA tx hash is independent of the ECDSA signature.
        let (signature, tx_hash) = match &self {
            Self::MlDsa(tx) => (ml_dsa_dummy_signature(), tx.tx_hash()),
            _ => (signature, delegate_ecdsa!(&self => tx.tx_hash(&signature))),
        };
        Signed::new_unchecked(self, signature, tx_hash)
    }
}

impl InMemorySize for Transaction {
    fn size(&self) -> usize {
        delegate!(self => tx.size())
    }
}

#[cfg(any(test, feature = "reth-codec"))]
impl reth_codecs::Compact for Transaction {
    // Serializes the TxType to the buffer if necessary, returning 2 bits of the type as an
    // identifier instead of the length.
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: alloy_rlp::bytes::BufMut + AsMut<[u8]>,
    {
        let identifier = self.tx_type().to_compact(buf);
        delegate!(self => tx.to_compact(buf));
        identifier
    }

    // For backwards compatibility purposes, only 2 bits of the type are encoded in the identifier
    // parameter. In the case of a [`COMPACT_EXTENDED_IDENTIFIER_FLAG`], the full transaction type
    // is read from the buffer as a single byte.
    //
    // # Panics
    //
    // A panic will be triggered if an identifier larger than 3 is passed from the database. For
    // optimism an identifier with value [`DEPOSIT_TX_TYPE_ID`] is allowed.
    fn from_compact(buf: &[u8], identifier: usize) -> (Self, &[u8]) {
        let (tx_type, buf) = DiesisTxType::from_compact(buf, identifier);

        match tx_type {
            DiesisTxType::Legacy => {
                let (tx, buf) = TxLegacy::from_compact(buf, buf.len());
                (Self::Legacy(tx), buf)
            }
            DiesisTxType::Eip2930 => {
                let (tx, buf) = TxEip2930::from_compact(buf, buf.len());
                (Self::Eip2930(tx), buf)
            }
            DiesisTxType::Eip1559 => {
                let (tx, buf) = TxEip1559::from_compact(buf, buf.len());
                (Self::Eip1559(tx), buf)
            }
            DiesisTxType::Eip4844 => {
                let (tx, buf) = TxEip4844::from_compact(buf, buf.len());
                (Self::Eip4844(tx), buf)
            }
            DiesisTxType::Eip7702 => {
                let (tx, buf) = TxEip7702::from_compact(buf, buf.len());
                (Self::Eip7702(tx), buf)
            }
            DiesisTxType::MlDsa => {
                let (tx, buf) = TxMlDsa::from_compact(buf, buf.len());
                (Self::MlDsa(tx), buf)
            }
        }
    }
}

impl RlpEcdsaEncodableTx for Transaction {
    fn rlp_encoded_fields_length(&self) -> usize {
        delegate!(self => tx.rlp_encoded_fields_length())
    }

    fn rlp_encode_fields(&self, out: &mut dyn BufMut) {
        delegate!(self => tx.rlp_encode_fields(out))
    }

    fn eip2718_encode_with_type(&self, signature: &Signature, _ty: u8, out: &mut dyn BufMut) {
        // ML-DSA carries its own signature in the tx body; ignore the ECDSA signature param.
        if let Self::MlDsa(tx) = self {
            tx.eip2718_encode(out);
            return;
        }
        delegate_ecdsa!(self => tx.eip2718_encode_with_type(signature, tx.ty(), out))
    }

    fn eip2718_encode(&self, signature: &Signature, out: &mut dyn BufMut) {
        if let Self::MlDsa(tx) = self {
            tx.eip2718_encode(out);
            return;
        }
        delegate_ecdsa!(self => tx.eip2718_encode(signature, out))
    }

    fn network_encode_with_type(&self, signature: &Signature, _ty: u8, out: &mut dyn BufMut) {
        if let Self::MlDsa(tx) = self {
            tx.eip2718_encode(out);
            return;
        }
        delegate_ecdsa!(self => tx.network_encode_with_type(signature, tx.ty(), out))
    }

    fn network_encode(&self, signature: &Signature, out: &mut dyn BufMut) {
        if let Self::MlDsa(tx) = self {
            tx.eip2718_encode(out);
            return;
        }
        delegate_ecdsa!(self => tx.network_encode(signature, out))
    }

    fn tx_hash_with_type(&self, signature: &Signature, _ty: u8) -> TxHash {
        // ML-DSA tx hash is independent of the ECDSA signature.
        if let Self::MlDsa(tx) = self {
            return tx.tx_hash();
        }
        delegate_ecdsa!(self => tx.tx_hash_with_type(signature, tx.ty()))
    }

    fn tx_hash(&self, signature: &Signature) -> TxHash {
        if let Self::MlDsa(tx) = self {
            return tx.tx_hash();
        }
        delegate_ecdsa!(self => tx.tx_hash(signature))
    }
}

/// Signed Ethereum transaction.
#[derive(Debug, Clone, Eq, derive_more::AsRef, derive_more::Deref)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::add_arbitrary_tests(rlp))]
#[cfg_attr(feature = "test-utils", derive(derive_more::DerefMut))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct TransactionSigned {
    /// Transaction hash
    #[cfg_attr(feature = "serde", serde(skip))]
    hash: OnceLock<TxHash>,
    /// The transaction signature values
    signature: Signature,
    /// Raw transaction info
    #[deref]
    #[as_ref]
    #[cfg_attr(feature = "test-utils", deref_mut)]
    transaction: Transaction,
}

impl TransactionSigned {
    fn recalculate_hash(&self) -> B256 {
        keccak256(self.encoded_2718())
    }

    const fn canonical_signature(transaction: &Transaction, signature: Signature) -> Signature {
        if matches!(transaction, Transaction::MlDsa(_)) {
            ml_dsa_dummy_signature()
        } else {
            signature
        }
    }

    fn canonical_hash(transaction: &Transaction, hash: B256) -> B256 {
        match transaction {
            Transaction::MlDsa(tx) => tx.tx_hash(),
            _ => hash,
        }
    }
}

impl Hash for TransactionSigned {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Self::canonical_signature(&self.transaction, self.signature).hash(state);
        self.transaction.hash(state);
    }
}

impl PartialEq for TransactionSigned {
    fn eq(&self, other: &Self) -> bool {
        Self::canonical_signature(&self.transaction, self.signature)
            == Self::canonical_signature(&other.transaction, other.signature)
            && self.transaction == other.transaction
            && self.tx_hash() == other.tx_hash()
    }
}

impl TransactionSigned {
    /// Creates a new signed transaction from the given transaction, signature and hash.
    pub fn new(transaction: Transaction, signature: Signature, hash: B256) -> Self {
        let signature = Self::canonical_signature(&transaction, signature);
        let hash = Self::canonical_hash(&transaction, hash);
        Self { hash: hash.into(), signature, transaction }
    }

    /// Creates a new signed transaction and lazily computes the hash on first access.
    pub const fn new_unhashed(transaction: Transaction, signature: Signature) -> Self {
        let signature = Self::canonical_signature(&transaction, signature);
        Self { hash: OnceLock::new(), signature, transaction }
    }

    /// Returns the transaction hash.
    #[inline]
    pub fn hash(&self) -> &B256 {
        self.hash.get_or_init(|| self.recalculate_hash())
    }

    /// Splits the transaction into parts.
    pub fn into_parts(self) -> (Transaction, Signature, B256) {
        let hash = *self.hash.get_or_init(|| self.recalculate_hash());
        (self.transaction, self.signature, hash)
    }

    /// Returns the EIP-4844 transaction as a signed value if this is an EIP-4844 envelope.
    pub fn as_eip4844(&self) -> Option<Signed<TxEip4844>> {
        match &self.transaction {
            Transaction::Eip4844(tx) => {
                Some(Signed::new_unchecked(tx.clone(), self.signature, *self.hash()))
            }
            _ => None,
        }
    }

    /// Converts this transaction into a pooled EIP-4844 envelope with the given sidecar.
    pub fn try_into_pooled_eip4844<T>(
        self,
        sidecar: T,
    ) -> Result<EthereumTxEnvelope<TxEip4844WithSidecar<T>>, ValueError<Self>> {
        let (tx, signature, hash) = self.into_parts();
        match tx {
            Transaction::Eip4844(tx) => Ok(EthereumTxEnvelope::Eip4844(Signed::new_unchecked(
                tx.with_sidecar(sidecar),
                signature,
                hash,
            ))),
            tx => Err(ValueError::new_static(
                Self::new(tx, signature, hash),
                "Expected 4844 transaction",
            )),
        }
    }
}

impl Typed2718 for TransactionSigned {
    fn ty(&self) -> u8 {
        self.transaction.ty()
    }
}

impl TransactionEnvelope for TransactionSigned {
    type TxType = DiesisTxType;

    fn tx_type(&self) -> Self::TxType {
        self.transaction.tx_type()
    }
}

impl alloy_consensus::Transaction for TransactionSigned {
    fn chain_id(&self) -> Option<ChainId> {
        self.transaction.chain_id()
    }

    fn nonce(&self) -> u64 {
        self.transaction.nonce()
    }

    fn gas_limit(&self) -> u64 {
        self.transaction.gas_limit()
    }

    fn gas_price(&self) -> Option<u128> {
        self.transaction.gas_price()
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.transaction.max_fee_per_gas()
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.transaction.max_priority_fee_per_gas()
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        self.transaction.max_fee_per_blob_gas()
    }

    fn priority_fee_or_price(&self) -> u128 {
        self.transaction.priority_fee_or_price()
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        self.transaction.effective_gas_price(base_fee)
    }

    fn is_dynamic_fee(&self) -> bool {
        self.transaction.is_dynamic_fee()
    }

    fn kind(&self) -> TxKind {
        self.transaction.kind()
    }

    fn is_create(&self) -> bool {
        self.transaction.is_create()
    }

    fn value(&self) -> U256 {
        self.transaction.value()
    }

    fn input(&self) -> &Bytes {
        self.transaction.input()
    }

    fn access_list(&self) -> Option<&AccessList> {
        self.transaction.access_list()
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        self.transaction.blob_versioned_hashes()
    }

    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        self.transaction.authorization_list()
    }
}

impl alloy_evm::FromRecoveredTx<TransactionSigned> for revm::context::TxEnv {
    fn from_recovered_tx(tx: &TransactionSigned, caller: Address) -> Self {
        match &tx.transaction {
            Transaction::Legacy(tx) => {
                <Self as alloy_evm::FromRecoveredTx<TxLegacy>>::from_recovered_tx(tx, caller)
            }
            Transaction::Eip2930(tx) => {
                <Self as alloy_evm::FromRecoveredTx<TxEip2930>>::from_recovered_tx(tx, caller)
            }
            Transaction::Eip1559(tx) => {
                <Self as alloy_evm::FromRecoveredTx<TxEip1559>>::from_recovered_tx(tx, caller)
            }
            Transaction::Eip4844(tx) => {
                <Self as alloy_evm::FromRecoveredTx<TxEip4844>>::from_recovered_tx(tx, caller)
            }
            Transaction::Eip7702(tx) => {
                <Self as alloy_evm::FromRecoveredTx<TxEip7702>>::from_recovered_tx(tx, caller)
            }
            Transaction::MlDsa(tx) => Self {
                tx_type: ML_DSA_TX_TYPE_ID,
                caller,
                gas_limit: tx.gas_limit,
                gas_price: tx.max_fee_per_gas,
                kind: tx.to,
                value: tx.value,
                data: tx.input.clone(),
                nonce: tx.nonce,
                chain_id: Some(tx.chain_id),
                access_list: tx.access_list.clone(),
                gas_priority_fee: Some(tx.max_priority_fee_per_gas),
                blob_hashes: Vec::new(),
                max_fee_per_blob_gas: 0,
                authorization_list: Vec::new(),
            },
        }
    }
}

impl alloy_evm::FromTxWithEncoded<TransactionSigned> for revm::context::TxEnv {
    fn from_encoded_tx(tx: &TransactionSigned, caller: Address, encoded: Bytes) -> Self {
        match &tx.transaction {
            Transaction::Legacy(tx) => {
                <Self as alloy_evm::FromTxWithEncoded<TxLegacy>>::from_encoded_tx(
                    tx, caller, encoded,
                )
            }
            Transaction::Eip2930(tx) => {
                <Self as alloy_evm::FromTxWithEncoded<TxEip2930>>::from_encoded_tx(
                    tx, caller, encoded,
                )
            }
            Transaction::Eip1559(tx) => {
                <Self as alloy_evm::FromTxWithEncoded<TxEip1559>>::from_encoded_tx(
                    tx, caller, encoded,
                )
            }
            Transaction::Eip4844(tx) => {
                <Self as alloy_evm::FromTxWithEncoded<TxEip4844>>::from_encoded_tx(
                    tx, caller, encoded,
                )
            }
            Transaction::Eip7702(tx) => {
                <Self as alloy_evm::FromTxWithEncoded<TxEip7702>>::from_encoded_tx(
                    tx, caller, encoded,
                )
            }
            Transaction::MlDsa(_) => {
                <Self as alloy_evm::FromRecoveredTx<TransactionSigned>>::from_recovered_tx(
                    tx, caller,
                )
            }
        }
    }
}

impl From<Signed<Transaction>> for TransactionSigned {
    fn from(value: Signed<Transaction>) -> Self {
        let (tx, sig, hash) = value.into_parts();
        Self::new(tx, sig, hash)
    }
}

impl From<Signed<TxLegacy>> for TransactionSigned {
    fn from(value: Signed<TxLegacy>) -> Self {
        let (tx, sig, hash) = value.into_parts();
        Self::new(Transaction::Legacy(tx), sig, hash)
    }
}

impl From<Signed<TxEip2930>> for TransactionSigned {
    fn from(value: Signed<TxEip2930>) -> Self {
        let (tx, sig, hash) = value.into_parts();
        Self::new(Transaction::Eip2930(tx), sig, hash)
    }
}

impl From<Signed<TxEip1559>> for TransactionSigned {
    fn from(value: Signed<TxEip1559>) -> Self {
        let (tx, sig, hash) = value.into_parts();
        Self::new(Transaction::Eip1559(tx), sig, hash)
    }
}

impl From<Signed<TxEip4844>> for TransactionSigned {
    fn from(value: Signed<TxEip4844>) -> Self {
        let (tx, sig, hash) = value.into_parts();
        Self::new(Transaction::Eip4844(tx), sig, hash)
    }
}

impl From<Signed<TxEip7702>> for TransactionSigned {
    fn from(value: Signed<TxEip7702>) -> Self {
        let (tx, sig, hash) = value.into_parts();
        Self::new(Transaction::Eip7702(tx), sig, hash)
    }
}

impl<Eip4844> From<EthereumTxEnvelope<Eip4844>> for TransactionSigned
where
    Eip4844: Into<TxEip4844>,
{
    fn from(value: EthereumTxEnvelope<Eip4844>) -> Self {
        let value = value.map_eip4844(Into::into);
        match value {
            EthereumTxEnvelope::Legacy(tx) => {
                let (tx, signature, hash) = tx.into_parts();
                Self::new(Transaction::Legacy(tx), signature, hash)
            }
            EthereumTxEnvelope::Eip2930(tx) => {
                let (tx, signature, hash) = tx.into_parts();
                Self::new(Transaction::Eip2930(tx), signature, hash)
            }
            EthereumTxEnvelope::Eip1559(tx) => {
                let (tx, signature, hash) = tx.into_parts();
                Self::new(Transaction::Eip1559(tx), signature, hash)
            }
            EthereumTxEnvelope::Eip4844(tx) => {
                let (tx, signature, hash) = tx.into_parts();
                Self::new(Transaction::Eip4844(tx), signature, hash)
            }
            EthereumTxEnvelope::Eip7702(tx) => {
                let (tx, signature, hash) = tx.into_parts();
                Self::new(Transaction::Eip7702(tx), signature, hash)
            }
        }
    }
}

/// Error message returned when an ML-DSA transaction is converted to an Ethereum-only
/// representation.
const ML_DSA_NOT_AN_ETHEREUM_ENVELOPE: &str =
    "ML-DSA transactions are not representable as Ethereum transaction envelopes";

// NOTE: these conversions are fallible (unlike upstream reth where `TransactionSigned` is the
// envelope itself) because the Diesis ML-DSA transaction (0x70) has no `EthereumTxEnvelope`
// variant. Infallible `From` impls here would have to panic on ML-DSA transactions read from the
// database or received over the network, which is not acceptable on RPC serving paths.
impl TryFrom<TransactionSigned> for EthereumTxEnvelope<TxEip4844> {
    type Error = ValueError<TransactionSigned>;

    fn try_from(value: TransactionSigned) -> Result<Self, Self::Error> {
        let (tx, signature, hash) = value.into_parts();
        match tx {
            Transaction::Legacy(tx) => Ok(Signed::new_unchecked(tx, signature, hash).into()),
            Transaction::Eip2930(tx) => Ok(Signed::new_unchecked(tx, signature, hash).into()),
            Transaction::Eip1559(tx) => Ok(Signed::new_unchecked(tx, signature, hash).into()),
            Transaction::Eip4844(tx) => Ok(Signed::new_unchecked(tx, signature, hash).into()),
            Transaction::Eip7702(tx) => Ok(Signed::new_unchecked(tx, signature, hash).into()),
            Transaction::MlDsa(tx) => {
                let value = TransactionSigned::new(Transaction::MlDsa(tx), signature, hash);
                Err(ValueError::new_static(value, ML_DSA_NOT_AN_ETHEREUM_ENVELOPE))
            }
        }
    }
}

impl TryFrom<TransactionSigned> for EthereumTxEnvelope<TxEip4844Variant> {
    type Error = ValueError<TransactionSigned>;

    fn try_from(value: TransactionSigned) -> Result<Self, Self::Error> {
        let (tx, signature, hash) = value.into_parts();
        match tx {
            Transaction::Legacy(tx) => Ok(Signed::new_unchecked(tx, signature, hash).into()),
            Transaction::Eip2930(tx) => Ok(Signed::new_unchecked(tx, signature, hash).into()),
            Transaction::Eip1559(tx) => Ok(Signed::new_unchecked(tx, signature, hash).into()),
            Transaction::Eip4844(tx) => {
                let signed = Signed::new_unchecked(tx, signature, hash);
                let signed: Signed<TxEip4844Variant> = signed.into();
                Ok(signed.into())
            }
            Transaction::Eip7702(tx) => Ok(Signed::new_unchecked(tx, signature, hash).into()),
            Transaction::MlDsa(tx) => {
                let value = TransactionSigned::new(Transaction::MlDsa(tx), signature, hash);
                Err(ValueError::new_static(value, ML_DSA_NOT_AN_ETHEREUM_ENVELOPE))
            }
        }
    }
}

#[cfg(feature = "rpc")]
impl reth_rpc_traits::FromConsensusTx<TransactionSigned> for alloy_rpc_types_eth::Transaction {
    type TxInfo = alloy_rpc_types_eth::TransactionInfo;
    type Err = ValueError<TransactionSigned>;

    fn from_consensus_tx(
        tx: TransactionSigned,
        signer: Address,
        tx_info: Self::TxInfo,
    ) -> Result<Self, Self::Err> {
        // This replaces the blanket impl in `reth-rpc-traits` (which requires an infallible
        // `From` conversion into the Ethereum envelope) so that ML-DSA transactions read from
        // the database yield a typed error instead of panicking when served over RPC.
        let envelope = EthereumTxEnvelope::<TxEip4844Variant>::try_from(tx)?;
        Ok(Self::from_transaction(
            alloy_consensus::transaction::Recovered::new_unchecked(envelope, signer),
            tx_info,
        ))
    }
}

#[cfg(feature = "rpc")]
impl From<alloy_rpc_types_eth::Transaction> for TransactionSigned {
    fn from(value: alloy_rpc_types_eth::Transaction) -> Self {
        value.into_inner().into()
    }
}

#[cfg(feature = "rpc")]
impl reth_rpc_traits::SignableTxRequest<TransactionSigned>
    for alloy_rpc_types_eth::TransactionRequest
{
    async fn try_build_and_sign(
        self,
        signer: impl alloy_network::TxSigner<Signature> + Send,
    ) -> Result<TransactionSigned, reth_rpc_traits::SignTxRequestError> {
        let mut tx = self
            .build_typed_tx()
            .map_err(|_| reth_rpc_traits::SignTxRequestError::InvalidTransactionRequest)?;
        let signature = signer.sign_transaction(&mut tx).await?;
        let envelope: EthereumTxEnvelope<TxEip4844> = tx.into_signed(signature).into();
        Ok(TransactionSigned::from(envelope))
    }
}

#[cfg(feature = "rpc")]
impl reth_rpc_traits::TryIntoSimTx<TransactionSigned> for alloy_rpc_types_eth::TransactionRequest {
    fn try_into_sim_tx(self) -> Result<TransactionSigned, ValueError<Self>> {
        self.build_typed_simulate_transaction().map(TransactionSigned::from)
    }
}

impl TryFrom<TransactionSigned> for PooledTransactionVariant {
    type Error = ValueError<TransactionSigned>;

    fn try_from(value: TransactionSigned) -> Result<Self, Self::Error> {
        let (tx, signature, hash) = value.into_parts();
        match tx {
            Transaction::Legacy(tx) => Ok(Signed::new_unchecked(tx, signature, hash).into()),
            Transaction::Eip2930(tx) => Ok(Signed::new_unchecked(tx, signature, hash).into()),
            Transaction::Eip1559(tx) => Ok(Signed::new_unchecked(tx, signature, hash).into()),
            Transaction::Eip7702(tx) => Ok(Signed::new_unchecked(tx, signature, hash).into()),
            Transaction::Eip4844(tx) => {
                let value = TransactionSigned::new(Transaction::Eip4844(tx), signature, hash);
                Err(ValueError::new_static(
                    value,
                    "EIP-4844 transaction is missing its blob sidecar",
                ))
            }
            Transaction::MlDsa(tx) => {
                let value = TransactionSigned::new(Transaction::MlDsa(tx), signature, hash);
                Err(ValueError::new_static(
                    value,
                    "ML-DSA transactions are not representable as pooled Ethereum transactions",
                ))
            }
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for TransactionSigned {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        #[expect(unused_mut)]
        let mut transaction = Transaction::arbitrary(u)?;

        // ML-DSA carries its own signature in the tx body — use a dummy ECDSA signature.
        if matches!(transaction, Transaction::MlDsa(_)) {
            return Ok(Self {
                transaction,
                signature: Signature::new(U256::ZERO, U256::ZERO, false),
                hash: Default::default(),
            });
        }

        let secp = secp256k1::Secp256k1::new();
        let key_pair = secp256k1::Keypair::new(&secp, &mut rand_08::thread_rng());
        let signature = reth_primitives_traits::crypto::secp256k1::sign_message(
            B256::from_slice(&key_pair.secret_bytes()[..]),
            transaction.signature_hash(),
        )
        .unwrap();

        Ok(Self { transaction, signature, hash: Default::default() })
    }
}

impl InMemorySize for TransactionSigned {
    fn size(&self) -> usize {
        let Self { hash: _, signature, transaction } = self;
        self.tx_hash().size() + signature.size() + transaction.size()
    }
}

impl Encodable2718 for TransactionSigned {
    fn type_flag(&self) -> Option<u8> {
        (!self.transaction.is_legacy()).then(|| self.ty())
    }

    fn encode_2718_len(&self) -> usize {
        // ML-DSA has its own encoding that doesn't take an ECDSA signature parameter.
        match &self.transaction {
            Transaction::MlDsa(tx) => tx.eip2718_encoded_length(),
            _ => delegate_ecdsa!(&self.transaction => tx.eip2718_encoded_length(&self.signature)),
        }
    }

    fn encode_2718(&self, out: &mut dyn alloy_rlp::BufMut) {
        match &self.transaction {
            Transaction::MlDsa(tx) => tx.eip2718_encode(out),
            _ => delegate_ecdsa!(&self.transaction => tx.eip2718_encode(&self.signature, out)),
        }
    }

    fn trie_hash(&self) -> B256 {
        *self.tx_hash()
    }
}

const fn ml_dsa_dummy_signature() -> Signature {
    Signature::new(U256::ZERO, U256::ZERO, false)
}

impl Decodable2718 for TransactionSigned {
    fn typed_decode(ty: u8, buf: &mut &[u8]) -> Eip2718Result<Self> {
        // Handle ML-DSA (0x70) before TxType conversion since TxType has no MlDsa variant.
        if ty == ML_DSA_TX_TYPE_ID {
            let tx = TxMlDsa::eip2718_decode(buf).map_err(|_| Eip2718Error::UnexpectedType(ty))?;
            return Ok(Self {
                transaction: Transaction::MlDsa(tx),
                signature: ml_dsa_dummy_signature(),
                hash: Default::default(),
            });
        }

        match ty.try_into().map_err(|_| Eip2718Error::UnexpectedType(ty))? {
            TxType::Legacy => Err(Eip2718Error::UnexpectedType(0)),
            TxType::Eip2930 => {
                let (tx, signature) = TxEip2930::rlp_decode_with_signature(buf)?;
                Ok(Self {
                    transaction: Transaction::Eip2930(tx),
                    signature,
                    hash: Default::default(),
                })
            }
            TxType::Eip1559 => {
                let (tx, signature) = TxEip1559::rlp_decode_with_signature(buf)?;
                Ok(Self {
                    transaction: Transaction::Eip1559(tx),
                    signature,
                    hash: Default::default(),
                })
            }
            TxType::Eip4844 => {
                let (tx, signature) = TxEip4844::rlp_decode_with_signature(buf)?;
                Ok(Self {
                    transaction: Transaction::Eip4844(tx),
                    signature,
                    hash: Default::default(),
                })
            }
            TxType::Eip7702 => {
                let (tx, signature) = TxEip7702::rlp_decode_with_signature(buf)?;
                Ok(Self {
                    transaction: Transaction::Eip7702(tx),
                    signature,
                    hash: Default::default(),
                })
            }
        }
    }

    fn fallback_decode(buf: &mut &[u8]) -> Eip2718Result<Self> {
        let (tx, signature) = TxLegacy::rlp_decode_with_signature(buf)?;
        Ok(Self { transaction: Transaction::Legacy(tx), signature, hash: Default::default() })
    }
}

impl Encodable for TransactionSigned {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.network_encode(out);
    }

    fn length(&self) -> usize {
        self.network_len()
    }
}

impl Decodable for TransactionSigned {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Self::network_decode(buf).map_err(Into::into)
    }
}

#[cfg(any(test, feature = "reth-codec"))]
impl reth_codecs::Compact for TransactionSigned {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: alloy_rlp::bytes::BufMut + AsMut<[u8]>,
    {
        use alloy_consensus::Transaction;

        let start = buf.as_mut().len();

        // Placeholder for bitflags.
        // The first byte uses 4 bits as flags: IsCompressed[1bit], TxType[2bits], Signature[1bit]
        buf.put_u8(0);

        let signature = Self::canonical_signature(&self.transaction, self.signature);
        let sig_bit = signature.to_compact(buf) as u8;
        let zstd_bit = self.transaction.input().len() >= 32;

        let tx_bits = if zstd_bit {
            let mut tmp = Vec::with_capacity(256);
            reth_zstd_compressors::with_tx_compressor(|compressor| {
                let tx_bits = self.transaction.to_compact(&mut tmp);
                buf.put_slice(&compressor.compress(&tmp).expect("Failed to compress"));
                tx_bits as u8
            })
        } else {
            self.transaction.to_compact(buf) as u8
        };

        // Replace bitflags with the actual values
        buf.as_mut()[start] = sig_bit | (tx_bits << 1) | ((zstd_bit as u8) << 3);

        buf.as_mut().len() - start
    }

    fn from_compact(mut buf: &[u8], _len: usize) -> (Self, &[u8]) {
        use alloy_rlp::bytes::Buf;

        // The first byte uses 4 bits as flags: IsCompressed[1], TxType[2], Signature[1]
        let bitflags = buf.get_u8() as usize;

        let sig_bit = bitflags & 1;
        let (signature, buf) = Signature::from_compact(buf, sig_bit);

        let zstd_bit = bitflags >> 3;
        let (transaction, buf) = if zstd_bit != 0 {
            reth_zstd_compressors::with_tx_decompressor(|decompressor| {
                // Compact decoding keeps zstd at the envelope boundary; the
                // decompressed payload is decoded as an uncompressed transaction.
                let transaction_type = (bitflags & 0b110) >> 1;
                let (transaction, _) =
                    Transaction::from_compact(decompressor.decompress(buf), transaction_type);
                (transaction, buf)
            })
        } else {
            let transaction_type = bitflags >> 1;
            Transaction::from_compact(buf, transaction_type)
        };

        let signature = Self::canonical_signature(&transaction, signature);
        (Self { signature, transaction, hash: Default::default() }, buf)
    }
}

#[cfg(feature = "reth-codec")]
reth_codecs::impl_compression_for_compact!(TransactionSigned);

impl SignerRecoverable for TransactionSigned {
    fn recover_signer(&self) -> Result<Address, RecoveryError> {
        if let Transaction::MlDsa(tx) = &self.transaction {
            tx.validate_key_material_shape().map_err(RecoveryError::from_source)?;
            return Err(RecoveryError::new());
        }
        let signature_hash = self.transaction.signature_hash();
        recover_signer(&self.signature, signature_hash)
    }

    fn recover_signer_unchecked(&self) -> Result<Address, RecoveryError> {
        if matches!(&self.transaction, Transaction::MlDsa(_)) {
            return Err(RecoveryError::new());
        }
        let signature_hash = self.transaction.signature_hash();
        recover_signer_unchecked(&self.signature, signature_hash)
    }

    fn recover_unchecked_with_buf(&self, buf: &mut Vec<u8>) -> Result<Address, RecoveryError> {
        if matches!(&self.transaction, Transaction::MlDsa(_)) {
            return Err(RecoveryError::new());
        }
        self.transaction.encode_for_signing(buf);
        let signature_hash = keccak256(buf);
        recover_signer_unchecked(&self.signature, signature_hash)
    }
}

impl TxHashRef for TransactionSigned {
    fn tx_hash(&self) -> &TxHash {
        self.hash.get_or_init(|| self.recalculate_hash())
    }
}

impl IsTyped2718 for TransactionSigned {
    fn is_type(type_id: u8) -> bool {
        type_id == ML_DSA_TX_TYPE_ID
            || <alloy_consensus::TxEnvelope as IsTyped2718>::is_type(type_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{transaction::SignerRecoverable, EthereumTxEnvelope};
    use proptest::proptest;
    use proptest_arbitrary_interop::arb;
    use reth_codecs::Compact;
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };

    fn empty_ml_dsa_transaction() -> TxMlDsa {
        TxMlDsa {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            gas_limit: 21_000,
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            input: Bytes::new(),
            access_list: AccessList::default(),
            sender: Address::ZERO,
            ml_dsa_level: 44,
            pubkey: Bytes::new(),
            ml_dsa_signature: Bytes::from(vec![0u8; crate::tx_ml_dsa::ML_DSA_44_SIGNATURE_LEN]),
        }
    }

    #[test]
    fn ml_dsa_transaction_has_raw_type_without_standard_txtype() {
        let tx = Transaction::MlDsa(empty_ml_dsa_transaction());

        assert_eq!(tx.standard_tx_type(), None);
        assert_eq!(tx.ty(), ML_DSA_TX_TYPE_ID);
    }

    #[test]
    fn ml_dsa_transaction_envelope_conversion_errors_instead_of_panicking() {
        let tx = Transaction::MlDsa(empty_ml_dsa_transaction());
        let signed = TransactionSigned::new(tx, Signature::test_signature(), B256::ZERO);

        // Both Ethereum envelope conversions must surface a typed error so RPC/network paths
        // never panic on ML-DSA transactions.
        let err = EthereumTxEnvelope::<TxEip4844Variant>::try_from(signed.clone()).unwrap_err();
        assert_eq!(err.to_string(), ML_DSA_NOT_AN_ETHEREUM_ENVELOPE);
        // The original transaction is returned in the error value.
        assert!(matches!(err.value().transaction, Transaction::MlDsa(_)));

        let err = EthereumTxEnvelope::<TxEip4844>::try_from(signed).unwrap_err();
        assert_eq!(err.to_string(), ML_DSA_NOT_AN_ETHEREUM_ENVELOPE);
        assert!(matches!(err.value().transaction, Transaction::MlDsa(_)));
    }

    #[test]
    fn ml_dsa_transaction_is_not_poolable() {
        let tx = Transaction::MlDsa(empty_ml_dsa_transaction());
        let signed = TransactionSigned::new(tx, Signature::test_signature(), B256::ZERO);

        // ML-DSA transactions must be rejected (not panic) when converted for tx-pool gossip.
        let err = PooledTransactionVariant::try_from(signed).unwrap_err();
        assert!(matches!(err.value().transaction, Transaction::MlDsa(_)));
    }

    #[test]
    fn ml_dsa_transaction_into_signed_canonicalizes_outer_signature() {
        let tx = Transaction::MlDsa(empty_ml_dsa_transaction());
        let signed = tx.into_signed(Signature::test_signature());
        let (_, signature, _) = signed.into_parts();

        assert_eq!(signature, ml_dsa_dummy_signature());
    }

    #[test]
    fn ml_dsa_outer_signature_is_canonicalized() {
        let tx = Transaction::MlDsa(empty_ml_dsa_transaction());
        let with_dummy = TransactionSigned::new_unhashed(tx.clone(), ml_dsa_dummy_signature());
        let with_nonzero = TransactionSigned::new_unhashed(tx, Signature::test_signature());

        assert_eq!(with_dummy.signature, ml_dsa_dummy_signature());
        assert_eq!(with_nonzero.signature, ml_dsa_dummy_signature());
        assert_eq!(with_dummy, with_nonzero);
        assert_eq!(with_dummy.tx_hash(), with_nonzero.tx_hash());

        let mut dummy_hash = DefaultHasher::new();
        Hash::hash(&with_dummy, &mut dummy_hash);
        let mut nonzero_hash = DefaultHasher::new();
        Hash::hash(&with_nonzero, &mut nonzero_hash);
        assert_eq!(dummy_hash.finish(), nonzero_hash.finish());
    }

    #[test]
    fn ml_dsa_network_roundtrip_ignores_nonzero_dummy_signature() {
        let tx = Transaction::MlDsa(empty_ml_dsa_transaction());
        let signed = TransactionSigned::new_unhashed(tx, Signature::test_signature());
        let mut encoded = Vec::new();
        signed.encode_2718(&mut encoded);

        let mut payload = &encoded[1..];
        let decoded = TransactionSigned::typed_decode(ML_DSA_TX_TYPE_ID, &mut payload)
            .expect("valid ML-DSA transaction should decode");

        assert!(payload.is_empty());
        assert_eq!(signed, decoded);
        assert_eq!(decoded.signature, ml_dsa_dummy_signature());
    }

    #[test]
    fn ml_dsa_compact_roundtrip_ignores_nonzero_dummy_signature() {
        let tx = Transaction::MlDsa(empty_ml_dsa_transaction());
        let signed = TransactionSigned::new_unhashed(tx, Signature::test_signature());
        let mut encoded = Vec::new();
        let len = signed.to_compact(&mut encoded);

        let (decoded, rest) = TransactionSigned::from_compact(&encoded, len);

        assert!(rest.is_empty());
        assert_eq!(signed, decoded);
        assert_eq!(decoded.signature, ml_dsa_dummy_signature());
    }

    #[test]
    fn ml_dsa_signer_recovery_requires_verified_path() {
        let tx = Transaction::MlDsa(empty_ml_dsa_transaction());
        let signed = TransactionSigned::new_unhashed(tx, Signature::test_signature());

        assert!(signed.recover_signer().is_err());
        assert!(signed.recover_signer_unchecked().is_err());
        assert!(signed.recover_unchecked_with_buf(&mut Vec::new()).is_err());
    }

    proptest! {
        #[test]
        fn test_roundtrip_compact_encode_envelope(reth_tx in arb::<TransactionSigned>()) {
            // MlDsa cannot be converted to EthereumTxEnvelope.
            proptest::prop_assume!(!matches!(reth_tx.transaction, Transaction::MlDsa(_)));

            let mut expected_buf = Vec::<u8>::new();
            let expected_len = reth_tx.to_compact(&mut expected_buf);

            let mut actual_but  = Vec::<u8>::new();
            let alloy_tx = EthereumTxEnvelope::<TxEip4844>::try_from(reth_tx).unwrap();
            let actual_len = alloy_tx.to_compact(&mut actual_but);

            assert_eq!(actual_but, expected_buf);
            assert_eq!(actual_len, expected_len);
        }

        #[test]
        fn test_roundtrip_compact_decode_envelope(reth_tx in arb::<TransactionSigned>()) {
            proptest::prop_assume!(!matches!(reth_tx.transaction, Transaction::MlDsa(_)));

            let mut buf = Vec::<u8>::new();
            let len = reth_tx.to_compact(&mut buf);

            let (actual_tx, _) = EthereumTxEnvelope::<TxEip4844>::from_compact(&buf, len);
            let expected_tx = EthereumTxEnvelope::<TxEip4844>::try_from(reth_tx).unwrap();

            assert_eq!(actual_tx, expected_tx);
        }

        #[test]
        fn test_roundtrip_compact_encode_envelope_zstd(mut reth_tx in arb::<TransactionSigned>()) {
            proptest::prop_assume!(!matches!(reth_tx.transaction, Transaction::MlDsa(_)));
               // zstd only kicks in if the input is large enough
            *reth_tx.transaction.input_mut() = vec![0;33].into();

            let mut expected_buf = Vec::<u8>::new();
            let expected_len = reth_tx.to_compact(&mut expected_buf);

            let mut actual_but  = Vec::<u8>::new();
            let alloy_tx = EthereumTxEnvelope::<TxEip4844>::try_from(reth_tx).unwrap();
            let actual_len = alloy_tx.to_compact(&mut actual_but);

            assert_eq!(actual_but, expected_buf);
            assert_eq!(actual_len, expected_len);
        }

        #[test]
        fn test_roundtrip_compact_decode_envelope_zstd(mut reth_tx in arb::<TransactionSigned>()) {
            proptest::prop_assume!(!matches!(reth_tx.transaction, Transaction::MlDsa(_)));
            // zstd only kicks in if the input is large enough
            *reth_tx.transaction.input_mut() = vec![0;33].into();

            let mut buf = Vec::<u8>::new();
            let len = reth_tx.to_compact(&mut buf);

            let (actual_tx, _) = EthereumTxEnvelope::<TxEip4844>::from_compact(&buf, len);
            let expected_tx = EthereumTxEnvelope::<TxEip4844>::try_from(reth_tx).unwrap();

            assert_eq!(actual_tx, expected_tx);
        }
    }
}
