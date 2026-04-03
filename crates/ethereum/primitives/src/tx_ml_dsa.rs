//! ML-DSA (FIPS 204) post-quantum transaction type.
//!
//! This module defines [`TxMlDsa`], a custom transaction type (type byte `0x70`)
//! for transactions signed with ML-DSA instead of ECDSA. Key differences from
//! standard Ethereum transaction types:
//!
//! - ML-DSA cannot recover the public key from a signature, so `sender` is an explicit field in the
//!   transaction body.
//! - The ML-DSA signature lives inside the transaction struct (`ml_dsa_signature`), not in the
//!   outer `TransactionSigned::signature` field.
//! - The full public key is carried on the first transaction for registry, then omitted on
//!   subsequent transactions.

use alloy_consensus::{SignableTransaction, Signed, Transaction, Typed2718};
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{
    bytes::BufMut, keccak256, Address, Bytes, ChainId, Signature, TxHash, TxKind, B256, U256,
};
use alloy_rlp::{Decodable, Encodable, Header};
use core::mem;

/// Type identifier for ML-DSA post-quantum transactions.
pub const ML_DSA_TX_TYPE_ID: u8 = 0x70;

/// An ML-DSA (FIPS 204) post-quantum transaction.
///
/// Follows the EIP-1559 fee market model but uses ML-DSA signatures instead of
/// ECDSA. The sender address is explicit because ML-DSA does not support public
/// key recovery from signatures.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TxMlDsa {
    /// Chain ID for replay protection.
    pub chain_id: ChainId,
    /// Transaction nonce.
    pub nonce: u64,
    /// Maximum priority fee per gas (tip to the block producer).
    pub max_priority_fee_per_gas: u128,
    /// Maximum total fee per gas the sender is willing to pay.
    pub max_fee_per_gas: u128,
    /// Gas limit for this transaction.
    pub gas_limit: u64,
    /// Destination address (or create sentinel).
    pub to: TxKind,
    /// Value transferred in wei.
    pub value: U256,
    /// Calldata or init code.
    pub input: Bytes,
    /// EIP-2930 access list.
    pub access_list: AccessList,
    /// Explicit sender address (ML-DSA has no key recovery).
    pub sender: Address,
    /// ML-DSA security level: 44, 65, or 87.
    pub ml_dsa_level: u8,
    /// Full ML-DSA public key on first transaction, empty after registration.
    pub pubkey: Bytes,
    /// ML-DSA signature bytes.
    pub ml_dsa_signature: Bytes,
}

impl TxMlDsa {
    // -----------------------------------------------------------------------
    // RLP helpers – signing fields (the subset that gets hashed)
    // -----------------------------------------------------------------------

    /// RLP-encodes only the signing fields (no pubkey or `ml_dsa_signature`).
    ///
    /// Signing fields: `chain_id`, nonce, `max_priority_fee_per_gas`, `max_fee_per_gas`,
    /// `gas_limit`, to, value, input, `access_list`, sender, `ml_dsa_level`.
    pub fn rlp_encode_signing_fields(&self, out: &mut dyn BufMut) {
        self.chain_id.encode(out);
        self.nonce.encode(out);
        self.max_priority_fee_per_gas.encode(out);
        self.max_fee_per_gas.encode(out);
        self.gas_limit.encode(out);
        self.to.encode(out);
        self.value.encode(out);
        self.input.0.encode(out);
        self.access_list.encode(out);
        self.sender.encode(out);
        self.ml_dsa_level.encode(out);
    }

    /// Returns the RLP-encoded length of the signing fields (no RLP header).
    pub fn rlp_signing_fields_length(&self) -> usize {
        self.chain_id.length() +
            self.nonce.length() +
            self.max_priority_fee_per_gas.length() +
            self.max_fee_per_gas.length() +
            self.gas_limit.length() +
            self.to.length() +
            self.value.length() +
            self.input.0.length() +
            self.access_list.length() +
            self.sender.length() +
            self.ml_dsa_level.length()
    }

    // -----------------------------------------------------------------------
    // RLP helpers – all fields (signing fields + pubkey + ml_dsa_signature)
    // -----------------------------------------------------------------------

    /// Returns the RLP-encoded length of all fields (no RLP header).
    pub fn rlp_encoded_fields_length(&self) -> usize {
        self.rlp_signing_fields_length() + self.pubkey.0.length() + self.ml_dsa_signature.0.length()
    }

    /// RLP-encodes all fields (signing fields + pubkey + `ml_dsa_signature`).
    pub fn rlp_encode_fields(&self, out: &mut dyn BufMut) {
        self.rlp_encode_signing_fields(out);
        self.pubkey.0.encode(out);
        self.ml_dsa_signature.0.encode(out);
    }

    /// Decodes all fields from RLP bytes (assumes the RLP list header has
    /// already been consumed).
    pub fn rlp_decode_fields(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Ok(Self {
            chain_id: Decodable::decode(buf)?,
            nonce: Decodable::decode(buf)?,
            max_priority_fee_per_gas: Decodable::decode(buf)?,
            max_fee_per_gas: Decodable::decode(buf)?,
            gas_limit: Decodable::decode(buf)?,
            to: Decodable::decode(buf)?,
            value: Decodable::decode(buf)?,
            input: Decodable::decode(buf)?,
            access_list: Decodable::decode(buf)?,
            sender: Decodable::decode(buf)?,
            ml_dsa_level: Decodable::decode(buf)?,
            pubkey: Decodable::decode(buf)?,
            ml_dsa_signature: Decodable::decode(buf)?,
        })
    }

    // -----------------------------------------------------------------------
    // Signing hash
    // -----------------------------------------------------------------------

    /// Computes the signing hash: `keccak256(0x70 || rlp_list([signing_fields]))`.
    pub fn signature_hash(&self) -> B256 {
        let mut buf = alloc::vec::Vec::with_capacity(1 + self.rlp_signing_payload_length());
        buf.put_u8(ML_DSA_TX_TYPE_ID);
        let header = Header { list: true, payload_length: self.rlp_signing_fields_length() };
        header.encode(&mut buf);
        self.rlp_encode_signing_fields(&mut buf);
        keccak256(&buf)
    }

    // -----------------------------------------------------------------------
    // EIP-2718 encoding / decoding
    // -----------------------------------------------------------------------

    /// EIP-2718 encode: `0x70 || rlp_list([all_fields])`.
    pub fn eip2718_encode(&self, out: &mut dyn BufMut) {
        out.put_u8(ML_DSA_TX_TYPE_ID);
        let header = Header { list: true, payload_length: self.rlp_encoded_fields_length() };
        header.encode(out);
        self.rlp_encode_fields(out);
    }

    /// Returns the length of the EIP-2718 encoding.
    pub fn eip2718_encoded_length(&self) -> usize {
        let fields_len = self.rlp_encoded_fields_length();
        let header = Header { list: true, payload_length: fields_len };
        // 1 byte type + header + fields
        1 + header.length() + fields_len
    }

    /// Decodes from EIP-2718 body bytes (after the type byte has already been
    /// consumed).
    pub fn eip2718_decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining = buf.len();

        let tx = Self::rlp_decode_fields(buf)?;

        if buf.len() + header.payload_length != remaining {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }

        Ok(tx)
    }

    // -----------------------------------------------------------------------
    // Transaction hash
    // -----------------------------------------------------------------------

    /// Computes the transaction hash: `keccak256(eip2718_encoded)`.
    pub fn tx_hash(&self) -> TxHash {
        let mut buf = alloc::vec::Vec::with_capacity(self.eip2718_encoded_length());
        self.eip2718_encode(&mut buf);
        keccak256(&buf)
    }

    // -----------------------------------------------------------------------
    // Size estimation
    // -----------------------------------------------------------------------

    /// Returns a heuristic for the in-memory size of this transaction.
    pub fn size(&self) -> usize {
        mem::size_of::<Self>() +
            self.access_list.size() +
            self.input.len() +
            self.pubkey.len() +
            self.ml_dsa_signature.len()
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Length of the signing payload: header + signing fields.
    fn rlp_signing_payload_length(&self) -> usize {
        let fields_len = self.rlp_signing_fields_length();
        let header = Header { list: true, payload_length: fields_len };
        header.length() + fields_len
    }
}

// ---------------------------------------------------------------------------
// alloy_consensus::Transaction
// ---------------------------------------------------------------------------

impl Transaction for TxMlDsa {
    #[inline]
    fn chain_id(&self) -> Option<ChainId> {
        Some(self.chain_id)
    }

    #[inline]
    fn nonce(&self) -> u64 {
        self.nonce
    }

    #[inline]
    fn gas_limit(&self) -> u64 {
        self.gas_limit
    }

    #[inline]
    fn gas_price(&self) -> Option<u128> {
        None
    }

    #[inline]
    fn max_fee_per_gas(&self) -> u128 {
        self.max_fee_per_gas
    }

    #[inline]
    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        Some(self.max_priority_fee_per_gas)
    }

    #[inline]
    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        None
    }

    #[inline]
    fn priority_fee_or_price(&self) -> u128 {
        self.max_priority_fee_per_gas
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        alloy_eips::eip1559::calc_effective_gas_price(
            self.max_fee_per_gas,
            self.max_priority_fee_per_gas,
            base_fee,
        )
    }

    #[inline]
    fn is_dynamic_fee(&self) -> bool {
        true
    }

    #[inline]
    fn kind(&self) -> TxKind {
        self.to
    }

    #[inline]
    fn is_create(&self) -> bool {
        self.to.is_create()
    }

    #[inline]
    fn value(&self) -> U256 {
        self.value
    }

    #[inline]
    fn input(&self) -> &Bytes {
        &self.input
    }

    #[inline]
    fn access_list(&self) -> Option<&AccessList> {
        Some(&self.access_list)
    }

    #[inline]
    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        None
    }

    #[inline]
    fn authorization_list(&self) -> Option<&[alloy_eips::eip7702::SignedAuthorization]> {
        None
    }
}

// ---------------------------------------------------------------------------
// Typed2718
// ---------------------------------------------------------------------------

impl Typed2718 for TxMlDsa {
    fn ty(&self) -> u8 {
        ML_DSA_TX_TYPE_ID
    }
}

// ---------------------------------------------------------------------------
// SignableTransaction<Signature>
//
// The ECDSA `Signature` is a dummy for type-system compatibility — the real
// signature lives in `self.ml_dsa_signature`.
// ---------------------------------------------------------------------------

impl SignableTransaction<Signature> for TxMlDsa {
    fn set_chain_id(&mut self, chain_id: ChainId) {
        self.chain_id = chain_id;
    }

    fn encode_for_signing(&self, out: &mut dyn alloy_rlp::BufMut) {
        // 0x70 || rlp_list([signing_fields])
        out.put_u8(ML_DSA_TX_TYPE_ID);
        let header = Header { list: true, payload_length: self.rlp_signing_fields_length() };
        header.encode(out);
        self.rlp_encode_signing_fields(out);
    }

    fn payload_len_for_signature(&self) -> usize {
        // 1 byte type prefix + header + signing fields
        1 + self.rlp_signing_payload_length()
    }

    fn into_signed(self, signature: Signature) -> Signed<Self, Signature> {
        let hash = self.tx_hash();
        Signed::new_unchecked(self, signature, hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eips::eip2930::AccessList;
    use alloy_primitives::{Address, Bytes, TxKind, B256, U256};

    /// Helper to create a sample transaction for testing.
    fn sample_tx() -> TxMlDsa {
        TxMlDsa {
            chain_id: 1,
            nonce: 42,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 21_000,
            to: TxKind::Call(Address::with_last_byte(0x42)),
            value: U256::from(1_000_000_000_000_000_000u128),
            input: Bytes::from(vec![0xca, 0xfe]),
            access_list: AccessList::default(),
            sender: Address::with_last_byte(0x01),
            ml_dsa_level: 65,
            pubkey: Bytes::from(vec![0xaa; 32]),
            ml_dsa_signature: Bytes::from(vec![0xbb; 64]),
        }
    }

    #[test]
    fn tx_type_is_0x70() {
        assert_eq!(ML_DSA_TX_TYPE_ID, 0x70);
        let tx = sample_tx();
        assert_eq!(tx.ty(), 0x70);
    }

    #[test]
    fn signature_hash_deterministic() {
        let tx = sample_tx();
        let h1 = tx.signature_hash();
        let h2 = tx.signature_hash();
        assert_eq!(h1, h2, "Signature hash must be deterministic");
        assert_ne!(h1, B256::ZERO, "Signature hash must not be zero");
    }

    #[test]
    fn signature_hash_changes_with_nonce() {
        let mut tx1 = sample_tx();
        tx1.nonce = 1;
        let mut tx2 = sample_tx();
        tx2.nonce = 2;
        assert_ne!(
            tx1.signature_hash(),
            tx2.signature_hash(),
            "Different nonces must produce different signature hashes"
        );
    }

    #[test]
    fn eip2718_roundtrip() {
        let tx = sample_tx();

        // Encode
        let mut buf = alloc::vec::Vec::new();
        tx.eip2718_encode(&mut buf);

        // Consume the type byte
        let mut slice = &buf[..];
        assert_eq!(slice[0], ML_DSA_TX_TYPE_ID);
        slice = &slice[1..];

        // Decode
        let decoded = TxMlDsa::eip2718_decode(&mut slice).expect("decode should succeed");
        assert!(slice.is_empty(), "all bytes should be consumed");
        assert_eq!(decoded, tx, "roundtrip should produce identical transaction");
    }

    #[test]
    fn tx_hash_matches_keccak_of_encoded() {
        let tx = sample_tx();

        let hash = tx.tx_hash();

        let mut buf = alloc::vec::Vec::new();
        tx.eip2718_encode(&mut buf);
        let expected = keccak256(&buf);

        assert_eq!(hash, expected, "tx_hash must equal keccak256(eip2718_encoded)");
    }

    #[test]
    fn chain_id_required() {
        let tx = sample_tx();
        assert_eq!(Transaction::chain_id(&tx), Some(1), "chain_id() must return Some");
    }

    #[test]
    fn is_dynamic_fee() {
        let tx = sample_tx();
        assert!(
            Transaction::is_dynamic_fee(&tx),
            "ML-DSA transactions follow EIP-1559 and must be dynamic-fee"
        );
    }
}
