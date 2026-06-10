//! RPC receipt response builder, extends a layer one receipt with layer two data.

use crate::EthApiError;
use alloy_consensus::{ReceiptEnvelope, Transaction, TxReceipt};
use alloy_eips::eip7840::BlobParams;
use alloy_primitives::{Address, TxKind};
use alloy_rpc_types_eth::{Log, TransactionReceipt};
use reth_chainspec::EthChainSpec;
use reth_ethereum_primitives::{DiesisTxType, Receipt};
use reth_primitives_traits::{NodePrimitives, TransactionMeta};
use reth_rpc_convert::transaction::{ConvertReceiptInput, ReceiptConverter};
use std::sync::Arc;

/// Builds an [`TransactionReceipt`] obtaining the inner receipt envelope from the given closure.
///
/// The closure is fallible so chain-specific receipt types without an
/// Ethereum envelope representation (e.g. Diesis ML-DSA `0x70` receipts) can
/// surface a typed RPC error instead of panicking on data that legitimately
/// appears in canonical blocks.
pub fn build_receipt<N, E>(
    input: ConvertReceiptInput<'_, N>,
    blob_params: Option<BlobParams>,
    build_rpc_receipt: impl FnOnce(N::Receipt, usize, TransactionMeta) -> Result<E, EthApiError>,
) -> Result<TransactionReceipt<E>, EthApiError>
where
    N: NodePrimitives,
{
    let ConvertReceiptInput { tx, meta, receipt, gas_used, next_log_index } = input;
    let from = tx.signer();

    let blob_gas_used = tx.blob_gas_used();
    // Blob gas price should only be present if the transaction is a blob transaction
    let blob_gas_price =
        blob_gas_used.and_then(|_| Some(blob_params?.calc_blob_fee(meta.excess_blob_gas?)));

    let (contract_address, to) = match tx.kind() {
        TxKind::Create => (Some(from.create(tx.nonce())), None),
        TxKind::Call(addr) => (None, Some(Address(*addr))),
    };

    Ok(TransactionReceipt {
        inner: build_rpc_receipt(receipt, next_log_index, meta)?,
        transaction_hash: meta.tx_hash,
        transaction_index: Some(meta.index),
        block_hash: Some(meta.block_hash),
        block_number: Some(meta.block_number),
        from,
        to,
        gas_used,
        contract_address,
        effective_gas_price: tx.effective_gas_price(meta.base_fee),
        // EIP-4844 fields
        blob_gas_price,
        blob_gas_used,
    })
}

/// Converter for Ethereum receipts.
#[derive(derive_more::Debug)]
pub struct EthReceiptConverter<
    ChainSpec,
    Builder = fn(Receipt, usize, TransactionMeta) -> Result<ReceiptEnvelope<Log>, EthApiError>,
> {
    chain_spec: Arc<ChainSpec>,
    #[debug(skip)]
    build_rpc_receipt: Builder,
}

impl<ChainSpec, Builder> Clone for EthReceiptConverter<ChainSpec, Builder>
where
    Builder: Clone,
{
    fn clone(&self) -> Self {
        Self {
            chain_spec: self.chain_spec.clone(),
            build_rpc_receipt: self.build_rpc_receipt.clone(),
        }
    }
}

impl<ChainSpec> EthReceiptConverter<ChainSpec> {
    /// Creates a new converter with the given chain spec.
    pub const fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self {
            chain_spec,
            build_rpc_receipt: |receipt: Receipt, next_log_index, meta: TransactionMeta| {
                let mut log_index = next_log_index;
                let tx_type = receipt.tx_type;
                let receipt = receipt
                    .map_logs(|log| {
                        let idx = log_index;
                        log_index += 1;
                        Log {
                            inner: log,
                            block_hash: Some(meta.block_hash),
                            block_number: Some(meta.block_number),
                            block_timestamp: Some(meta.timestamp),
                            transaction_hash: Some(meta.tx_hash),
                            transaction_index: Some(meta.index),
                            log_index: Some(idx as u64),
                            removed: false,
                        }
                    })
                    .into_with_bloom()
                    .map_receipt(Into::into);

                match tx_type {
                    DiesisTxType::Legacy => Ok(ReceiptEnvelope::Legacy(receipt)),
                    DiesisTxType::Eip2930 => Ok(ReceiptEnvelope::Eip2930(receipt)),
                    DiesisTxType::Eip1559 => Ok(ReceiptEnvelope::Eip1559(receipt)),
                    DiesisTxType::Eip4844 => Ok(ReceiptEnvelope::Eip4844(receipt)),
                    DiesisTxType::Eip7702 => Ok(ReceiptEnvelope::Eip7702(receipt)),
                    // ML-DSA receipts have no Ethereum envelope representation;
                    // return a typed error instead of panicking — a panic here
                    // is remotely triggerable by querying the receipt of any
                    // 0x70 transaction included in a canonical block.
                    DiesisTxType::MlDsa => Err(EthApiError::Unsupported(
                        "MlDsa receipts cannot be converted to Ethereum receipt envelopes",
                    )),
                }
            },
        }
    }

    /// Sets new builder for the converter.
    pub fn with_builder<Builder>(
        self,
        build_rpc_receipt: Builder,
    ) -> EthReceiptConverter<ChainSpec, Builder> {
        EthReceiptConverter { chain_spec: self.chain_spec, build_rpc_receipt }
    }
}

impl<N, ChainSpec, Builder, Rpc> ReceiptConverter<N> for EthReceiptConverter<ChainSpec, Builder>
where
    N: NodePrimitives,
    ChainSpec: EthChainSpec + 'static,
    Builder: Fn(N::Receipt, usize, TransactionMeta) -> Result<Rpc, EthApiError> + 'static,
{
    type RpcReceipt = TransactionReceipt<Rpc>;
    type Error = EthApiError;

    fn convert_receipts(
        &self,
        inputs: Vec<ConvertReceiptInput<'_, N>>,
    ) -> Result<Vec<Self::RpcReceipt>, Self::Error> {
        let mut receipts = Vec::with_capacity(inputs.len());

        for input in inputs {
            let blob_params = self.chain_spec.blob_params_at_timestamp(input.meta.timestamp);
            receipts.push(build_receipt(input, blob_params, &self.build_rpc_receipt)?);
        }

        Ok(receipts)
    }
}
