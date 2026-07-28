//! L1 `eth` API types.

use alloy_network::Ethereum;
use reth_evm_ethereum::EthEvmConfig;
use reth_rpc_convert::RpcConverter;
use reth_rpc_eth_types::receipt::EthReceiptConverter;

/// An [`RpcConverter`] with its generics set to Ethereum specific.
pub type EthRpcConverter<ChainSpec> =
    RpcConverter<Ethereum, EthEvmConfig, EthReceiptConverter<ChainSpec>>;

//tests for simulate
#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Transaction, TxType};
    use alloy_rpc_types_eth::TransactionRequest;
    use reth_chainspec::MAINNET;
    use reth_rpc_eth_types::simulate::resolve_transaction;
    use revm::database::CacheDB;

    #[test]
    fn test_fill_ml_dsa_tx_returns_error_instead_of_panicking() {
        use alloy_consensus::transaction::Recovered;
        use alloy_eips::eip2930::AccessList;
        use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
        use reth_ethereum_primitives::{tx_ml_dsa::TxMlDsa, TransactionSigned};
        use reth_rpc_convert::RpcConvert;
        use reth_rpc_eth_types::EthApiError;

        let converter = EthRpcConverter::new(EthReceiptConverter::new(MAINNET.clone()));

        let tx = TransactionSigned::new(
            reth_ethereum_primitives::Transaction::MlDsa(TxMlDsa {
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
                ml_dsa_signature: Bytes::new(),
            }),
            Signature::test_signature(),
            B256::ZERO,
        );

        // Serving an ML-DSA tx through the RPC response conversion (e.g.
        // `eth_getTransactionByHash`) must yield a typed error, never panic.
        let result =
            converter.fill(Recovered::new_unchecked(tx, Address::ZERO), Default::default());
        assert!(matches!(result, Err(EthApiError::Unsupported(_))), "{result:?}");
    }

    #[test]
    fn test_resolve_transaction_empty_request() {
        let builder = EthRpcConverter::new(EthReceiptConverter::new(MAINNET.clone()));
        let mut db = CacheDB::<reth_revm::db::EmptyDBTyped<reth_errors::ProviderError>>::default();
        let tx = TransactionRequest::default();
        let result = resolve_transaction(tx, 21000, 0, 1, false, &mut db, &builder).unwrap();

        // For an empty request, we should get a valid transaction with defaults
        let tx = result.into_inner();
        assert_eq!(tx.max_fee_per_gas(), 0);
        assert_eq!(tx.max_priority_fee_per_gas(), Some(0));
        assert_eq!(tx.gas_price(), None);
    }

    #[test]
    fn test_resolve_transaction_legacy() {
        let mut db = CacheDB::<reth_revm::db::EmptyDBTyped<reth_errors::ProviderError>>::default();
        let builder = EthRpcConverter::new(EthReceiptConverter::new(MAINNET.clone()));

        let tx = TransactionRequest { gas_price: Some(100), ..Default::default() };

        let tx = resolve_transaction(tx, 21000, 0, 1, false, &mut db, &builder).unwrap();

        // The fork's transaction type is `DiesisTxType`, a superset of the Ethereum `TxType`.
        assert_eq!(tx.tx_type(), TxType::Legacy.into());

        let tx = tx.into_inner();
        assert_eq!(tx.gas_price(), Some(100));
        assert_eq!(tx.max_priority_fee_per_gas(), None);
    }

    #[test]
    fn test_resolve_transaction_partial_eip1559() {
        let mut db = CacheDB::<reth_revm::db::EmptyDBTyped<reth_errors::ProviderError>>::default();
        let rpc_converter = EthRpcConverter::new(EthReceiptConverter::new(MAINNET.clone()));

        let tx = TransactionRequest {
            max_fee_per_gas: Some(200),
            max_priority_fee_per_gas: Some(10),
            ..Default::default()
        };

        let result = resolve_transaction(tx, 21000, 0, 1, false, &mut db, &rpc_converter).unwrap();

        assert_eq!(result.tx_type(), TxType::Eip1559.into());
        let tx = result.into_inner();
        assert_eq!(tx.max_fee_per_gas(), 200);
        assert_eq!(tx.max_priority_fee_per_gas(), Some(10));
        assert_eq!(tx.gas_price(), None);
    }

    #[test]
    fn test_resolve_transaction_wraps_max_nonce_when_nonce_check_disabled() {
        let mut db = CacheDB::<reth_revm::db::EmptyDBTyped<reth_errors::ProviderError>>::default();
        let rpc_converter = EthRpcConverter::new(EthReceiptConverter::new(MAINNET.clone()));

        let tx = TransactionRequest { nonce: Some(u64::MAX), ..Default::default() };

        let result = resolve_transaction(tx, 21000, 0, 1, true, &mut db, &rpc_converter).unwrap();

        assert_eq!(result.nonce(), 0);
    }
}
