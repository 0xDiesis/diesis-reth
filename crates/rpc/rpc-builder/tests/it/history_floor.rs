use crate::utils::test_address;
use alloy_eips::BlockNumberOrTag;
use alloy_primitives::{B256, U64};
use futures::stream;
use jsonrpsee::{
    core::client::{ClientT, Error as ClientError},
    rpc_params, RpcModule,
};
use reth_chain_state::{ExecutedBlock, NewCanonicalChain};
use reth_consensus::noop::NoopConsensus;
use reth_ethereum_primitives::EthPrimitives;
use reth_evm_ethereum::EthEvmConfig;
use reth_network_api::noop::NoopNetwork;
use reth_provider::{
    providers::BlockchainProvider,
    test_utils::{blocks::BlockchainTestData, create_test_provider_factory, MockNodeTypesWithDB},
    BlockWriter, OriginalValuesKnown, ProviderFactory, StateWriter, StaticFileProviderFactory,
};
use reth_rpc::EthApi;
use reth_rpc_builder::{
    IpcServerBuilder, RethRpcModule, RpcModuleBuilder, RpcServerConfig, RpcServerHandle,
    TransportRpcModuleConfig, TransportRpcModules,
};
use reth_rpc_eth_api::EthApiServer;
use reth_rpc_eth_types::{
    cache::cache_new_blocks_task, EthApiError, EthStateCache, EthStateCacheConfig,
};
use reth_storage_api::StateWriteConfig;
use reth_tasks::Runtime;
use reth_tokio_util::EventSender;
use reth_transaction_pool::test_utils::{TestPool, TestPoolBuilder};
use serde_json::Value;
use std::sync::Arc;

type TestFactory = ProviderFactory<MockNodeTypesWithDB>;
type TestProvider = BlockchainProvider<MockNodeTypesWithDB>;
type TestRpcBuilder = RpcModuleBuilder<
    EthPrimitives,
    TestProvider,
    TestPool,
    NoopNetwork,
    EthEvmConfig,
    NoopConsensus,
>;

async fn assert_history_responses(client: &impl ClientT) {
    let error = client.request::<u64, _>("expired_history", rpc_params![]).await.unwrap_err();
    match error {
        ClientError::Call(error) => assert_eq!(error.code(), 4444),
        other => panic!("expected history-floor call error, got {other:?}"),
    }

    assert_eq!(client.request::<u64, _>("available_history", rpc_params![]).await.unwrap(), 7);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn history_floor_error_is_identical_over_http_ws_and_ipc() {
    let mut module = RpcModule::new(());
    module
        .register_method("expired_history", |_, _, _| {
            Err::<u64, _>(EthApiError::PrunedHistoryUnavailable.into_rpc_err())
        })
        .unwrap();
    module.register_method("available_history", |_, _, _| 7_u64).unwrap();

    let modules = TransportRpcModules::default()
        .with_http(module.clone())
        .with_ws(module.clone())
        .with_ipc(module);
    let ipc_dir = tempfile::tempdir().unwrap();
    let ipc_endpoint = ipc_dir.path().join("history-floor.ipc").display().to_string();
    let handle = RpcServerConfig::http(Default::default())
        .with_http_address(test_address())
        .with_ws(Default::default())
        .with_ws_address(test_address())
        .with_ipc(IpcServerBuilder::default())
        .with_ipc_endpoint(ipc_endpoint)
        .start(&modules)
        .await
        .unwrap();

    let http = handle.http_client().unwrap();
    let ws = handle.ws_client().await.unwrap();
    let ipc = handle.ipc_client().await.unwrap();
    assert_history_responses(&http).await;
    assert_history_responses(&ws).await;
    assert_history_responses(&ipc).await;

    handle.stop().unwrap();
}

fn provider_with_blocks(block_count: usize) -> (TestFactory, TestProvider, BlockchainTestData) {
    let data = BlockchainTestData::default();
    let factory = create_test_provider_factory();
    let provider = factory.provider_rw().unwrap();
    provider
        .insert_block(&data.genesis.clone().try_recover().expect("genesis has valid senders"))
        .unwrap();
    for (block, outcome) in data.blocks.iter().take(block_count) {
        provider.insert_block(block).unwrap();
        provider
            .write_state(outcome, OriginalValuesKnown::No, StateWriteConfig::default())
            .unwrap();
    }
    provider.commit().unwrap();
    let blockchain = BlockchainProvider::new(factory.clone()).unwrap();
    (factory, blockchain, data)
}

fn rpc_builder(provider: TestProvider, executor: Runtime) -> TestRpcBuilder {
    RpcModuleBuilder::default()
        .with_provider(provider)
        .with_pool(TestPoolBuilder::default().into())
        .with_network(NoopNetwork::default())
        .with_executor(executor)
        .with_evm_config(EthEvmConfig::mainnet())
        .with_consensus(NoopConsensus::default())
}

async fn launch_provider_history_server() -> (RpcServerHandle, tempfile::TempDir, B256, B256) {
    let (factory, provider, data) = provider_with_blocks(0);
    factory.static_file_provider().raise_history_floor(2);

    let executor = Runtime::test();
    let cache = EthStateCache::spawn_with(
        provider.clone(),
        EthStateCacheConfig::default(),
        executor.clone(),
    );
    let builder = rpc_builder(provider, executor);
    let eth_api = builder.eth_api_builder().eth_cache(cache.clone()).build();

    let cached = data
        .blocks
        .iter()
        .take(2)
        .map(|(block, _)| ExecutedBlock {
            recovered_block: Arc::new(block.clone()),
            ..Default::default()
        })
        .collect();
    let notification = NewCanonicalChain::Commit { new: cached }.to_chain_notification();
    cache_new_blocks_task(cache, stream::iter([notification])).await;

    let modules = builder.build(
        TransportRpcModuleConfig::default()
            .with_http([RethRpcModule::Eth])
            .with_ws([RethRpcModule::Eth])
            .with_ipc([RethRpcModule::Eth]),
        eth_api,
        EventSender::new(1),
    );
    let ipc_dir = tempfile::tempdir().unwrap();
    let ipc_endpoint = ipc_dir.path().join("provider-history-floor.ipc").display().to_string();
    let handle = RpcServerConfig::http(Default::default())
        .with_http_address(test_address())
        .with_ws(Default::default())
        .with_ws_address(test_address())
        .with_ipc(IpcServerBuilder::default())
        .with_ipc_endpoint(ipc_endpoint)
        .start(&modules)
        .await
        .unwrap();

    (handle, ipc_dir, data.blocks[0].0.hash(), data.blocks[1].0.hash())
}

async fn assert_cached_history_available(client: &impl ClientT, hash: B256) {
    let block: Value =
        client.request("eth_getBlockByHash", rpc_params![hash, false]).await.unwrap();
    assert!(!block.is_null());

    let receipts: Value = client.request("eth_getBlockReceipts", rpc_params![hash]).await.unwrap();
    assert!(!receipts.is_null());

    let transaction: Value = client
        .request("eth_getTransactionByBlockHashAndIndex", rpc_params![hash, "0x0"])
        .await
        .unwrap();
    assert!(!transaction.is_null());
}

fn assert_pruned_history_error(error: ClientError) {
    match error {
        ClientError::Call(error) => assert_eq!(error.code(), 4444),
        other => panic!("expected history-floor call error, got {other:?}"),
    }
}

async fn assert_cached_block_expired(client: &impl ClientT, hash: B256) {
    let error = client
        .request::<Value, _>("eth_getBlockByHash", rpc_params![hash, false])
        .await
        .unwrap_err();
    assert_pruned_history_error(error);
}

async fn assert_cached_receipts_expired(client: &impl ClientT, hash: B256) {
    let error =
        client.request::<Value, _>("eth_getBlockReceipts", rpc_params![hash]).await.unwrap_err();
    assert_pruned_history_error(error);
}

async fn assert_cached_transaction_expired(client: &impl ClientT, hash: B256) {
    let error = client
        .request::<Value, _>("eth_getTransactionByBlockHashAndIndex", rpc_params![hash, "0x0"])
        .await
        .unwrap_err();
    assert_pruned_history_error(error);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn provider_backed_cached_history_keeps_the_floor_boundary_over_every_transport() {
    let (handle, _ipc_dir, _, available_hash) = launch_provider_history_server().await;
    let http = handle.http_client().unwrap();
    let ws = handle.ws_client().await.unwrap();
    let ipc = handle.ipc_client().await.unwrap();
    assert_cached_history_available(&http, available_hash).await;
    assert_cached_history_available(&ws, available_hash).await;
    assert_cached_history_available(&ipc, available_hash).await;
    handle.stop().unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn provider_backed_stale_cached_block_returns_4444_over_http() {
    let (handle, _ipc_dir, expired_hash, _) = launch_provider_history_server().await;
    let http = handle.http_client().unwrap();
    assert_cached_block_expired(&http, expired_hash).await;
    handle.stop().unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn provider_backed_stale_cached_receipts_return_4444_over_http() {
    let (handle, _ipc_dir, expired_hash, _) = launch_provider_history_server().await;
    let http = handle.http_client().unwrap();
    assert_cached_receipts_expired(&http, expired_hash).await;
    handle.stop().unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn provider_backed_stale_cached_transaction_returns_4444_over_http() {
    let (handle, _ipc_dir, expired_hash, _) = launch_provider_history_server().await;
    let http = handle.http_client().unwrap();
    assert_cached_transaction_expired(&http, expired_hash).await;
    handle.stop().unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn provider_backed_stale_cached_block_returns_4444_over_ws() {
    let (handle, _ipc_dir, expired_hash, _) = launch_provider_history_server().await;
    let ws = handle.ws_client().await.unwrap();
    assert_cached_block_expired(&ws, expired_hash).await;
    handle.stop().unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn provider_backed_stale_cached_block_returns_4444_over_ipc() {
    let (handle, _ipc_dir, expired_hash, _) = launch_provider_history_server().await;
    let ipc = handle.ipc_client().await.unwrap();
    assert_cached_block_expired(&ipc, expired_hash).await;
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn provider_backed_fee_history_checks_the_floor_before_its_cache() {
    let (factory, provider, data) = provider_with_blocks(0);
    let eth_api = rpc_builder(provider.clone(), Runtime::test()).bootstrap_eth_api();
    provider.canonical_in_memory_state().update_chain(NewCanonicalChain::Commit {
        new: data
            .blocks
            .iter()
            .take(2)
            .map(|(block, _)| ExecutedBlock {
                recovered_block: Arc::new(block.clone()),
                ..Default::default()
            })
            .collect(),
    });
    for _ in 0..1_000 {
        if eth_api.fee_history_cache().upper_bound() == 2 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(eth_api.fee_history_cache().upper_bound(), 2);
    assert!(eth_api.fee_history_cache().get_history(1, 1).await.is_some());
    factory.static_file_provider().raise_history_floor(2);

    let error = <EthApi<_, _> as EthApiServer<_, _, _, _, _, _>>::fee_history(
        &eth_api,
        U64::from(1),
        BlockNumberOrTag::Number(1),
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), 4444);

    <EthApi<_, _> as EthApiServer<_, _, _, _, _, _>>::fee_history(
        &eth_api,
        U64::from(1),
        BlockNumberOrTag::Number(2),
        None,
    )
    .await
    .unwrap();
}
