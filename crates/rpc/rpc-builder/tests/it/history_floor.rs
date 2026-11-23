use crate::utils::test_address;
use jsonrpsee::{
    core::client::{ClientT, Error as ClientError},
    rpc_params, RpcModule,
};
use reth_rpc_builder::{IpcServerBuilder, RpcServerConfig, TransportRpcModules};
use reth_rpc_eth_types::EthApiError;

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
