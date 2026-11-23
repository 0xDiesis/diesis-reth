use reth_rpc_eth_types::EthApiError;

pub(super) fn ensure_body_history(
    _requested: u64,
    _earliest_available: u64,
) -> Result<(), EthApiError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_history_guard_rejects_only_expired_blocks() {
        assert!(matches!(
            ensure_body_history(44, 45),
            Err(EthApiError::PrunedHistoryUnavailable)
        ));
        assert!(ensure_body_history(45, 45).is_ok());
        assert!(ensure_body_history(46, 45).is_ok());
    }
}
