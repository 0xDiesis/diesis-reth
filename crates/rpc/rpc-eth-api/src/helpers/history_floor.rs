use alloy_eips::{BlockId, BlockNumberOrTag};
use alloy_primitives::B256;
use reth_rpc_eth_types::EthApiError;
use reth_storage_api::{BlockIdReader, BlockNumReader};

pub(super) fn history_block_hash(
    provider: &impl BlockIdReader,
    id: BlockId,
) -> Result<Option<B256>, EthApiError> {
    let floor = provider.earliest_block_number()?;
    if let BlockId::Number(BlockNumberOrTag::Number(number)) = id {
        ensure_body_history(number, floor)?;
        return Ok(provider.block_hash_for_id(id)?)
    }

    let hash = provider.block_hash_for_id(id)?;
    if floor > 0 &&
        let Some(hash) = hash &&
        let Some(number) = provider.block_number(hash)?
    {
        ensure_body_history(number, floor)?;
    }
    Ok(hash)
}

pub(super) fn ensure_provider_body_history(
    provider: &impl BlockNumReader,
    number: u64,
) -> Result<(), EthApiError> {
    ensure_body_history(number, provider.earliest_block_number()?)
}

pub(super) const fn ensure_body_history(
    requested: u64,
    earliest_available: u64,
) -> Result<(), EthApiError> {
    if body_history_is_expired(requested, earliest_available) {
        return Err(EthApiError::PrunedHistoryUnavailable { requested, earliest_available })
    }
    Ok(())
}

pub(super) const fn body_history_is_expired(requested: u64, earliest_available: u64) -> bool {
    requested < earliest_available
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_history_guard_rejects_only_expired_blocks() {
        assert!(matches!(
            ensure_body_history(44, 45),
            Err(EthApiError::PrunedHistoryUnavailable { requested: 44, earliest_available: 45 })
        ));
        assert!(ensure_body_history(45, 45).is_ok());
        assert!(ensure_body_history(46, 45).is_ok());
    }
}
