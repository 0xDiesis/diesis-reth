use alloy_primitives::BlockNumber;
use reth_storage_errors::provider::{ProviderError, ProviderResult};
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) fn raise_floor(floor: &AtomicU64, first_available: BlockNumber) {
    floor.fetch_max(first_available, Ordering::Relaxed);
}

pub(super) fn ensure_available(
    requested: BlockNumber,
    earliest_available: BlockNumber,
) -> ProviderResult<()> {
    if requested < earliest_available {
        return Err(ProviderError::BlockExpired { requested, earliest_available })
    }
    Ok(())
}
