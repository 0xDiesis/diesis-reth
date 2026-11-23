use alloy_primitives::BlockNumber;
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) fn raise_floor(floor: &AtomicU64, first_available: BlockNumber) {
    floor.store(first_available, Ordering::Relaxed);
}
