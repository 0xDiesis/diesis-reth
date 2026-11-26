use super::DatabaseProvider;
use crate::{DBProvider, StaticFileProviderFactory};
use alloy_primitives::{BlockNumber, TxNumber};
use reth_db_api::{cursor::DbCursorRO, models::StoredBlockBodyIndices, tables, transaction::DbTx};
use reth_node_types::NodeTypes;
use reth_storage_errors::provider::ProviderResult;
use std::ops::Range;

pub(super) fn transaction_block(
    tx: &impl DbTx,
    id: TxNumber,
) -> ProviderResult<Option<BlockNumber>> {
    Ok(tx.cursor_read::<tables::TransactionBlocks>()?.seek(id)?.map(|(_, block)| block))
}

impl<TX: DbTx + 'static, N: NodeTypes> DatabaseProvider<TX, N> {
    /// Reads body-index metadata without applying the public body-history floor.
    ///
    /// This is limited to internal in-memory range accounting, which needs the expired anchor's
    /// next transaction number without returning the anchor's body indices to a caller.
    pub(crate) fn block_body_indices_unchecked(
        &self,
        number: BlockNumber,
    ) -> ProviderResult<Option<StoredBlockBodyIndices>> {
        Ok(self.tx_ref().get::<tables::BlockBodyIndices>(number)?)
    }

    pub(super) fn ensure_body_history(&self, requested: BlockNumber) -> ProviderResult<()> {
        self.static_file_provider().ensure_history_available(requested)
    }

    pub(super) fn ensure_transaction_history(&self, id: TxNumber) -> ProviderResult<()> {
        let floor = self.static_file_provider().earliest_history_height();
        if floor > 0 &&
            let Some(block) = transaction_block(self.tx_ref(), id)?
        {
            self.ensure_body_history(block)?;
        }
        Ok(())
    }

    pub(super) fn transaction_history_is_expired(&self, id: TxNumber) -> ProviderResult<bool> {
        let floor = self.static_file_provider().earliest_history_height();
        if floor == 0 {
            return Ok(false)
        }
        Ok(transaction_block(self.tx_ref(), id)?.is_some_and(|block| block < floor))
    }

    pub(super) fn ensure_transaction_range(&self, range: &Range<TxNumber>) -> ProviderResult<()> {
        if let Some(id) = range.clone().next() {
            self.ensure_transaction_history(id)?;
        }
        Ok(())
    }
}
