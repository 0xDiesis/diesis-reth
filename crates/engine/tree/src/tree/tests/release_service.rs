//! Joined tree-actor, database, persistence-writer and release-journal tests.

use super::*;
use crate::writer_fence::{
    AbortableRelease, LocalReleaseRecovery, ReleaseBinding, ReleaseFenceReceipt,
    ReleaseRecoveryPhase, ReleaseRecoveryQuery, ReleaseRecoverySource, WriterFenceBootstrap,
    WriterFenceStartup,
};
use reth_provider::BlockNumReader;
use std::path::PathBuf;

use super::super::release_harness::JoinedHarness;

#[tokio::test]
async fn joined_root_constructor_reopens_the_persisted_head_without_requeueing() {
    let root = tempfile::tempdir().unwrap();
    let genesis = reth_chain_state::test_utils::TestBlockBuilder::eth()
        .get_executed_blocks(0..1)
        .next()
        .unwrap();
    let harness = JoinedHarness::from_persisted_genesis_at(
        root.path(),
        reth_chainspec::MAINNET.clone(),
        genesis,
    );
    let expected = harness.expected();
    let journal = harness.journal_path().to_path_buf();
    let restart = harness.shutdown_actor();
    drop(restart);

    let bootstrap = WriterFenceBootstrap::acquire(journal).unwrap();
    let reopened = JoinedHarness::reopen_root(
        root.path(),
        reth_chainspec::MAINNET.clone(),
        expected,
        bootstrap,
    );
    assert_eq!(reopened.expected(), expected);
    reopened.assert_exact_database_head();
}

#[tokio::test]
async fn joined_release_drains_real_service_arms_and_completes_exact_operation() {
    let mut harness = JoinedHarness::new();
    let release = harness.acquire().await;
    harness.assert_writer_closed();
    harness.assert_journal(1);
    let operation = harness.operation();
    assert!(harness
        .persistence
        .release_release_fence(operation + 1)
        .recv_timeout(Duration::from_secs(10))
        .unwrap()
        .is_err());
    harness.assert_writer_closed();
    harness.assert_journal(1);

    let arm = tokio::spawn(async move { release.arm_commit().await });
    let armed = harness.drive(arm).await.unwrap();
    assert_eq!(armed.binding(), harness.release_binding);
    harness.assert_writer_closed();
    harness.assert_journal(2);
    let committed = armed.receipt();
    let complete = tokio::spawn(async move { armed.complete(committed).await });
    harness.drive(complete).await.unwrap();
    assert!(matches!(harness.tree.writer_fence.phase(), WriterFencePhase::Idle));
    harness.assert_journal(0);
    harness.assert_exact_database_head();

    // Successful matching completion reopened the actual database writer.
    let (tx, rx) = crossbeam_channel::bounded(1);
    harness.persistence.clone().remove_blocks_above(0, tx).unwrap();
    assert_eq!(rx.recv_timeout(Duration::from_secs(10)).unwrap().last_block.unwrap().number, 0);
    assert_eq!(harness.factory.provider().unwrap().best_block_number().unwrap(), 0);
    harness.assert_clean_restart();
}

#[tokio::test]
async fn joined_same_head_different_plan_receipt_keeps_the_real_writer_fenced() {
    let mut harness = JoinedHarness::new();
    let release = harness.acquire().await;
    let arm = tokio::spawn(async move { release.arm_commit().await });
    let armed = harness.drive(arm).await.unwrap();
    let mut encoded = armed.receipt().encode();
    encoded[96] ^= 1;
    let checksum = alloy_primitives::keccak256(&encoded[..ReleaseFenceReceipt::ENCODED_LEN - 32]);
    encoded[ReleaseFenceReceipt::ENCODED_LEN - 32..].copy_from_slice(checksum.as_slice());
    let wrong_plan = ReleaseFenceReceipt::decode(&encoded).unwrap();

    let exact = armed.receipt();
    let complete = tokio::spawn(async move { armed.complete(wrong_plan).await });
    assert_eq!(harness.drive(complete).await, Err(WriterFenceError::StaleCapability));
    // A refused pre-check neither resolves nor poisons the armed release: the actor stays
    // armed, the writer stays closed and the Armed journal record is unchanged.
    assert!(matches!(
        harness.tree.writer_fence.phase(),
        WriterFencePhase::ReleaseCommitArmed { .. }
    ));
    harness.assert_writer_closed();
    harness.assert_journal(2);
    harness.assert_restart_reconciles_only_exact_commit(exact, wrong_plan);
}

struct FixedRecoverySource {
    expected: ReleaseRecoveryQuery,
    observation: LocalReleaseRecovery,
    inspected: usize,
}

impl ReleaseRecoverySource for FixedRecoverySource {
    type Error = String;

    fn inspect(
        &mut self,
        query: ReleaseRecoveryQuery,
    ) -> Result<LocalReleaseRecovery, Self::Error> {
        self.inspected += 1;
        if query != self.expected {
            return Err(format!("unexpected recovery query {query:?}"));
        }
        Ok(self.observation.clone())
    }
}

impl JoinedHarness {
    /// Restart through the real pre-writer bootstrap: the Armed journal is pending, a
    /// same-head different-plan committed record is refused and preserves Armed, and only
    /// the exact prior receipt bytes reconcile to Clean.
    fn assert_restart_reconciles_only_exact_commit(
        self,
        exact: ReleaseFenceReceipt,
        wrong_plan: ReleaseFenceReceipt,
    ) {
        let Self { tree, persistence, factory, journal, release_binding, .. } = self;
        drop(tree);
        drop(persistence);
        let pending = |journal: PathBuf| match WriterFenceBootstrap::inspect(journal).unwrap() {
            WriterFenceStartup::Pending(recovery) => recovery,
            WriterFenceStartup::Ready(_) => panic!("armed journal must require recovery"),
        };
        let recovery = pending(journal.clone());
        let query = recovery.query();
        assert_eq!(query.phase(), ReleaseRecoveryPhase::Armed);
        assert_eq!(query.binding(), release_binding);
        assert_eq!(query.record_key(), exact.record_key());
        assert_ne!(query.record_key(), wrong_plan.record_key());

        let mut mismatched = FixedRecoverySource {
            expected: query,
            observation: LocalReleaseRecovery::Committed(wrong_plan.encode().to_vec()),
            inspected: 0,
        };
        assert!(matches!(
            recovery.reconcile(&mut mismatched),
            Err(WriterFenceError::RecoveryEvidence { .. })
        ));
        assert_eq!(mismatched.inspected, 1);
        let recovery = pending(journal.clone());
        assert_eq!(recovery.query(), query);

        let mut absent = FixedRecoverySource {
            expected: query,
            observation: LocalReleaseRecovery::Absent,
            inspected: 0,
        };
        assert!(matches!(
            recovery.reconcile(&mut absent),
            Err(WriterFenceError::RecoveryEvidence { .. })
        ));
        let recovery = pending(journal.clone());

        let mut committed = FixedRecoverySource {
            expected: query,
            observation: LocalReleaseRecovery::Committed(exact.encode().to_vec()),
            inspected: 0,
        };
        let bootstrap = recovery.reconcile(&mut committed).unwrap();
        assert_eq!(committed.inspected, 1);
        drop(bootstrap);
        drop(WriterFenceBootstrap::acquire(journal.clone()).unwrap());
        drop(factory);
    }
}

#[tokio::test]
async fn joined_exact_abandonment_reopens_the_real_writer_after_a_tombstone() {
    let mut harness = JoinedHarness::new();
    let release = harness.acquire().await;
    let arm = tokio::spawn(async move { release.arm_commit().await });
    let armed = harness.drive(arm).await.unwrap();
    harness.assert_writer_closed();
    harness.assert_journal(2);

    // The production caller supplies these bytes only after its authoritative local store has
    // durably committed an irrevocable abandonment tombstone and synced the parent directory.
    let abandoned = ReleaseFenceReceipt::decode(&armed.receipt().encode()).unwrap();
    let abandon = tokio::spawn(async move { armed.abandon(abandoned).await });
    harness.drive(abandon).await.unwrap();
    assert!(matches!(harness.tree.writer_fence.phase(), WriterFencePhase::Idle));
    harness.assert_journal(0);

    let (tx, rx) = crossbeam_channel::bounded(1);
    harness.persistence.clone().remove_blocks_above(0, tx).unwrap();
    assert_eq!(rx.recv_timeout(Duration::from_secs(10)).unwrap().last_block.unwrap().number, 0);
    harness.assert_clean_restart();
}

#[tokio::test]
async fn joined_cancelled_arm_ack_keeps_database_writer_and_restart_fenced() {
    let mut harness = JoinedHarness::new();
    let release = harness.acquire().await;
    let arm = tokio::spawn(async move { release.arm_commit().await });
    tokio::task::yield_now().await;
    let request = harness.tree.writer_fence_incoming.recv_timeout(Duration::from_secs(10)).unwrap();
    // The genuine Arm request reached the actor queue, but its caller is cancelled before
    // the actor replies. The actor must still persist Armed and retain writer ownership.
    arm.abort();
    assert!(arm.await.unwrap_err().is_cancelled());
    harness.tree.on_writer_fence_request(request).expect("cancelled Arm request is non-fatal");
    assert!(matches!(
        harness.tree.writer_fence.phase(),
        WriterFencePhase::ReleaseCommitArmed { .. }
    ));
    harness.assert_writer_closed();
    harness.assert_journal(2);
    harness.assert_restart_refused();
}

#[tokio::test]
async fn joined_dropped_armed_token_has_no_unfence_side_effect() {
    let mut harness = JoinedHarness::new();
    let release = harness.acquire().await;
    let arm = tokio::spawn(async move { release.arm_commit().await });
    let armed = harness.drive(arm).await.unwrap();
    let journal_before = std::fs::read(&harness.journal).unwrap();
    drop(armed);
    assert!(matches!(
        harness.tree.writer_fence_incoming.try_recv(),
        Err(crossbeam_channel::TryRecvError::Empty)
    ));
    harness.assert_writer_closed();
    harness.assert_journal(2);
    assert_eq!(std::fs::read(&harness.journal).unwrap(), journal_before);
    harness.assert_restart_refused();
}

#[tokio::test]
async fn joined_missing_armed_journal_prevents_completion_and_keeps_writer_closed() {
    let mut harness = JoinedHarness::new();
    let release = harness.acquire().await;
    let arm = tokio::spawn(async move { release.arm_commit().await });
    let armed = harness.drive(arm).await.unwrap();
    harness.assert_journal(2);
    harness.assert_writer_closed();

    // Losing the current durable record must not let terminal publication recreate it and
    // unfreeze the service. This removes only this fixture's owned temporary journal.
    std::fs::remove_file(&harness.journal).unwrap();
    let committed = armed.receipt();
    let complete = tokio::spawn(async move { armed.complete(committed).await });
    assert!(matches!(harness.drive(complete).await, Err(WriterFenceError::Journal { .. })));
    assert!(matches!(harness.tree.writer_fence.phase(), WriterFencePhase::Faulted));
    harness.assert_writer_closed();
    assert!(!harness.journal.exists(), "completion must not recreate a missing Armed record");

    // After the real writer thread joins and the actor releases its lock, startup must
    // still identify prior initialization and refuse the missing record.
    harness.assert_restart_refused_for("initialized writer-fence journal record is missing");
}
