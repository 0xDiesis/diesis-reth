#![allow(missing_docs)]
use byteorder::{ByteOrder, LittleEndian};
use reth_libmdbx::*;
use tempfile::tempdir;

#[test]
fn test_open() {
    let dir = tempdir().unwrap();

    // opening non-existent env with read-only should fail
    assert!(Environment::builder().set_flags(Mode::ReadOnly.into()).open(dir.path()).is_err());

    // opening non-existent env should succeed
    assert!(Environment::builder().open(dir.path()).is_ok());

    // opening env with read-only should succeed
    assert!(Environment::builder().set_flags(Mode::ReadOnly.into()).open(dir.path()).is_ok());
}

#[test]
fn test_begin_txn() {
    let dir = tempdir().unwrap();

    {
        // writable environment
        let env = Environment::builder().open(dir.path()).unwrap();

        assert!(env.begin_rw_txn().is_ok());
        assert!(env.begin_ro_txn().is_ok());
    }

    {
        // read-only environment
        let env = Environment::builder().set_flags(Mode::ReadOnly.into()).open(dir.path()).unwrap();

        assert!(env.begin_rw_txn().is_err());
        assert!(env.begin_ro_txn().is_ok());
    }
}

#[test]
fn test_open_db() {
    let dir = tempdir().unwrap();
    let env = Environment::builder().set_max_dbs(1).open(dir.path()).unwrap();

    let txn = env.begin_ro_txn().unwrap();
    assert!(txn.open_db(None).is_ok());
    assert!(txn.open_db(Some("testdb")).is_err());
}

#[test]
fn test_create_db() {
    let dir = tempdir().unwrap();
    let env = Environment::builder().set_max_dbs(11).open(dir.path()).unwrap();

    let txn = env.begin_rw_txn().unwrap();
    assert!(txn.open_db(Some("testdb")).is_err());
    assert!(txn.create_db(Some("testdb"), DatabaseFlags::empty()).is_ok());
    assert!(txn.open_db(Some("testdb")).is_ok())
}

#[test]
fn test_close_database() {
    let dir = tempdir().unwrap();
    let env = Environment::builder().set_max_dbs(10).open(dir.path()).unwrap();

    let txn = env.begin_rw_txn().unwrap();
    txn.create_db(Some("db"), DatabaseFlags::empty()).unwrap();
    txn.open_db(Some("db")).unwrap();
}

#[test]
fn test_sync() {
    let dir = tempdir().unwrap();
    {
        let env = Environment::builder().open(dir.path()).unwrap();
        env.sync(true).unwrap();
    }
    {
        let env = Environment::builder().set_flags(Mode::ReadOnly.into()).open(dir.path()).unwrap();
        env.sync(true).unwrap_err();
    }
}

#[test]
fn test_copy_is_a_consistent_readable_snapshot() {
    let src_dir = tempdir().unwrap();
    let env = Environment::builder().set_max_dbs(2).open(src_dir.path()).unwrap();

    // Seed deterministic contents in a named table.
    let txn = env.begin_rw_txn().unwrap();
    let db = txn.create_db(Some("t"), DatabaseFlags::empty()).unwrap();
    for i in 0u32..128 {
        let mut key = [0u8; 4];
        LittleEndian::write_u32(&mut key, i);
        txn.put(db.dbi(), key, key, WriteFlags::empty()).unwrap();
    }
    txn.commit().unwrap();

    // Copy to a fresh, not-yet-existing single database file.
    let dst_dir = tempdir().unwrap();
    let dst_file = dst_dir.path().join("snapshot.dat");
    env.copy(&dst_file, false).unwrap();
    assert!(dst_file.is_file(), "copy must produce a single data file");

    // Copying over an existing path must fail (dest must not exist).
    env.copy(&dst_file, false).unwrap_err();

    // The copy reopens as a self-consistent environment with identical data.
    // It is a single file, so it must be opened in no-subdir mode.
    let copied = Environment::builder()
        .set_max_dbs(2)
        .set_flags(EnvironmentFlags {
            no_sub_dir: true,
            mode: Mode::ReadOnly,
            ..Default::default()
        })
        .open(&dst_file)
        .unwrap();
    let rtxn = copied.begin_ro_txn().unwrap();
    let rdb = rtxn.open_db(Some("t")).unwrap();
    for i in 0u32..128 {
        let mut key = [0u8; 4];
        LittleEndian::write_u32(&mut key, i);
        let value = rtxn.get::<[u8; 4]>(rdb.dbi(), &key).unwrap();
        assert_eq!(value, Some(key));
    }
}

#[test]
fn test_stat() {
    let dir = tempdir().unwrap();
    let env = Environment::builder().open(dir.path()).unwrap();

    // Stats should be empty initially.
    let stat = env.stat().unwrap();
    assert_eq!(stat.depth(), 0);
    assert_eq!(stat.branch_pages(), 0);
    assert_eq!(stat.leaf_pages(), 0);
    assert_eq!(stat.overflow_pages(), 0);
    assert_eq!(stat.entries(), 0);

    // Write a few small values.
    for i in 0..64 {
        let mut value = [0u8; 8];
        LittleEndian::write_u64(&mut value, i);
        let tx = env.begin_rw_txn().expect("begin_rw_txn");
        tx.put(tx.open_db(None).unwrap().dbi(), value, value, WriteFlags::default())
            .expect("tx.put");
        tx.commit().expect("tx.commit");
    }

    // Stats should now reflect inserted values.
    let stat = env.stat().unwrap();
    assert_eq!(stat.depth(), 1);
    assert_eq!(stat.branch_pages(), 0);
    assert_eq!(stat.leaf_pages(), 1);
    assert_eq!(stat.overflow_pages(), 0);
    assert_eq!(stat.entries(), 64);
}

#[test]
fn test_info() {
    let map_size = 1024 * 1024;
    let dir = tempdir().unwrap();
    let env = Environment::builder()
        .set_geometry(Geometry { size: Some(map_size..), ..Default::default() })
        .open(dir.path())
        .unwrap();

    let info = env.info().unwrap();
    assert_eq!(info.geometry().min(), map_size as u64);
    // assert_eq!(info.last_pgno(), 1);
    // assert_eq!(info.last_txnid(), 0);
    assert_eq!(info.num_readers(), 0);
    assert!(matches!(info.mode(), Mode::ReadWrite { sync_mode: SyncMode::Durable }));
    assert!(env.is_read_write().unwrap());

    drop(env);
    let env = Environment::builder()
        .set_geometry(Geometry { size: Some(map_size..), ..Default::default() })
        .set_flags(EnvironmentFlags { mode: Mode::ReadOnly, ..Default::default() })
        .open(dir.path())
        .unwrap();
    let info = env.info().unwrap();
    assert!(matches!(info.mode(), Mode::ReadOnly));
    assert!(env.is_read_only().unwrap());
}

#[test]
fn test_freelist() {
    let dir = tempdir().unwrap();
    let env = Environment::builder().open(dir.path()).unwrap();

    let mut freelist = env.freelist().unwrap();
    assert_eq!(freelist, 0);

    // Write a few small values.
    for i in 0..64 {
        let mut value = [0u8; 8];
        LittleEndian::write_u64(&mut value, i);
        let tx = env.begin_rw_txn().expect("begin_rw_txn");
        tx.put(tx.open_db(None).unwrap().dbi(), value, value, WriteFlags::default())
            .expect("tx.put");
        tx.commit().expect("tx.commit");
    }
    let tx = env.begin_rw_txn().expect("begin_rw_txn");
    tx.clear_db(tx.open_db(None).unwrap().dbi()).expect("clear");
    tx.commit().expect("tx.commit");

    // Freelist should not be empty after clear_db.
    freelist = env.freelist().unwrap();
    assert!(freelist > 0);
}
