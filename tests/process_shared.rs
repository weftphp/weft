//! Shared-memory structures used from several forked processes at once.
//!
//! Kept to a single test so no other test thread is running when the process forks.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use weft::lock::{Barrier, ProcessMutex};
use weft::memory::queue::SharedQueue;
use weft::memory::table::{Column, ColumnType, Table, Value};
use weft::memory::{Shared, ShmSafe};
use weft::os::process::{self, ExitStatus, Fork};

#[repr(C)]
#[derive(Default)]
struct Counters {
    lock: ProcessMutex,
    start: Barrier,
    /// Updated non-atomically (load + store) so only the mutex keeps it consistent.
    guarded: AtomicU64,
}

// SAFETY: made only of ShmSafe parts.
unsafe impl ShmSafe for Counters {}

const WORKERS: u64 = 4;
const ROUNDS: u64 = 500;

#[test]
fn workers_share_tables_queues_and_locks() {
    let counters = Shared::<Counters>::new().unwrap();
    counters.start.set_parties(WORKERS as u32 + 1);
    let table = Table::new(&[Column::new("hits", ColumnType::Int)], 64, 32).unwrap();
    let queue = SharedQueue::new(4096, 64).unwrap();

    let mut children = Vec::new();
    for worker in 0..WORKERS {
        // SAFETY: the child only touches shared memory and exits with _exit.
        match unsafe { process::fork() }.unwrap() {
            Fork::Child => {
                counters.start.wait();
                for i in 0..ROUNDS {
                    {
                        let _guard = counters.lock.lock();
                        let v = counters.guarded.load(Ordering::Relaxed);
                        counters.guarded.store(v + 1, Ordering::Relaxed);
                    }
                    let key = [b'k', b'0' + (i % 8) as u8];
                    if table.incr(key, "hits", Value::Int(1)).is_err() {
                        process::exit_now(2);
                    }
                }
                let report = worker.to_le_bytes();
                if queue.push(&report, Some(Duration::from_secs(10))).is_err() {
                    process::exit_now(3);
                }
                process::exit_now(0);
            }
            Fork::Parent(pid) => children.push(pid),
        }
    }

    counters.start.wait();
    let mut reports = Vec::new();
    for _ in 0..WORKERS {
        let message = queue
            .pop(Some(Duration::from_secs(20)))
            .expect("worker report");
        reports.push(u64::from_le_bytes(message.try_into().unwrap()));
    }
    for pid in children {
        let (_, status) = process::wait(Some(pid), true).unwrap().unwrap();
        assert_eq!(status, ExitStatus::Exited(0));
    }

    reports.sort_unstable();
    assert_eq!(reports, (0..WORKERS).collect::<Vec<_>>());
    assert_eq!(counters.guarded.load(Ordering::Relaxed), WORKERS * ROUNDS);
    let total: i64 = table
        .rows()
        .iter()
        .filter_map(|(_, row)| row.int("hits"))
        .sum();
    assert_eq!(total as u64, WORKERS * ROUNDS);
    assert_eq!(table.len(), 8);
}
