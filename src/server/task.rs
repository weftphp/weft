//! Task workers: pull tasks from the shared queue, run
//! [`Handler::on_task`], and send results back to the event worker
//! that submitted them.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::Duration;

use super::Handler;
use super::ipc::{Envelope, Peers, TaskId, decode_task};
use crate::core::log::logger;
use crate::memory::queue::SharedQueue;

/// What a task handler knows about the task it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskContext {
    /// Index of this task worker (0-based among task workers).
    pub worker_id: usize,
    pub task: TaskId,
    /// The event worker that submitted the task.
    pub from_worker: usize,
}

/// How often a waiting task worker checks whether it should stop.
const POLL: Duration = Duration::from_millis(100);

/// Runs a task worker until `should_stop` returns `true`.
pub(crate) fn run(
    index: usize,
    queue: Arc<SharedQueue>,
    peers: &dyn Peers,
    mut handler: Box<dyn Handler>,
    mut should_stop: impl FnMut() -> bool,
) {
    while !should_stop() {
        let Some(message) = queue.pop(Some(POLL)) else {
            continue;
        };
        let Some((task, from, data)) = decode_task(&message) else {
            continue;
        };
        let ctx = TaskContext {
            worker_id: index,
            task,
            from_worker: from,
        };
        let data = data.to_vec();
        match catch_unwind(AssertUnwindSafe(|| handler.on_task(&ctx, data))) {
            Ok(Some(result)) => {
                if let Err(e) = peers.deliver(from, Envelope::TaskResult { task, data: result }) {
                    logger().warn(format!("task {}: result not delivered: {e}", task.0));
                }
            }
            Ok(None) => {}
            Err(_) => logger().error(format!("task {} panicked in task worker {index}", task.0)),
        }
    }
}
