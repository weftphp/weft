//! Process creation, signalling and reaping.

use std::fmt;
use std::io;

use crate::os::fd::{check, retry};

/// A process id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pid(pub libc::pid_t);

impl Pid {
    /// The calling process.
    pub fn current() -> Pid {
        // SAFETY: getpid cannot fail.
        Pid(unsafe { libc::getpid() })
    }

    /// The parent of the calling process.
    pub fn parent() -> Pid {
        // SAFETY: getppid cannot fail.
        Pid(unsafe { libc::getppid() })
    }
}

impl fmt::Display for Pid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Which side of a [`fork`] the caller is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fork {
    Parent(Pid),
    Child,
}

/// Forks the process.
///
/// # Safety
///
/// Only the calling thread survives in the child. Locks held by other threads stay locked
/// forever there, so until it calls `exec` or exits the child may only rely on state no other
/// thread could have been mutating (in particular, avoid the allocator if other threads exist).
pub unsafe fn fork() -> io::Result<Fork> {
    // SAFETY: the caller upholds the post-fork restrictions documented above.
    match check(unsafe { libc::fork() })? {
        0 => Ok(Fork::Child),
        pid => Ok(Fork::Parent(Pid(pid))),
    }
}

/// Ends the calling process immediately, without running destructors or `atexit` hooks.
/// This is what a forked child should use to exit.
pub fn exit_now(code: i32) -> ! {
    // SAFETY: _exit is always safe to call; it does not return.
    unsafe { libc::_exit(code) }
}

/// How a child process ended (or changed state).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    /// Exited normally with this code.
    Exited(i32),
    /// Killed by a signal.
    Signaled { signal: i32, core_dumped: bool },
}

impl ExitStatus {
    fn from_raw(status: libc::c_int) -> Option<ExitStatus> {
        if libc::WIFEXITED(status) {
            Some(ExitStatus::Exited(libc::WEXITSTATUS(status)))
        } else if libc::WIFSIGNALED(status) {
            Some(ExitStatus::Signaled {
                signal: libc::WTERMSIG(status),
                core_dumped: libc::WCOREDUMP(status),
            })
        } else {
            None
        }
    }

    pub fn success(self) -> bool {
        self == ExitStatus::Exited(0)
    }
}

impl fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExitStatus::Exited(code) => write!(f, "exit code {code}"),
            ExitStatus::Signaled {
                signal,
                core_dumped,
            } => {
                write!(f, "signal {signal}")?;
                if *core_dumped {
                    f.write_str(" (core dumped)")?;
                }
                Ok(())
            }
        }
    }
}

/// Reaps a terminated child: `pid`, or any child if `None`.
///
/// With `block == false` returns `Ok(None)` when no matching child has exited yet. Fails with
/// `ECHILD` when there is no matching child at all.
pub fn wait(pid: Option<Pid>, block: bool) -> io::Result<Option<(Pid, ExitStatus)>> {
    let target = pid.map_or(-1, |p| p.0);
    let flags = if block { 0 } else { libc::WNOHANG };
    loop {
        let mut status = 0;
        // SAFETY: `status` is a valid out-pointer for the duration of the call.
        let reaped = retry(|| check(unsafe { libc::waitpid(target, &mut status, flags) }))?;
        if reaped == 0 {
            return Ok(None);
        }
        // Stop/continue notifications are not requested, but skip anything unexpected.
        if let Some(exit) = ExitStatus::from_raw(status) {
            return Ok(Some((Pid(reaped), exit)));
        }
    }
}

/// Sends `signal` to `pid`.
pub fn kill(pid: Pid, signal: i32) -> io::Result<()> {
    // SAFETY: kill has no memory-safety preconditions.
    check(unsafe { libc::kill(pid.0, signal) }).map(drop)
}

/// Whether `pid` exists (it may belong to another user).
pub fn exists(pid: Pid) -> bool {
    match kill(pid, 0) {
        Ok(()) => true,
        Err(err) => err.raw_os_error() == Some(libc::EPERM),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fork_and_reap() {
        // SAFETY: the child only calls _exit.
        match unsafe { fork() }.unwrap() {
            Fork::Child => exit_now(7),
            Fork::Parent(child) => {
                let (pid, status) = wait(Some(child), true).unwrap().unwrap();
                assert_eq!(pid, child);
                assert_eq!(status, ExitStatus::Exited(7));
                assert!(!status.success());
                assert!(!exists(child));
            }
        }
    }

    #[test]
    fn signalled_child() {
        // SAFETY: the child only pauses until killed (or exits if pause returns).
        match unsafe { fork() }.unwrap() {
            Fork::Child => {
                // SAFETY: pause has no preconditions.
                unsafe { libc::pause() };
                exit_now(0)
            }
            Fork::Parent(child) => {
                assert!(exists(child));
                kill(child, libc::SIGKILL).unwrap();
                let (_, status) = wait(Some(child), true).unwrap().unwrap();
                assert_eq!(
                    status,
                    ExitStatus::Signaled {
                        signal: libc::SIGKILL,
                        core_dumped: false
                    }
                );
                assert_eq!(status.to_string(), format!("signal {}", libc::SIGKILL));
            }
        }
    }

    #[test]
    fn current_process() {
        assert_eq!(Pid::current().0 as u32, std::process::id());
        assert!(exists(Pid::parent()));
    }
}
