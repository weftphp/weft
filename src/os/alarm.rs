//! A process-wide interval timer (`setitimer` + `SIGALRM`), for code without an event loop
//! that still needs periodic wake-ups, such as a worker blocked in a long computation.
//!
//! Ticks arrive as `SIGALRM` through [`signal`]: wait on [`signal::notifier`] or poll
//! [`signal::take_pending`].
//! There is one such timer per process.

use std::io;
use std::time::Duration;

use super::fd::check;
use super::signal;

fn timeval(d: Duration) -> libc::timeval {
    libc::timeval {
        tv_sec: d.as_secs().min(libc::time_t::MAX as u64) as libc::time_t,
        tv_usec: d.subsec_micros() as libc::suseconds_t,
    }
}

fn set(first: Duration, interval: Duration) -> io::Result<()> {
    let value = libc::itimerval {
        it_interval: timeval(interval),
        it_value: timeval(first),
    };
    // SAFETY: `value` is a valid itimerval; the old value is not requested.
    check(unsafe { libc::setitimer(libc::ITIMER_REAL, &value, std::ptr::null_mut()) }).map(drop)
}

/// Delivers `SIGALRM` every `interval` (the first after one interval).
pub fn start(interval: Duration) -> io::Result<()> {
    if interval.is_zero() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "zero interval"));
    }
    signal::watch(libc::SIGALRM)?;
    set(interval, interval)
}

/// Delivers a single `SIGALRM` after `delay`.
pub fn once(delay: Duration) -> io::Result<()> {
    if delay.is_zero() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "zero delay"));
    }
    signal::watch(libc::SIGALRM)?;
    set(delay, Duration::ZERO)
}

/// Disarms the timer and restores `SIGALRM`'s default disposition.
pub fn stop() -> io::Result<()> {
    set(Duration::ZERO, Duration::ZERO)?;
    signal::reset(libc::SIGALRM)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn ticks_arrive_as_signals() {
        start(Duration::from_millis(5)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut ticks = 0;
        while ticks < 3 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(2));
            if signal::take_pending().contains(&libc::SIGALRM) {
                ticks += 1;
            }
        }
        stop().unwrap();
        assert_eq!(ticks, 3);
        assert!(start(Duration::ZERO).is_err());
    }
}
