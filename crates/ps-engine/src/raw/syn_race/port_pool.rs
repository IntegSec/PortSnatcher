//! Source-port pool for the SYN race.
//!
//! We allocate a contiguous range (default `40000..=49999`) that the
//! race sender cycles through. Kernel's default ephemeral range on
//! Linux is `32768..=60999`; collisions with kernel-selected ephemeral
//! ports are rare in our smaller window but *possible*, and when they
//! happen the kernel's SYN_SENT state takes precedence — our crafted
//! SYN is a no-op. That's acceptable: we treat it as a transient miss
//! and try again on the next cycle.
//!
//! The pool is deliberately minimal: no reserved-port sysctl tampering
//! (which would need root persistent state) and no per-target
//! affinity. Those are v1.3 enhancements if measurements show a lift.

use std::sync::atomic::{AtomicU32, Ordering};

/// Default source-port pool lower bound.
pub const DEFAULT_LOW: u16 = 40_000;
/// Default source-port pool upper bound (inclusive).
pub const DEFAULT_HIGH: u16 = 49_999;

#[derive(Debug)]
pub struct PortPool {
    low: u16,
    high: u16,
    cursor: AtomicU32,
}

impl PortPool {
    pub fn new(low: u16, high: u16) -> Self {
        assert!(high >= low, "port pool high must be ≥ low");
        Self {
            low,
            high,
            cursor: AtomicU32::new(0),
        }
    }

    pub fn default_range() -> Self {
        Self::new(DEFAULT_LOW, DEFAULT_HIGH)
    }

    /// Total number of ports in the pool.
    pub fn len(&self) -> u32 {
        (self.high as u32) - (self.low as u32) + 1
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bounds as a closed range.
    pub fn bounds(&self) -> (u16, u16) {
        (self.low, self.high)
    }

    /// Returns `true` if `port` falls within the pool.
    pub fn contains(&self, port: u16) -> bool {
        port >= self.low && port <= self.high
    }

    /// Hand out the next source port, wrapping around at `high`.
    /// Thread-safe; callers racing for port numbers get monotonically
    /// distinct handouts until the cursor wraps.
    pub fn next_port(&self) -> u16 {
        let span = self.len();
        let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % span;
        self.low + idx as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hands_out_distinct_ports_until_wrap() {
        let p = PortPool::new(40_000, 40_002); // 3 ports
        assert_eq!(p.next_port(), 40_000);
        assert_eq!(p.next_port(), 40_001);
        assert_eq!(p.next_port(), 40_002);
        assert_eq!(p.next_port(), 40_000); // wraps
    }

    #[test]
    fn contains_checks_bounds() {
        let p = PortPool::new(40_000, 40_010);
        assert!(p.contains(40_000));
        assert!(p.contains(40_010));
        assert!(!p.contains(39_999));
        assert!(!p.contains(40_011));
    }

    #[test]
    fn len_matches_inclusive_range() {
        let p = PortPool::new(40_000, 40_099);
        assert_eq!(p.len(), 100);
    }

    #[test]
    fn default_range_covers_10k() {
        let p = PortPool::default_range();
        assert_eq!(p.len(), 10_000);
        assert!(p.contains(40_000));
        assert!(p.contains(49_999));
    }
}
