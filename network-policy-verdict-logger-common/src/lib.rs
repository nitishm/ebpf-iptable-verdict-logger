#![no_std]

use core::convert::TryFrom;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IPTableV4Flow {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
}

// ANCHOR: pod
#[cfg(feature = "user")]
unsafe impl aya::Pod for IPTableV4Flow {}
// ANCHOR_END: pod
