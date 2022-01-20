#![no_std]

#[repr(C)]
pub struct IPTableVerdict {
    pub verdict: u32,
}

