#![no_std]

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IPTableVerdict {
    pub verdict: i32,
}

pub struct IPTableFlow {
    pub remote_ip: u32,
    pub len: u32,
}
