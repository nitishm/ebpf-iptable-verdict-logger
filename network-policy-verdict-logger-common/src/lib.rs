#![no_std]

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IPTableVerdict {
    pub verdict: i32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IPTableFlow {
    // pub src_ip4: u32,
    // pub dst_ip4: u32,
    // pub src_port: u16,
    // pub dst_port: u16,
    // pub proto: u16,
}
