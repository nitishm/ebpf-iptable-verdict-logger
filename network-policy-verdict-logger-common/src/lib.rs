#![no_std]

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IPTableV4Flow {
    pub eth_proto: u16,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    pub verdict: i32,
}
