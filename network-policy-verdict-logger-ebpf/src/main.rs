#![no_std]
#![no_main]
mod bindings;

use aya_bpf::{
    cty::c_int, cty::c_uchar, 
    helpers::{bpf_probe_read,bpf_get_current_pid_tgid},
    macros::{map, kprobe, kretprobe}, 
    maps::{HashMap, PerfEventArray}, 
    programs::ProbeContext,
};

use aya_log_ebpf::info;

use bindings::{
    sk_buff,
    iphdr, tcphdr, udphdr,
};

use network_policy_verdict_logger_common::IPTableV4Flow;

#[map(name = "FLOW_TABLE_V4")]
static mut FLOW_TABLE_V4: HashMap<IPTableV4Flow, i32> = HashMap::with_max_entries(1024, 0);

#[map(name = "FLOWS_V4_LUP")]
static mut FLOWS_V4_LUP: HashMap<(u32, u32), IPTableV4Flow> = HashMap::with_max_entries(1024, 0);

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<IPTableV4Flow> =
    PerfEventArray::<IPTableV4Flow>::with_max_entries(1024, 0);

#[kprobe(name = "network_policy_verdict_logger_probe")]
pub fn network_policy_verdict_logger_probe(ctx: ProbeContext) -> u32 {
    match unsafe { try_network_policy_verdict_logger_probe(ctx) } {
        Ok(ret) => 0,
        Err(ret) => 0,
    }
}

unsafe fn try_network_policy_verdict_logger_probe(ctx: ProbeContext) -> Result<u32, u32> {
    let tid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let pid = bpf_get_current_pid_tgid() as u32;

    let tp: *const sk_buff = ctx.arg(0).ok_or(1u32)?;
    let eth_proto = bpf_probe_read(&(*tp).protocol as *const u16).map_err(|_| 100u32)?;

    if eth_proto != IPV4_PROTOCOL_NUMBER && eth_proto != IPV6_PROTOCOL_NUMBER {
        return Ok(0);
    }

    // For now let's only handle IPv4
    if eth_proto == IPV6_PROTOCOL_NUMBER {
        return Ok(0);
    }
    
    // Verifier doesnt like this!!
    let head = bpf_probe_read(&(*tp).head as *const *mut c_uchar).map_err(|_| 100u8)?;
    let network_header_offset =
        bpf_probe_read(&(*tp).network_header as *const u16).map_err(|_| 100u16)?;

    let nw_hdr_ptr = head.add(network_header_offset as usize);
    let nw_hdr = bpf_probe_read(nw_hdr_ptr as *const iphdr).map_err(|_| 101u8)?;

    let proto = nw_hdr.protocol as u16;
    
    let saddr = nw_hdr.saddr as u32;
    let daddr = nw_hdr.daddr as u32;

    if proto != UDP_PROTOCOL_NUMBER && proto != TCP_PROTOCOL_NUMBER {
        return Ok(0);
    }

    let mut sport: u16 = 0;
    let mut dport: u16 = 0;

    match proto {
        TCP_PROTOCOL_NUMBER => {
            let transport_header_offset =
                bpf_probe_read(&(*tp).transport_header as *const u16).map_err(|_| 100u16)?;

            let trans_hdr_ptr = head.add(transport_header_offset as usize);
            let trans_hdr = bpf_probe_read(trans_hdr_ptr as *const tcphdr).map_err(|_| 101u8)?;
            sport = trans_hdr.source;
            dport = trans_hdr.dest;
        },
        UDP_PROTOCOL_NUMBER => {
            let transport_header_offset =
                bpf_probe_read(&(*tp).transport_header as *const u16).map_err(|_| 100u16)?;

            let trans_hdr_ptr = head.add(transport_header_offset as usize);
            let trans_hdr = bpf_probe_read(trans_hdr_ptr as *const udphdr).map_err(|_| 101u8)?;
            sport = trans_hdr.source;
            dport = trans_hdr.dest;
        },
        _ => (),
    };

    let flow = IPTableV4Flow {
        proto: proto as u8,
        saddr: saddr,
        daddr: daddr,
        sport: sport,
        dport: dport,
    };

    FLOWS_V4_LUP.insert(&(tid, pid), &flow, 0).map_err(|e| e as u32)?;

    Ok(0)
}

#[kretprobe(name = "network_policy_verdict_logger")]
pub fn network_policy_verdict_logger(ctx: ProbeContext) -> u32 {
    match unsafe { try_network_policy_verdict_logger(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_network_policy_verdict_logger(ctx: ProbeContext) -> Result<u32, u32> {
    let tid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let pid = bpf_get_current_pid_tgid() as u32;
    let retval: c_int = ctx.ret().ok_or(100u32)?;

    match FLOWS_V4_LUP.get(&(tid, pid)) {
        Some(flow) => {
            let mut new_flow = *flow;
            let verdict = retval as i32;
            FLOW_TABLE_V4.insert(&new_flow, &verdict, 0).map_err(|e| e as u32)?;
        },
        None => (),
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

const IPV4_PROTOCOL_NUMBER: u16 = 8u16;
const IPV6_PROTOCOL_NUMBER: u16 = 41u16;
const TCP_PROTOCOL_NUMBER: u16 = 6u16;
const UDP_PROTOCOL_NUMBER: u16 = 17u16;
