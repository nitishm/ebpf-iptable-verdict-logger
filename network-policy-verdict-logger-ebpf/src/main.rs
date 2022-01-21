#![no_std]
#![no_main]

use aya_bpf::{
    macros::kprobe,
    macros::kretprobe,
    macros::map,
    maps::PerfEventArray,
    programs::ProbeContext,
    cty::c_int,
    bindings::__sk_buff,
    helpers::bpf_probe_read,
};

use aya_log_ebpf::info;

use network_policy_verdict_logger_common::{IPTableVerdict, IPTableFlow};

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<IPTableVerdict> = PerfEventArray::<IPTableVerdict>::with_max_entries(1024, 0);

#[map(name = "TUPLES")]
static mut TUPLES: PerfEventArray<IPTableFlow> = PerfEventArray::<IPTableFlow>::with_max_entries(1024, 0); 

#[kprobe(name="network_policy_verdict_logger_probe")]
pub fn network_policy_verdict_logger_probe(ctx: ProbeContext) -> u32 {
    match unsafe { try_network_policy_verdict_logger_probe(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_network_policy_verdict_logger_probe(ctx: ProbeContext) -> Result<u32, u32> {
    let tp: *const __sk_buff = ctx.arg(0).ok_or(1u32)?;
    
    let remote_ip = bpf_probe_read(&(*tp).remote_ip4 as *const u32).map_err(|_| 1u32)?;
    let len = bpf_probe_read(&(*tp).len as *const u32).map_err(|_| 1u32)?;
    
    let flow = IPTableFlow {
        remote_ip: remote_ip,
        len: len,
    };

    TUPLES.output(&ctx, &flow, 0);
    
    Ok(0)
}

#[kretprobe(name="network_policy_verdict_logger")]
pub fn network_policy_verdict_logger(ctx: ProbeContext) -> u32 {
    match unsafe { try_network_policy_verdict_logger(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_network_policy_verdict_logger(ctx: ProbeContext) -> Result<u32, u32> {
    let retval: c_int = ctx.ret().ok_or(100u32)?;
    if retval == 1 {
        return Ok(0);
    }

    let verdict = IPTableVerdict {
        verdict: retval as i32,
    };
    
    EVENTS.output(&ctx, &verdict, 0);
    
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
