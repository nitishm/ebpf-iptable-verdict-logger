#![no_std]
#![no_main]
mod bindings;

use aya_bpf::{
    macros::kprobe,
    macros::kretprobe,
    macros::map,
    maps::PerfEventArray,
    programs::ProbeContext,
    cty::c_int,
    helpers::bpf_probe_read,
};

use aya_log_ebpf::info;

use bindings::sk_buff;

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
    let tp: *const sk_buff = ctx.arg(0).ok_or(1u32)?;
    // let flow = IPTableFlow {
    // };

    // TUPLES.output(&ctx, &flow, 0);
    
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
