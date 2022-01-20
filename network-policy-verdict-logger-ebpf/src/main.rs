#![no_std]
#![no_main]

use aya_bpf::{
    macros::kretprobe,
    macros::map,
    maps::PerfEventArray,
    programs::ProbeContext,
    cty::c_int,
};

use network_policy_verdict_logger_common::IPTableVerdict;

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<IPTableVerdict> = PerfEventArray::<IPTableVerdict>::with_max_entries(1024, 0);

#[kretprobe(name="network_policy_verdict_logger")]
pub fn network_policy_verdict_logger(ctx: ProbeContext) -> u32 {
    match unsafe { try_network_policy_verdict_logger(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_network_policy_verdict_logger(ctx: ProbeContext) -> Result<u32, u32> {
    let retval: c_int = ctx.ret().ok_or(100u32)?;
    
    let verdict = IPTableVerdict {
        verdict: retval as u32,
    };

    EVENTS.output(&ctx, &verdict, 0);
    
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
