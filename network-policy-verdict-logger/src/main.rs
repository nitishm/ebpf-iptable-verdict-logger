use aya::{
    maps::perf::AsyncPerfEventArray,
    Bpf, 
    include_bytes_aligned,
    util::online_cpus,
};

use std::convert::{TryFrom, TryInto};
use aya::programs::KProbe;
use bytes::BytesMut;
use std::{
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    thread::sleep,
    time::Duration,
    net,
};
use structopt::StructOpt;
use tokio::{task,signal};

use network_policy_verdict_logger_common::{IPTableVerdict, IPTableFlow};

#[tokio::main]
async fn main() {
    if let Err(e) = try_main().await {
        eprintln!("error: {:#}", e);
    }
}

#[derive(Debug, StructOpt)]
struct Opt {
    
}

async fn try_main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();
    // This will include youe eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/network-policy-verdict-logger"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/network-policy-verdict-logger"
    ))?;
    let program: &mut KProbe = bpf.program_mut("network_policy_verdict_logger_probe").unwrap().try_into()?;
    program.load()?;
    program.attach("nf_hook_slow", 0)?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("TUPLES")?)?;
    
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const IPTableFlow;
                    let data = unsafe { ptr.read_unaligned() };
                    let remote_addr = net::Ipv4Addr::from(data.remote_ip);
                    println!("LOG: CPU {} EVENT {} REMOTE_IP {} LEN {}", cpu_id, i, remote_addr, data.len );
                }
            }
        });
    }
    return wait_until_terminated().await;
}

async fn wait_until_terminated() -> Result<(), anyhow::Error> {
    signal::ctrl_c().await?;
    println!("Exiting...");
    Ok(())
}
