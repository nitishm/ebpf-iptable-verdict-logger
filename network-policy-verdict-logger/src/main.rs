use aya::{
    maps::{perf::AsyncPerfEventArray,HashMap}, 
    Bpf, 
    include_bytes_aligned,
    util::online_cpus,
};

use std::{convert::{TryFrom, TryInto}, net};
use aya::programs::KProbe;
use bytes::BytesMut;
use structopt::StructOpt;
use tokio::{task,signal, time::sleep};

use network_policy_verdict_logger_common::IPTableV4Flow;


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
    let program_kprobe: &mut KProbe = bpf.program_mut("network_policy_verdict_logger_probe").unwrap().try_into()?;
    program_kprobe.load()?;
    program_kprobe.attach("nf_hook_slow", 0)?;

    let program_kretprobe: &mut KProbe = bpf.program_mut("network_policy_verdict_logger").unwrap().try_into()?;
    program_kretprobe.load()?;
    program_kretprobe.attach("nf_hook_slow", 0)?;

    let flow_table: HashMap<_, IPTableV4Flow, i32> = HashMap::try_from(bpf.map_mut("FLOW_TABLE_V4")?)?;

    task::spawn(async move {
        loop {
            for pair in flow_table.iter().enumerate() {
                if let Ok(flow_table) = pair.1 {
                    let flow = flow_table.0;
                    let verdict = flow_table.1;
                    let saddr = net::Ipv4Addr::from(flow.saddr.to_be());
                    let daddr = net::Ipv4Addr::from(flow.daddr.to_be());
                    if verdict == -1 {
                        println!("Transport Proto {}\nSourceIP {}\nDestIP {}\nSourcePort {}\nDestPort {}\nVerdict {}\n", 
                            flow.proto, saddr, daddr, flow.sport, flow.dport, verdict);
                    } 
                }
            }
            sleep(std::time::Duration::from_secs(3)).await;
        }
    });

    // for cpu_id in online_cpus()? {
    //     let mut buf_tuples = perf_array_tuples.open(cpu_id, None)?;

    //     task::spawn(async move {
    //         let mut buffers = (0..10)
    //             .map(|_| BytesMut::with_capacity(1024))
    //             .collect::<Vec<_>>();

    //         loop {
    //             let events = buf_tuples.read_events(&mut buffers).await.unwrap();
    //             for i in 0..events.read {
    //                 let buf = &mut buffers[i];
    //                 let ptr = buf.as_ptr() as *const IPTableV4Flow;
    //                 let data = unsafe { ptr.read_unaligned() };
    //                 let saddr = net::Ipv4Addr::from(data.saddr.to_be());
    //                 let daddr = net::Ipv4Addr::from(data.daddr.to_be());
    //                 // if data.proto == 17 {
    //                     println!("Network Proto {} Transport Proto {} SourceIP {} DestIP {} SourcePort {} DestPort {} Verdict {}", 
    //                         data.eth_proto, data.proto, saddr, daddr, data.sport, data.dport, data.verdict,
    //                     );
    //                 // }
    //             }
    //         }
    //     });
    // }
    return wait_until_terminated().await;
}

async fn wait_until_terminated() -> Result<(), anyhow::Error> {
    signal::ctrl_c().await?;
    println!("Exiting...");
    Ok(())
}
