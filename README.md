# network-policy-verdict-logger

The eBPF verdict logger is a PoC for Kubernetes NetworkPolicy observability using eBPF programs, for implementations using iptable/ipset policy enforcement. The eBPF program attaches a pair of kprobe and kretprobe to the `nf_slow_hook()` function in the linux networking stack to capture the input (`sk_buff` that contains the flow tuple information) and the return value (verdict). The captured data is stored in a shared eBPF map between the userspace and eBPF program. The current implementation periodically prints the contects of the map to stdout for demonstration purposes.

The project is built using [aya](https://github.com/aya/aya-rs), a Rust library for building eBPF userspace and kernel programs with native support for eBPF (without FFIs or wrappers over existing `C` tools).

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
2. Install a rust nightly toolchain: `rustup install nightly`
3. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

## Build Userspace

```bash
cargo build
```

## Run

```bash
cargo xtask run
```

Add a `DROP` rule for `example.com` (resolves to IP address `93.184.216.34`) and attempt sending a request to the blocked IP using `curl`

```terminal
sudo iptables -A OUTPUT -d 93.184.216.34 -j DROP
curl -4 93.184.216.34
```

In a separate terminal running the eBPF program you should see the flow tuple and verdict information printed to the console as follows,

```terminal
...
warning: `network-policy-verdict-logger` (bin "network-policy-verdict-logger") generated 3 warnings
    Finished dev [unoptimized + debuginfo] target(s) in 1.18s
Transport Proto 6
SourceIP 10.0.0.4
DestIP 93.184.216.34
SourcePort 45227
DestPort 20480
Verdict -1
```
, where -1 represents a packet DROP.
