//! Load every XDP program in the eBPF object without attaching — exercises
//! the kernel verifier only. Reports per-program acceptance plus the tail of
//! the verifier log on failure. Used by T4-8 host validation so program-load
//! issues are separated from netdev attach behavior.
//!
//! Usage: xdp-verify <path-to-ebpf-object>

fn main() {
    #[cfg(target_os = "linux")]
    {
        let path = std::env::args()
            .nth(1)
            .unwrap_or_else(|| "data/cloud-node-xdp-ebpf.o".to_string());
        let mut bpf = match aya::Ebpf::load_file(&path) {
            Ok(bpf) => bpf,
            Err(err) => {
                eprintln!("load_file {path}: {err}");
                std::process::exit(2);
            }
        };
        let mut names: Vec<String> = bpf
            .programs()
            .map(|(name, _)| name.to_string())
            .collect();
        names.sort();
        let mut failed = 0u32;
        for name in &names {
            let program = bpf.program_mut(name).expect("program enumerated");
            let xdp: &mut aya::programs::Xdp = match program.try_into() {
                Ok(xdp) => xdp,
                Err(err) => {
                    println!("SKIP {name}: not an XDP program ({err})");
                    continue;
                }
            };
            match xdp.load() {
                Ok(()) => println!("OK   {name}"),
                Err(err) => {
                    failed += 1;
                    println!("FAIL {name}: {err}");
                }
            }
        }
        println!("summary: {} programs, {failed} failed", names.len());
        std::process::exit(if failed > 0 { 1 } else { 0 });
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("xdp-verify only runs on Linux");
        std::process::exit(2);
    }
}
