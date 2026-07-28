use valv::chacha;

fn main() {
    let token = chacha!("VALV_AUDIT_TOKEN: offline-recovery-check-2026-07-26");
    let digest = token.with_bytes(|bytes| {
        if std::env::var_os("VALV_DEBUGGER_PAUSE").is_some() {
            std::thread::sleep(std::time::Duration::from_secs(30));
        }

        bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |acc, byte| {
            (acc ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
    });

    println!("probe_digest={digest:016x}");
}
