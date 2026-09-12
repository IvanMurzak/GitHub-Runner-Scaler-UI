//! Manual cross-boundary acceptance fixture for a disposable WSL distro.

use std::path::PathBuf;

use chrono::Utc;
use runner_manager_platform::wsl::fence::{
    DrainRequest, FenceClaim, FenceOwnerKind, GuestHeartbeat, clear_recovery,
};

fn main() {
    let mut args = std::env::args_os().skip(1);
    let operation = args
        .next()
        .expect("operation")
        .to_string_lossy()
        .into_owned();
    let root = PathBuf::from(args.next().expect("shared root"));
    match operation.as_str() {
        "request" => {
            let generation = generation(&mut args);
            DrainRequest::new(generation, Utc::now())
                .write(&root)
                .expect("write drain request");
        }
        "claim" => {
            let generation = generation(&mut args);
            let claim =
                FenceClaim::try_claim(&root, FenceOwnerKind::WindowsRecovery, Some(generation))
                    .expect("claim recovery fence")
                    .expect("recovery fence is already held");
            claim.make_durable();
        }
        "heartbeat" => {
            let heartbeat = GuestHeartbeat::read(&root)
                .expect("read heartbeat")
                .expect("heartbeat is absent");
            println!("{}", serde_json::to_string_pretty(&heartbeat).unwrap());
        }
        "clear" => clear_recovery(&root, generation(&mut args)).expect("clear recovery"),
        other => panic!("unknown operation {other}"),
    }
}

fn generation(args: &mut impl Iterator<Item = std::ffi::OsString>) -> u64 {
    args.next()
        .expect("generation")
        .to_string_lossy()
        .parse()
        .expect("numeric generation")
}
