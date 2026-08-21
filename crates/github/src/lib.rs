// owner: c2-device-flow-auth
//
// c2 also owns the shared authenticated HTTP client that lives at this crate
// root; c3 owns `rest`, and c4 owns `demand` and `jit`.

pub mod demand;
pub mod device_flow;
pub mod jit;
pub mod rest;
