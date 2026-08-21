// owner: d1-platform-core
//
// d1 owns `os`, `paths`, `lock`, `process`, `logging` and this crate root;
// d2 owns `secrets`; d3 owns `service`.

pub mod lock;
pub mod logging;
pub mod os;
pub mod paths;
pub mod process;
pub mod secrets;
pub mod service;
