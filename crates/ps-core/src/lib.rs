//! PortSnatcher core: types, scope enforcement, config, and the frozen `portsnatcher/v1` event schema.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod target;
pub use target::{CidrBlock, Target};

pub mod port;
pub use port::{PortSpec, PortSpecError};
