pub mod file;
pub mod guard;
pub mod resolver;

pub use file::ScopeFile;
pub use guard::{ScopeGuard, ScopeToken, ScopeViolation};
pub use resolver::{DnsResolver, MonotonicResolver};
