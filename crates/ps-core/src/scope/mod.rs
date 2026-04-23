pub mod file;
pub mod guard;

pub use file::ScopeFile;
pub use guard::{ScopeGuard, ScopeToken, ScopeViolation};
