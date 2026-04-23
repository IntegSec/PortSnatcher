//! PortSnatcher core: types, scope enforcement, config, and the frozen `portsnatcher/v1` event schema.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod target;
pub use target::{CidrBlock, Target};

pub mod port;
pub use port::{PortSpec, PortSpecError};

pub mod profile;
pub use profile::{Profile, ProfileDefaults};

pub mod technique;
pub use technique::TechniqueTag;

pub mod id;
pub use id::{CatchId, EngagementId, EventId};

pub mod event;
pub use event::{Event, SCHEMA as EVENT_SCHEMA};
