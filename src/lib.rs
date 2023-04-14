static BIMINI_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

pub mod aws;
pub mod vault;

mod user_spec;
pub use user_spec::{UserSpec, UserSpecError};

mod spawn_directory;
pub use spawn_directory::SpawnDirectory;
