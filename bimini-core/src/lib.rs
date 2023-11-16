const PKG_NAME: &str = env!("CARGO_PKG_NAME");
const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

const BIMINI_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

pub mod aws;
pub mod error;
pub mod nix;
pub mod proc;
pub mod vault;

// pub use child::{Child, ChildBuilder};
// pub use ProcController;
