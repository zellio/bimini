pub trait Client {
    type Credentials;

    fn credentials(&self) -> &Self::Credentials;

    fn region(&self) -> Option<&String>;

    fn region_mut(&mut self) -> Option<&mut String>;

    fn with_region(self, region: impl ToString) -> Self;
}

mod aws_client;
pub use aws_client::*;

mod credentials;
pub use credentials::{Credentials, CredentialsBuilder};

mod sts_client;
pub use sts_client::*;
