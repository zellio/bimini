pub const STS_REQUEST_METHOD: &str = "POST";

pub const STS_GET_CALLER_IDENTITY_REQUEST_BODY: &[u8; 43] =
    b"Action=GetCallerIdentity&Version=2011-06-15";

mod client;
pub use client::{AwsClient, Client, Credentials, CredentialsBuilder, StsClient};
