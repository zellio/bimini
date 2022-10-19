use crate::aws_client::{AwsClient, AWS_CONTAINER_CREDENTIAL_IP};
use crate::BIMINI_USER_AGENT;
use anyhow::Result;
use builder_pattern::Builder;

#[allow(dead_code)]
#[derive(Builder, Debug, serde::Deserialize)]
#[serde(rename_all(deserialize = "PascalCase"))]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,

    #[default(None)]
    pub token: Option<String>,

    #[default(None)]
    pub expiration: Option<String>,

    #[default(None)]
    pub role_arn: Option<String>,
}

impl AwsCredentials {
    fn container_credential_provider_url(
        relative_url: Option<String>,
        full_url: Option<String>,
    ) -> Option<url::Url> {
        relative_url
            .map(|path| format!("http://{}{}", AWS_CONTAINER_CREDENTIAL_IP, path))
            .or(full_url)
            .map(|url| url::Url::parse(&url).ok())
            .unwrap_or(None)
    }

    fn from_container_credential_provider(url: &url::Url) -> Result<AwsCredentials> {
        Ok(ureq::request_url("GET", url)
            .set("user-agent", BIMINI_USER_AGENT)
            .set("accept", "application/json")
            .call()?
            .into_json()?)
    }

    pub fn from_container_credential_env_vars(
        relative_url: Option<String>,
        full_url: Option<String>,
    ) -> Option<Result<AwsCredentials>> {
        AwsCredentials::container_credential_provider_url(relative_url, full_url)
            .map(|url| AwsCredentials::from_container_credential_provider(&url))
    }

    pub fn to_client(&self, region: String) -> AwsClient {
        let token = if let Some(token) = &self.token {
            Some(String::from(token))
        } else {
            None
        };

        AwsClient {
            region,
            access_key_id: self.access_key_id.clone(),
            secret_access_key: self.secret_access_key.clone(),
            session_token: token,
        }
    }
}
