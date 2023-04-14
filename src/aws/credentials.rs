use crate::BIMINI_USER_AGENT;
use anyhow::Result;
use builder_pattern::Builder;

const AWS_CONTAINER_CREDENTIAL_IP: &str = "169.254.170.2";

#[allow(dead_code)]
#[derive(Builder, Debug, serde::Deserialize)]
#[serde(rename_all(deserialize = "PascalCase"))]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,

    #[default(None)]
    pub token: Option<String>,

    #[default(None)]
    pub expiration: Option<String>,

    #[default(None)]
    pub role_arn: Option<String>,
}

impl Credentials {
    fn container_credential_provider_url(
        relative_url: Option<String>,
        full_url: Option<String>,
    ) -> Option<url::Url> {
        relative_url
            .map(|path| format!("http://{AWS_CONTAINER_CREDENTIAL_IP}{path}"))
            .or(full_url)
            .and_then(|url| url::Url::parse(&url).ok())
    }

    fn from_container_credential_provider(url: &url::Url) -> Result<Credentials> {
        Ok(ureq::request_url("GET", url)
            .set("user-agent", BIMINI_USER_AGENT)
            .set("accept", "application/json")
            .call()?
            .into_json()?)
    }

    pub fn from_container_credential_env_vars(
        relative_url: Option<String>,
        full_url: Option<String>,
    ) -> Option<Result<Credentials>> {
        Credentials::container_credential_provider_url(relative_url, full_url)
            .map(|url| Credentials::from_container_credential_provider(&url))
    }
}
