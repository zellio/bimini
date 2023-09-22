use std::collections::HashMap;

use crate::{
    error::{BiminiError, BiminiResult},
    nix::ToEnv,
    BIMINI_USER_AGENT,
};

const AWS_CONTAINER_CREDENTIAL_IP: &str = "169.254.170.2";
use derive_builder::Builder;
use serde::Deserialize;

#[allow(dead_code)]
#[derive(Builder, Debug, Deserialize, Clone)]
#[builder(build_fn(error = "BiminiError"))]
#[serde(rename_all(deserialize = "PascalCase"))]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,

    #[builder(default = "None")]
    pub token: Option<String>,

    #[builder(default = "None")]
    pub expiration: Option<String>,

    #[builder(default = "None")]
    pub role_arn: Option<String>,
}

impl Credentials {
    pub fn from_url(value: &url::Url) -> BiminiResult<Self> {
        Ok(ureq::request_url("GET", value)
            .set("user-agent", BIMINI_USER_AGENT)
            .set("accept", "application/json")
            .call()?
            .into_json()?)
    }

    pub fn from_url_path(path: &str) -> BiminiResult<Self> {
        Credentials::from_url(&url::Url::parse(&format!(
            "http://{AWS_CONTAINER_CREDENTIAL_IP}{path}"
        ))?)
    }

    pub fn from_env() -> BiminiResult<Self> {
        Ok(CredentialsBuilder::default()
            .access_key_id(std::env::var("AWS_ACCESS_KEY_ID")?)
            .secret_access_key(std::env::var("AWS_SECRET_ACCESS_KEY")?)
            .token(std::env::var("AWS_SESSION_TOKEN").ok())
            .build()?)
    }
}

impl ToEnv for Credentials {
    fn to_env(&self) -> std::collections::HashMap<String, String> {
        let mut env = HashMap::from([
            ("AWS_ACCESS_KEY_ID".to_string(), self.access_key_id.clone()),
            (
                "AWS_SECRET_ACCESS_KEY".to_string(),
                self.secret_access_key.clone(),
            ),
        ]);

        if let Some(ref token) = self.token {
            env.insert("AWS_SESSION_TOKEN".to_string(), token.to_string());
        }

        if let Some(ref expiration) = self.expiration {
            env.insert("AWS_SESSION_EXPIRATION".to_string(), expiration.to_string());
        }

        env
    }
}
