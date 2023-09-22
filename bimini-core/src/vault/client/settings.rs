use crate::{error::BiminiError, nix::ToEnv};
use derive_builder::Builder;
use std::collections::HashMap;

#[derive(Builder, Debug, Clone)]
#[builder(build_fn(error = "BiminiError"))]
pub struct Settings {
    #[builder(default = "self.default_address()")]
    pub address: url::Url,

    #[builder(default = "self.default_from_env(\"VAULT_TOKEN\")")]
    pub token: Option<String>,

    #[builder(default = "self.default_from_env(\"VAULT_CACERT\")")]
    pub cacert: Option<String>,

    #[builder(default = "self.default_from_env(\"VAULT_CAPATH\")")]
    pub capath: Option<String>,

    #[builder(default = "self.default_from_env(\"VAULT_CLIENT_CERT\")")]
    pub client_cert: Option<String>,

    #[builder(default = "self.default_from_env(\"VAULT_CLIENT_KEY\")")]
    pub client_key: Option<String>,

    #[builder(default = "self.default_client_timeout()")]
    pub client_timeout: u64,

    #[builder(default = "self.default_from_env(\"VAULT_SECURITY_HEADER\")")]
    pub security_header: Option<String>,
}

impl SettingsBuilder {
    fn default_address(&self) -> url::Url {
        url::Url::parse(
            &std::env::var("VAULT_ADDR").unwrap_or_else(|_| "http://localhost:8200".to_string()),
        )
        .unwrap()
    }

    fn default_from_env(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }

    fn default_client_timeout(&self) -> u64 {
        let s = std::env::var("VAULT_CLIENT_TIMEOUT").unwrap_or("60".to_string());
        s.parse().unwrap_or(60)
    }
}

impl ToEnv for Settings {
    fn to_env(&self) -> HashMap<String, String> {
        let mut env = HashMap::from([("VAULT_ADDR".to_string(), format!("{}", self.address))]);

        if let Some(cacert) = &self.cacert {
            env.insert("VAULT_CACERT".into(), String::from(cacert));
        }

        if let Some(capath) = &self.capath {
            env.insert("VAULT_CAPATH".into(), String::from(capath));
        }

        env
    }
}
