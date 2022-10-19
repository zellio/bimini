pub mod auth;
pub mod engine;

use crate::BIMINI_USER_AGENT;
use anyhow::Result;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt::Debug;

#[derive(Debug)]
pub struct VaultApi {
    /// Hashcorp Vault url.
    pub address: url::Url,

    /// Hashicorp Vault security authorization header.
    pub security_header: Option<String>,

    /// Hashicorp Vault access token.
    pub token: Option<String>,
}

impl VaultApi {
    pub fn new(
        address: String,
        security_header: Option<String>,
        token: Option<String>,
    ) -> VaultApi {
        VaultApi {
            address: url::Url::parse(&address).expect("Invalid value for VAULT_ADDR"),
            security_header,
            token,
        }
    }

    pub fn api_url(&self, path: &str) -> url::Url {
        let path = format!("/v1/{}", path);
        let mut url = self.address.clone();
        url.set_path(&path);
        url
    }

    pub fn request(&self, method: &str, path: &str) -> ureq::Request {
        let mut request = ureq::request_url(method, &self.api_url(path))
            .timeout(std::time::Duration::from_secs(30))
            .set("user-agent", BIMINI_USER_AGENT)
            .set("accept", "application/json");

        if let Some(security_header) = &self.security_header {
            request = request.set("x-vault-aws-iam-server-id", security_header);
        }

        if let Some(token) = &self.token {
            request = request.set("x-vault-token", token);
        }

        request
    }

    pub fn post(
        &self,
        path: &str,
        data: &Option<impl Serialize + Debug>,
    ) -> Result<ureq::Response, ureq::Error> {
        let request = self.request("POST", path);

        if let Some(data) = data {
            request.send_json(data)
        } else {
            request.call()
        }
    }

    pub fn get(
        &self,
        path: &str,
        params: &Option<HashMap<String, String>>,
    ) -> Result<ureq::Response, ureq::Error> {
        let mut request = self.request("GET", path);

        if let Some(params) = params {
            for (key, value) in params.into_iter() {
                request = request.query(key, value);
            }
        }

        request.call()
    }
}
