use crate::BIMINI_USER_AGENT;
use anyhow::Result;
use builder_pattern::Builder;
use serde::Serialize;
use std::boxed::Box;
use std::collections::HashMap;
use std::fmt::Debug;

#[derive(Builder, Debug)]
pub struct Client {
    /// Hashcorp Vault url.
    pub address: url::Url,

    /// Hashicorp Vault security authorization header.
    pub security_header: Option<String>,

    /// Hashicorp Vault access token.
    pub token: Option<String>,
}

impl Client {
    pub fn api_url(&self, path: &str) -> url::Url {
        let path = format!("/v1/{path}");
        let mut url = self.address.clone();
        url.set_path(&path);
        url
    }

    pub fn request(&self, method: &str, path: &str) -> ureq::Request {
        let mut request = ureq::request_url(method, &self.api_url(path))
            .timeout(std::time::Duration::from_secs(30))
            .set("user-agent", BIMINI_USER_AGENT)
            .set("accept", "application/json")
            .set("x-vault-request", "true");

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
    ) -> Result<ureq::Response, Box<ureq::Error>> {
        let request = self.request("POST", path);

        if let Some(data) = data {
            request.send_json(data).map_err(Box::new)
        } else {
            request.call().map_err(Box::new)
        }
    }

    pub fn get(
        &self,
        path: &str,
        params: &Option<HashMap<String, String>>,
    ) -> Result<ureq::Response, Box<ureq::Error>> {
        let mut request = self.request("GET", path);

        if let Some(params) = params {
            for (key, value) in params.iter() {
                request = request.query(key, value);
            }
        }

        request.call().map_err(Box::new)
    }
}
