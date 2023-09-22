use std::{collections::HashMap, time::Duration};

use crate::{
    error::BiminiResult,
    nix::ToEnv,
    vault::client::{engine::Engine, Client, Request, Response, Settings},
    BIMINI_USER_AGENT,
};

#[derive(Clone)]
pub struct VaultClient {
    settings: Settings,
}

impl Client for VaultClient {
    type Settings = Settings;

    fn settings(&self) -> &Self::Settings {
        &self.settings
    }

    fn settings_mut(&mut self) -> &mut Self::Settings {
        &mut self.settings
    }

    fn activate<E>(&self, mount: impl ToString) -> E
    where
        E: Engine + std::convert::From<Self>,
    {
        let mut engine: E = E::from(self.clone());
        *engine.mount_mut() = mount.to_string();
        engine
    }

    fn request<Rq, Rs>(&self, request: Request<Rq>) -> BiminiResult<Response<Rs>>
    where
        Rq: serde::Serialize + Clone,
        Rs: for<'de> serde::Deserialize<'de>,
    {
        let mut url = self.settings().address.clone();
        url.set_path(&request.path);

        let mut http_request = ureq::request_url(&request.method, &url)
            .timeout(Duration::from_secs(self.settings().client_timeout))
            .set("user-agent", BIMINI_USER_AGENT)
            .set("accept", "application/json")
            .set("x-vault-request", "true");

        if let Some(token) = &self.settings().token {
            http_request = http_request.set("x-vault-token", token)
        }

        if let Some(headers) = request.headers {
            for (header, value) in headers {
                http_request = http_request.set(&header, &value);
            }
        };

        let response = if let Some(data) = request.data {
            http_request.send_json(data)?
        } else {
            http_request.call()?
        };

        Ok(response.into_json::<Response<Rs>>()?)
    }
}

impl ToEnv for VaultClient {
    fn to_env(&self) -> HashMap<String, String> {
        self.settings().to_env()
    }
}

impl From<Settings> for VaultClient {
    fn from(value: Settings) -> Self {
        VaultClient { settings: value }
    }
}
