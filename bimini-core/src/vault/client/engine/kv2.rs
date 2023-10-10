use std::collections::HashMap;

use crate::{
    error::BiminiResult,
    vault::client::{Engine, VaultClient},
};

#[derive(serde::Deserialize)]
pub struct Kv2ReadResponse {
    pub data: HashMap<String, String>,
}

#[bimini_macros::vault_engine(client = VaultClient, subpath = "data")]
pub struct Kv2Engine;

impl Kv2Engine {
    pub fn get_page(&self, path: &str) -> BiminiResult<Kv2ReadResponse> {
        let page: super::Response<Kv2ReadResponse> = Engine::get(self, path)?;
        Ok(page.data)
    }

    pub fn get_field(&self, path: &str, field: &str) -> BiminiResult<Option<String>> {
        let page: super::Response<Kv2ReadResponse> = Engine::get(self, path)?;
        Ok(page.data.data.get(field).map(String::from))
    }
}
