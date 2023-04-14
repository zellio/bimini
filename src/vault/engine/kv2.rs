use crate::vault::Client;
use anyhow::Result;
use std::collections::HashMap;

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
pub struct Kv2GetResponseDataMetadata {
    pub created_time: String,
    pub custom_metadata: Option<HashMap<String, String>>,
    pub deletion_time: String,
    pub destroyed: bool,
    pub version: i32,
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
pub struct Kv2GetResponseData {
    pub data: HashMap<String, String>,
    pub metadata: Kv2GetResponseDataMetadata,
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
pub struct Kv2GetResponse {
    pub request_id: String,
    pub data: Kv2GetResponseData,
}

impl Client {
    pub fn kv2_get(
        &self,
        engine: &str,
        path: &str,
        version: Option<i32>,
    ) -> Result<Kv2GetResponse> {
        let path = format!("{engine}/data/{path}");
        self.get(
            &path,
            &version.map(|version| HashMap::from([(String::from("version"), version.to_string())])),
        )?
        .into_json()
        .map_err(|err| err.into())
    }

    pub fn kv2_get_field(
        &self,
        engine: &str,
        path: &str,
        field: &str,
        version: Option<i32>,
    ) -> Result<Option<String>> {
        self.kv2_get(engine, path, version).map(|json| {
            let key = String::from(field);
            if json.data.data.contains_key(&key) {
                Some(json.data.data.get(&key).map(String::from).unwrap())
            } else {
                None
            }
        })
    }
}
