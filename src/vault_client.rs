use crate::aws_client::AwsClient;
use anyhow::Result;
use builder_pattern::Builder;
use std::collections::HashMap;

#[derive(Debug, Builder)]
pub struct VaultClient {
    /// Hashcorp Vault url.
    pub addr: String,

    /// Hashicorp Vault security authorization header.
    #[default(String::from(""))]
    pub security_header: String,

    /// Hashicorp Vault access role.
    pub role: String,

    /// Hashicorp Vault access token.
    pub token: Option<String>,
}

static BIMINI_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
struct VaultAuthAwsLoginResponseAuth {
    renewable: bool,
    lease_duration: u64,
    metadata: HashMap<String, String>,
    policies: Vec<String>,
    accessor: String,
    client_token: String,
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
struct VaultAuthAwsLoginResponse {
    auth: VaultAuthAwsLoginResponseAuth,
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
struct VaultKV2DataGetResponseDataMetadata {
    created_time: String,
    custom_metadata: Option<HashMap<String, String>>,
    deletion_time: String,
    destroyed: bool,
    version: i32,
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
struct VaultKV2DataGetResponseData {
    data: HashMap<String, String>,
    metadata: VaultKV2DataGetResponseDataMetadata,
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
struct VaultKV2DataGetResponse {
    request_id: String,
    data: VaultKV2DataGetResponseData,
}

impl VaultClient {
    fn request(&self, method: &str, url: &str) -> ureq::Request {
        let request = ureq::request(method, url)
            .timeout(std::time::Duration::from_secs(30))
            .set("user-agent", BIMINI_USER_AGENT)
            .set("accept", "application/json")
            .set("x-vault-aws-iam-server-id", &self.security_header);

        if let Some(token) = &self.token {
            request.set("x-vault-token", token)
        } else {
            request
        }
    }

    fn api_get(&self, path: &str) -> Result<ureq::Response, ureq::Error> {
        let url = format!("{}/v1/{}", self.addr, path);
        self.request("GET", &url).call()
    }

    fn api_post(
        &self,
        path: &str,
        json_data: impl serde::Serialize + std::fmt::Debug,
    ) -> Result<ureq::Response, ureq::Error> {
        let url = format!("{}/v1/{}", self.addr, path);
        self.request("POST", &url).send_json(json_data)
    }

    pub fn authenticate(&mut self, aws_client: &AwsClient) -> Result<()> {
        let mut login_data = aws_client.sts_signed_request_data(&self.security_header)?;
        login_data.insert("role", self.role.clone());
        login_data.insert("nonce", uuid::Uuid::new_v4().hyphenated().to_string());

        let auth_log_response: VaultAuthAwsLoginResponse = self
            .api_post("auth/aws/login", &login_data)
            .map_err(|err| {
                tracing::error!("Vault auth request failed - {err}");
                err
            })?
            .into_json()
            .map_err(|err| {
                tracing::error!("Decoding vault aws auth failed. - {err}");
                err
            })?;

        self.token = Some(auth_log_response.auth.client_token);

        Ok(())
    }

    pub fn process_env_map(&self, env: std::env::Vars) -> HashMap<String, String> {
        let mut data_pages = HashMap::<String, Option<VaultKV2DataGetResponse>>::new();

        env.map(|(key, val)| {
            (
                key,
                if val.starts_with("vault:") {
                    let fields: Vec<&str> = val.split(':').collect();
                    let (_, engine, path, key) = (fields[0], fields[1], fields[2], fields[3]);

                    let path = format!("{engine}/data/{path}");
                    let data_page = data_pages.entry(path.clone()).or_insert_with(|| {
                        self.api_get(&path)
                            .map_err(|err| {
                                tracing::error!("Failed fetching vault path - {err}");
                                err
                            })
                            .map(|response| {
                                response
                                    .into_json::<VaultKV2DataGetResponse>()
                                    .map_err(|err| {
                                        tracing::error!("Failed decoding vault data - {err}");
                                        err
                                    })
                                    .ok()
                            })
                            .unwrap_or(None)
                    });

                    if let Some(data_page) = data_page {
                        String::from(data_page.data.data.get(&String::from(key)).unwrap_or(&val))
                    } else {
                        val
                    }
                } else {
                    val
                },
            )
        })
        .collect()
    }
}
