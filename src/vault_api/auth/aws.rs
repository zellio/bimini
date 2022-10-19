use crate::aws_client::AwsClient;
use crate::vault_api::VaultApi;
use anyhow::Result;
use std::collections::HashMap;

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
pub struct AuthAwsResponseAuth {
    pub renewable: bool,
    pub lease_duration: u64,
    pub metadata: HashMap<String, String>,
    pub policies: Vec<String>,
    pub accessor: String,
    pub client_token: String,
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
pub struct AuthAwsResponse {
    pub auth: AuthAwsResponseAuth,
}

impl VaultApi {
    pub fn auth_aws_login(&mut self, role: &str, aws_client: &AwsClient) -> Result<()> {
        let mut login_data = aws_client.sts_signed_request_data(self.security_header.as_ref())?;
        login_data.insert("role", String::from(role));
        login_data.insert("nonce", uuid::Uuid::new_v4().hyphenated().to_string());

        let response = self
            .post("auth/aws/login", &Some(login_data))
            .map_err(|err| {
                tracing::error!("Vault AWS Auth request failed - {err}");
                err
            })?
            .into_json::<AuthAwsResponse>()
            .map_err(|err| {
                tracing::error!("Vault AWS Auth response parsing failed - {err}");
                err
            })?;

        self.token = Some(response.auth.client_token);

        Ok(())
    }
}
