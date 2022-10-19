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
        let headers = self
            .security_header
            .as_ref()
            .map(|sec_header| HashMap::from([("x-vault-aws-iam-server-id", sec_header.as_str())]));

        let signed_request = aws_client
            .sts_get_caller_identity_signed_request(headers)
            .map(|req| aws_client.sign_request(req))??;

        let nonce = uuid::Uuid::new_v4().hyphenated().to_string();
        let iam_request_url = base64::encode(b"https://sts.amazonaws.com");
        let iam_request_headers = serde_json::to_string(
            &signed_request
                .headers()
                .iter()
                .map(|(key, val)| (key.as_str(), val.to_str().unwrap_or("")))
                .collect::<HashMap<&str, &str>>(),
        )
        .map(base64::encode)?;
        let iam_request_body =
            base64::encode(crate::aws_client::STS_GET_CALLER_IDENTITY_REQUEST_BODY);

        let login_data = HashMap::from([
            ("role", role),
            ("nonce", &nonce),
            ("iam_http_request_method", "POST"),
            ("iam_request_url", &iam_request_url),
            ("iam_request_headers", &iam_request_headers),
            ("iam_request_body", &iam_request_body),
        ]);

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
