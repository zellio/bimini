use crate::{
    aws::{AwsClient, StsClient, STS_GET_CALLER_IDENTITY_REQUEST_BODY, STS_REQUEST_METHOD},
    error::BiminiResult,
    vault::client::{
        engine::{auth::AuthEngine, Engine},
        Client, Response, VaultClient,
    },
};

use std::collections::HashMap;

use base64::{engine::general_purpose, Engine as _};

#[bimini_macros::vault_engine(client = VaultClient, subpath = "aws")]
pub struct AwsIamAuthEngine;

impl AuthEngine for AwsIamAuthEngine {}

impl AwsIamAuthEngine {
    #[tracing::instrument(skip_all)]
    pub fn login(
        &self,
        role: &str,
        aws_client: &AwsClient,
    ) -> BiminiResult<Response<serde_json::Value>> {
        let headers = self
            .client
            .settings()
            .security_header
            .as_ref()
            .map(|security_header| {
                HashMap::from([("x-vault-aws-iam-server-id", security_header.as_str())])
            });

        let signed_request = aws_client.signed_get_caller_identity_request(headers)?;
        let nonce = uuid::Uuid::new_v4().hyphenated().to_string();
        let iam_request_url = general_purpose::STANDARD.encode(b"https://sts.amazonaws.com");
        let iam_request_headers = serde_json::to_string(
            &signed_request
                .headers()
                .iter()
                .map(|(key, val)| (key.as_str(), val.to_str().unwrap_or("")))
                .collect::<HashMap<&str, &str>>(),
        )
        .map(|s| general_purpose::STANDARD.encode(s))?;
        let iam_request_body =
            general_purpose::STANDARD.encode(STS_GET_CALLER_IDENTITY_REQUEST_BODY);

        let request = HashMap::from([
            ("role", role),
            ("nonce", &nonce),
            ("iam_http_request_method", STS_REQUEST_METHOD),
            ("iam_request_url", &iam_request_url),
            ("iam_request_headers", &iam_request_headers),
            ("iam_request_body", &iam_request_body),
        ]);

        AuthEngine::post_login(self, request)
    }
}
