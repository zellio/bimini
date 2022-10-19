pub mod aws_credentials;

use crate::BIMINI_USER_AGENT;

use anyhow::Result;
use aws_sigv4::http_request;
use builder_pattern::Builder;
use std::collections::HashMap;
use std::time;

const AWS_CONTAINER_CREDENTIAL_IP: &str = "169.254.170.2";
pub const STS_GET_CALLER_IDENTITY_REQUEST_BODY: &[u8; 43] =
    b"Action=GetCallerIdentity&Version=2011-06-15";

#[derive(Builder, Debug)]
pub struct AwsClient {
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,

    #[default(None)]
    pub session_token: Option<String>,
}

impl AwsClient {
    pub fn sts_get_caller_identity_signed_request(
        &self,
        headers: Option<HashMap<&str, &str>>,
    ) -> Result<http::Request<&[u8; 43]>> {
        const REQUEST_METHOD: &str = "POST";

        let mut request_builder = http::Request::builder()
            .method(REQUEST_METHOD)
            .uri("https://sts.amazonaws.com")
            .header(http::header::USER_AGENT, BIMINI_USER_AGENT)
            .header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded;charset=utf-8",
            );

        if let Some(headers) = headers {
            for (header, value) in headers {
                request_builder = request_builder.header(header, value);
            }
        }

        let request = request_builder
            .body(STS_GET_CALLER_IDENTITY_REQUEST_BODY)
            .map_err(|error| {
                tracing::error!("Failed to construct sts:GetCallerIdentity request - {error}");
                error
            })?;

        Ok(request)
    }

    pub fn sign_request<T: std::convert::AsRef<[u8]>>(
        &self,
        mut request: http::Request<T>,
    ) -> Result<http::Request<T>> {
        let mut signing_params_builder = http_request::SigningParams::builder()
            .region(&self.region)
            .access_key(&self.access_key_id)
            .secret_key(&self.secret_access_key)
            .service_name("sts")
            .time(time::SystemTime::now())
            .settings(http_request::SigningSettings::default());

        if let Some(ref token) = self.session_token {
            signing_params_builder = signing_params_builder.security_token(token);
        }

        let signing_params = signing_params_builder.build().map_err(|err| {
            tracing::error!("Failed to construct signing params - {err}");
            err
        })?;

        let signable_request = http_request::SignableRequest::from(&request);
        let (signing_instructions, _signature) =
            http_request::sign(signable_request, &signing_params)
                .unwrap()
                .into_parts();

        signing_instructions.apply_to_request(&mut request);

        Ok(request)
    }

    pub fn as_envs(&self) -> HashMap<&str, &str> {
        let mut envs = HashMap::from([
            ("AWS_REGION", self.region.as_str()),
            ("AWS_ACCESS_KEY_ID", self.access_key_id.as_str()),
            ("AWS_SECRET_ACCESS_KEY", self.secret_access_key.as_str()),
        ]);

        if let Some(token) = &self.session_token {
            envs.insert("AWS_SESSION_TOKEN", token.as_str());
        }

        envs
    }
}
