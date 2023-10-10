use aws_sigv4::http_request;
use derive_builder::Builder;
use std::{collections::HashMap, time};

use crate::{
    aws::{
        client::{Client, Credentials, StsClient},
        STS_GET_CALLER_IDENTITY_REQUEST_BODY, STS_REQUEST_METHOD,
    },
    error::{BiminiError, BiminiResult},
    nix::ToEnv,
    BIMINI_USER_AGENT,
};

#[derive(Builder)]
#[builder(build_fn(error = "BiminiError"))]
pub struct AwsClient {
    credentials: Credentials,

    #[builder(default)]
    region: Option<String>,
}

impl Client for AwsClient {
    type Credentials = Credentials;

    fn credentials(&self) -> &Self::Credentials {
        &self.credentials
    }

    fn region(&self) -> Option<&String> {
        self.region.as_ref()
    }

    fn region_mut(&mut self) -> Option<&mut String> {
        self.region.as_mut()
    }

    fn with_region(mut self, region: impl ToString) -> Self {
        self.region = Some(region.to_string());
        self
    }
}

impl StsClient for AwsClient {
    fn get_caller_identity_request(
        &self,
        headers: Option<HashMap<&str, &str>>,
    ) -> BiminiResult<http::Request<&[u8]>> {
        let mut request_builder = http::Request::builder()
            .method(STS_REQUEST_METHOD)
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

        Ok(request_builder.body(STS_GET_CALLER_IDENTITY_REQUEST_BODY.as_slice())?)
    }

    fn sign_request<'a>(
        &'a self,
        mut request: http::Request<&'a [u8]>,
    ) -> BiminiResult<http::Request<&[u8]>> {
        let mut signing_params_builder = http_request::SigningParams::builder()
            .region(self.region.as_ref().unwrap())
            .access_key(&self.credentials().access_key_id)
            .secret_key(&self.credentials().secret_access_key)
            .service_name("sts")
            .time(time::SystemTime::now())
            .settings(http_request::SigningSettings::default());

        if let Some(ref token) = self.credentials().token {
            signing_params_builder = signing_params_builder.security_token(token);
        }

        let signing_params = signing_params_builder.build()?;

        let signable_request = http_request::SignableRequest::from(&request);
        let (signing_instructions, _signature) =
            http_request::sign(signable_request, &signing_params)
                .unwrap()
                .into_parts();

        signing_instructions.apply_to_request(&mut request);

        Ok(request)
    }
}

impl ToEnv for AwsClient {
    fn to_env(&self) -> HashMap<String, String> {
        let mut env = self.credentials().to_env();

        if let Some(ref region) = self.region {
            env.insert("AWS_REGION".to_string(), region.to_string());
        }

        env
    }
}

impl From<Credentials> for AwsClient {
    fn from(value: Credentials) -> Self {
        AwsClient {
            credentials: value,
            region: None,
        }
    }
}
