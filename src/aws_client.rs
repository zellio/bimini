use anyhow::Result;
use aws_sigv4::http_request;
use builder_pattern::Builder;
use std::collections::HashMap;
use std::time;

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize, Builder)]
#[serde(rename_all(deserialize = "PascalCase"))]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub expiration: Option<String>,
    pub role_arn: Option<String>,
    pub secret_access_key: String,
    pub token: Option<String>,
}

static AWS_CREDENTIALS_IP: &str = "169.254.170.2";

impl AwsCredentials {
    pub fn fetch(url: &str) -> Result<AwsCredentials> {
        Ok(ureq::get(url)
            .set("Accepts", "application/json")
            .call()?
            .into_json()?)
    }

    pub fn lookup(
        relative_url: Option<String>,
        full_url: Option<String>,
    ) -> Option<AwsCredentials> {
        relative_url
            .map(|url| format!("{}{}", AWS_CREDENTIALS_IP, url))
            .or(full_url)
            .map(|url| format!("http://{}", url))
            .map(|url| {
                AwsCredentials::fetch(&url)
                    .map_err(|err| {
                        tracing::error!("Failed to fetch AWS container credentials.");
                        err
                    })
                    .ok()
            })
            .unwrap_or(None)
    }

    pub fn to_client(&self, region: String) -> AwsClient {
        AwsClient::new()
            .region(region)
            .access_key_id(self.access_key_id.clone())
            .secret_access_key(self.secret_access_key.clone())
            .session_token(self.token.clone())
            .build()
    }
}

#[derive(Builder, Debug)]
pub struct AwsClient {
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

impl From<AwsCredentials>
    for AwsClientBuilder<'static, String, (), String, Option<String>, (), ()>
{
    fn from(
        aws_credentials: AwsCredentials,
    ) -> AwsClientBuilder<'static, String, (), String, Option<String>, (), ()> {
        AwsClient::new()
            .access_key_id(aws_credentials.access_key_id.clone())
            .secret_access_key(aws_credentials.secret_access_key.clone())
            .session_token(aws_credentials.token)
    }
}

impl AwsClient {
    pub fn as_env_map(&self) -> HashMap<String, String> {
        HashMap::from([
            (String::from("AWS_REGION"), String::from(&self.region)),
            (
                String::from("AWS_ACCESS_KEY_ID"),
                String::from(&self.access_key_id),
            ),
            (
                String::from("AWS_SECRET_ACCESS_KEY"),
                String::from(&self.access_key_id),
            ),
            (
                String::from("AWS_SESSION_TOKEN"),
                self.session_token
                    .as_ref()
                    .map(String::from)
                    .unwrap_or_else(|| String::from("")),
            ),
        ])
    }

    pub fn sts_signed_request_data(&self, server_id: &str) -> Result<HashMap<&str, String>> {
        tracing::info!("Constructing sts:GetCallerIdentity request.");

        const REQUEST_METHOD: &str = "POST";
        const REQUEST_BODY: &[u8; 43] = b"Action=GetCallerIdentity&Version=2011-06-15";

        let mut request = http::Request::builder()
            .method(REQUEST_METHOD)
            .uri("https://sts.amazonaws.com")
            .header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded;charset=utf-8",
            )
            .header("x-vault-aws-iam-server-id", server_id)
            .body(REQUEST_BODY)
            .map_err(|error| {
                tracing::error!("Failed to construct sts:GetCallerIdentity request - {error}");
                error
            })?;

        tracing::info!("Constructing request signing parameters.");
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

        tracing::info!("Signing sts:GetCallerIdentity request for Vault auth.");
        let signable_request = http_request::SignableRequest::from(&request);
        let (signing_instructions, _signature) =
            http_request::sign(signable_request, &signing_params)
                .unwrap()
                .into_parts();

        signing_instructions.apply_to_request(&mut request);

        Ok(HashMap::from([
            ("iam_http_request_method", String::from(REQUEST_METHOD)),
            (
                "iam_request_url",
                base64::encode(b"https://sts.amazonaws.com"),
            ),
            (
                "iam_request_headers",
                serde_json::to_string(
                    &request
                        .headers()
                        .iter()
                        .map(|(key, val)| {
                            (
                                String::from(key.as_str()),
                                String::from_utf8_lossy(val.clone().as_bytes()).to_string(),
                            )
                        })
                        .collect::<HashMap<String, String>>(),
                )
                .map(base64::encode)?,
            ),
            ("iam_request_body", base64::encode(REQUEST_BODY)),
        ]))
    }
}
