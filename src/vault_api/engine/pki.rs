use crate::vault_api::VaultApi;
use anyhow::Result;
use builder_pattern::Builder;

#[allow(dead_code)]
#[derive(Builder, Debug, serde::Deserialize, serde::Serialize)]
pub struct PkiIssueRequest {
    /// Specifies the requested CN for the certificate. If the CN is allowed
    /// by role policy, it will be issued. If more than one common_name is
    /// desired, specify the alternative names in the alt_names list.
    pub common_name: String,

    /// Specifies the requested CN for the certificate. If the CN is allowed
    /// by role policy, it will be issued. If more than one common_name is
    /// desired, specify the alternative names in the alt_names list
    #[default(None)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_names: Option<String>,

    /// Specifies requested Subject Alternative Names, in a comma-delimited
    /// list. These can be host names or email addresses; they will be parsed
    /// into their respective fields. If any requested names do not match role
    /// policy, the entire request will be denied.
    #[default(None)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_sans: Option<String>,

    /// Specifies requested IP Subject Alternative Names, in a comma-delimited
    /// list. Only valid if the role allows IP SANs (which is the default).
    #[default(None)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri_sans: Option<String>,

    /// Specifies the requested URI Subject Alternative Names, in a
    /// comma-delimited list. If any requested URIs do not match role policy,
    /// the entire request will be denied
    #[default(None)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_sans: Option<String>,

    /// Specifies requested Time To Live. Cannot be greater than the role's
    /// max_ttl value. If not provided, the role's ttl value will be
    /// used. Note that the role values default to system values if not
    /// explicitly set. See not_after as an alternative for setting an
    /// absolute end date (rather than a relative one).
    #[default(None)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,

    /// Specifies the format for returned data. Can be pem, der, or
    /// pem_bundle; defaults to pem. If der, the output is base64 encoded. If
    /// pem_bundle, the certificate field will contain the private key and
    /// certificate, concatenated; if the issuing CA is not a Vault-derived
    /// self-signed root, this will be included as well.
    #[default(None)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    /// Specifies the format for marshaling the private key within the
    /// private_key response field. Defaults to der which will return either
    /// base64-encoded DER or PEM-encoded DER, depending on the value of
    /// format. The other option is pkcs8 which will return the key marshalled
    /// as PEM-encoded PKCS8.
    #[default(None)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_format: Option<String>,

    /// If true, the given common_name will not be included in DNS or Email
    /// Subject Alternate Names (as appropriate). Useful if the CN is not a
    /// hostname or email address, but is instead some human-readable
    /// identifier.
    #[default(None)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_cn_from_sans: Option<bool>,

    /// Set the Not After field of the certificate with specified date
    /// value. The value format should be given in UTC format
    /// YYYY-MM-ddTHH:MM:SSZ. Supports the Y10K end date for IEEE 802.1AR-2018
    /// standard devices, 9999-12-31T23:59:59Z.
    #[default(None)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
pub struct PkiIssueResponseData {
    pub ca_chain: Vec<String>,
    pub certificate: String,
    pub expiration: u64,
    pub issuing_ca: String,
    pub private_key: String,
    pub private_key_type: String,
    pub serial_number: String,
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
pub struct PkiIssueResponse {
    pub data: PkiIssueResponseData,
    pub lease_duration: u64,
    pub lease_id: String,
    pub renewable: bool,
    pub request_id: String,
    pub warnings: Option<String>,
}

impl VaultApi {
    pub fn pki_issue(
        &self,
        engine: &str,
        role: &str,
        request: &PkiIssueRequest,
    ) -> Result<PkiIssueResponse> {
        let path = format!("{}/issue/{}", engine, role);
        self.post(&path, &Some(request))?
            .into_json()
            .map_err(|err| err.into())
    }
}
