use crate::{
    error::{BiminiError, BiminiResult},
    vault::client::{engine::Engine, Response, VaultClient},
    PKG_NAME,
};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use std::path;

#[allow(dead_code)]
#[derive(Builder, Debug, Deserialize, Serialize)]
#[builder(build_fn(error = "BiminiError"))]
pub struct PkiIssueRequest {
    /// Specifies the requested CN for the certificate. If the CN is allowed
    /// by role policy, it will be issued. If more than one common_name is
    /// desired, specify the alternative names in the alt_names list.
    pub common_name: String,

    /// Specifies the requested CN for the certificate. If the CN is allowed
    /// by role policy, it will be issued. If more than one common_name is
    /// desired, specify the alternative names in the alt_names list
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_names: Option<String>,

    /// Specifies requested Subject Alternative Names, in a comma-delimited
    /// list. These can be host names or email addresses; they will be parsed
    /// into their respective fields. If any requested names do not match role
    /// policy, the entire request will be denied.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_sans: Option<String>,

    /// Specifies requested IP Subject Alternative Names, in a comma-delimited
    /// list. Only valid if the role allows IP SANs (which is the default).
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri_sans: Option<String>,

    /// Specifies the requested URI Subject Alternative Names, in a
    /// comma-delimited list. If any requested URIs do not match role policy,
    /// the entire request will be denied
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_sans: Option<String>,

    /// Specifies requested Time To Live. Cannot be greater than the role's
    /// max_ttl value. If not provided, the role's ttl value will be
    /// used. Note that the role values default to system values if not
    /// explicitly set. See not_after as an alternative for setting an
    /// absolute end date (rather than a relative one).
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,

    /// Specifies the format for returned data. Can be pem, der, or
    /// pem_bundle; defaults to pem. If der, the output is base64 encoded. If
    /// pem_bundle, the certificate field will contain the private key and
    /// certificate, concatenated; if the issuing CA is not a Vault-derived
    /// self-signed root, this will be included as well.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    /// Specifies the format for marshaling the private key within the
    /// private_key response field. Defaults to der which will return either
    /// base64-encoded DER or PEM-encoded DER, depending on the value of
    /// format. The other option is pkcs8 which will return the key marshalled
    /// as PEM-encoded PKCS8.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_format: Option<String>,

    /// If true, the given common_name will not be included in DNS or Email
    /// Subject Alternate Names (as appropriate). Useful if the CN is not a
    /// hostname or email address, but is instead some human-readable
    /// identifier.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_cn_from_sans: Option<bool>,

    /// Set the Not After field of the certificate with specified date
    /// value. The value format should be given in UTC format
    /// YYYY-MM-ddTHH:MM:SSZ. Supports the Y10K end date for IEEE 802.1AR-2018
    /// standard devices, 9999-12-31T23:59:59Z.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct PkiIssueResponseData {
    pub ca_chain: Vec<String>,
    pub certificate: String,
    pub expiration: u64,
    pub issuing_ca: String,
    pub private_key: String,
    pub private_key_type: String,
    pub serial_number: String,
}

#[bimini_macros::vault_engine(client = VaultClient)]
pub struct PkiEngine;

impl PkiEngine {
    pub fn issue(
        &self,
        role: &str,
        request: &PkiIssueRequest,
    ) -> BiminiResult<Response<PkiIssueResponseData>> {
        super::Engine::post(self, &format!("issue/{role}"), request)
    }

    pub fn generate_cert(&self, role: &str, request: &PkiIssueRequest) -> BiminiResult<()> {
        let response = self.issue(role, request)?;

        let ssl_path = path::Path::new("/opt").join(PKG_NAME).join("ssl");
        let ssl_private_path = ssl_path.join("private");
        let ssl_certs_path = ssl_path.join("certs");

        std::fs::create_dir_all(&ssl_path)?;
        std::fs::create_dir_all(&ssl_private_path)?;
        std::fs::create_dir_all(&ssl_certs_path)?;

        let key_format = if let Some(private_key_format) = request.private_key_format.as_ref() {
            String::from(private_key_format)
        } else {
            String::from("der")
        };

        let cert_format = if let Some(format) = request.format.as_ref() {
            String::from(format)
        } else {
            String::from("pem")
        };

        let mut ssl_private_key_path = ssl_private_path.join("key");
        ssl_private_key_path.set_extension(&key_format);
        std::fs::write(
            &ssl_private_key_path,
            format!("{}\n", &response.data.private_key),
        )?;

        let mut ssl_cert_path = ssl_certs_path.join("certificate");
        ssl_cert_path.set_extension(&cert_format);
        std::fs::write(&ssl_cert_path, format!("{}\n", &response.data.certificate))?;

        let mut ssl_ca_cert_path = ssl_certs_path.join("issuing-ca");
        ssl_ca_cert_path.set_extension(&cert_format);
        std::fs::write(
            &ssl_ca_cert_path,
            format!("{}\n", &response.data.certificate),
        )?;

        let mut ssl_ca_chain_path = ssl_certs_path.join("ca-chain");
        ssl_ca_chain_path.set_extension(&cert_format);
        std::fs::write(
            &ssl_ca_chain_path,
            format!("{}\n", &response.data.ca_chain.join("\n")),
        )?;

        Ok(())
    }
}
