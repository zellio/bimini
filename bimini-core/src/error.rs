use core::result;
use std::{error, fmt};

#[derive(Debug)]
pub enum BiminiError {
    AwsSigBuild(aws_sigv4::signing_params::BuildError),
    Builder(derive_builder::UninitializedFieldError),
    Env(std::env::VarError),
    Errno(nix::errno::Errno),
    HttpError(http::Error),
    Io(std::io::Error),
    Json(serde_json::Error),
    Unknown(String),
    UreqError(Box<ureq::Error>),
    UrlParseError(url::ParseError),
    Utf8Error(core::str::Utf8Error),
    ProcController(String),
    TryFromIntError(std::num::TryFromIntError),
    ThreadJoin(Box<dyn std::any::Any + Send>),
    VaultCreds(String),
    CertGeneration(String),
}

impl error::Error for BiminiError {}

impl fmt::Display for BiminiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CertGeneration(msg) => write!(f, "Vault cert generation error: {msg}"),
            Self::VaultCreds(msg) => write!(f, "Vault credentials error: {msg}"),
            Self::AwsSigBuild(err) => write!(f, "Failed construting aws sig: {err}"),
            Self::Builder(err) => write!(f, "Derived builder failure: {err}"),
            Self::Env(err) => write!(f, "Env var lookup error: {err}"),
            Self::Errno(err) => write!(f, "{err}"),
            Self::HttpError(err) => write!(f, "Http Encoding error: {err}"),
            Self::Io(err) => write!(f, "Io Error: {err}"),
            Self::Json(err) => write!(f, "Json Serde error: {err}"),
            Self::ProcController(msg) => write!(f, "ProcController error: {msg}"),
            Self::ThreadJoin(_) => write!(f, "Failed joining thread."),
            Self::TryFromIntError(err) => write!(f, "Int conversion error: {err}"),
            Self::Unknown(msg) => write!(f, "Unknown error: {msg}"),
            Self::UreqError(err) => write!(f, "uReq error: {err}"),
            Self::UrlParseError(err) => write!(f, "URL Parser error: {err}"),
            Self::Utf8Error(err) => write!(f, "UTF8 encdoing error: {err}"),
        }
    }
}

pub type BiminiResult<T> = result::Result<T, BiminiError>;

impl From<nix::errno::Errno> for BiminiError {
    fn from(value: nix::errno::Errno) -> Self {
        Self::Errno(value)
    }
}

impl From<std::env::VarError> for BiminiError {
    fn from(value: std::env::VarError) -> Self {
        Self::Env(value)
    }
}

impl From<std::io::Error> for BiminiError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for BiminiError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<derive_builder::UninitializedFieldError> for BiminiError {
    fn from(value: derive_builder::UninitializedFieldError) -> Self {
        Self::Builder(value)
    }
}

impl From<core::str::Utf8Error> for BiminiError {
    fn from(value: core::str::Utf8Error) -> Self {
        Self::Utf8Error(value)
    }
}

impl From<http::Error> for BiminiError {
    fn from(value: http::Error) -> Self {
        Self::HttpError(value)
    }
}

impl From<ureq::Error> for BiminiError {
    fn from(value: ureq::Error) -> Self {
        Self::UreqError(Box::new(value))
    }
}

impl From<aws_sigv4::signing_params::BuildError> for BiminiError {
    fn from(value: aws_sigv4::signing_params::BuildError) -> Self {
        Self::AwsSigBuild(value)
    }
}

impl From<url::ParseError> for BiminiError {
    fn from(value: url::ParseError) -> Self {
        Self::UrlParseError(value)
    }
}

impl From<std::num::TryFromIntError> for BiminiError {
    fn from(value: std::num::TryFromIntError) -> Self {
        Self::TryFromIntError(value)
    }
}

impl From<Box<dyn std::any::Any + Send>> for BiminiError {
    fn from(value: Box<dyn std::any::Any + Send>) -> Self {
        Self::ThreadJoin(value)
    }
}
