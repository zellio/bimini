use bimini_core::{
    aws::{self, AwsClient, Client as AwsClientTrait},
    error::{BiminiError, BiminiResult},
    nix::UserSpec,
    proc,
    vault::{
        self,
        engine::{auth::AwsIamAuthEngine, PkiEngine, PkiIssueRequest},
        Client as VaultClientTrait, VaultClient,
    },
};
use clap::{builder::ArgPredicate, Parser};
use std::{path::PathBuf, process, str::FromStr};
use tracing_subscriber::{filter::LevelFilter, prelude::*, Registry};

#[derive(clap::ValueEnum, Clone, Debug)]
enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Off,
}

impl From<&LogLevel> for LevelFilter {
    fn from(value: &LogLevel) -> Self {
        match value {
            LogLevel::Trace => Self::TRACE,
            LogLevel::Debug => Self::DEBUG,
            LogLevel::Info => Self::INFO,
            LogLevel::Warn => Self::WARN,
            LogLevel::Error => Self::ERROR,
            LogLevel::Off => Self::OFF,
        }
    }
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum LogFormat {
    Auto,
    Plain,
    Pretty,
    Json,
}

#[derive(clap::Parser, Debug)]
#[command(author, version)]
struct CliArgs {
    /// Log level
    #[clap(
        long,
        value_enum,
        default_value_t = LogLevel::Info,
        env("BIMINI_LOG_LEVEL"),
    )]
    log_level: LogLevel,

    /// Log format
    #[clap(
        long,
        value_enum,
        default_value_t = LogFormat::Auto,
        env("BIMINI_LOG_FORMAT"),
    )]
    log_format: LogFormat,

    /// Userspec for owner of child process.
    #[clap(help_heading("Child Spawn"), long("spawn-as"), env("BIMINI_SPAWN_AS"))]
    spawn_userspec: Option<String>,

    /// Directory to spawn child process in (will fallback to spawn_as HOME)
    #[clap(
        help_heading("Child Spawn"),
        long("spawn-directory"),
        env("BIMINI_SPAWN_DIRECTORY")
    )]
    spawn_directory: Option<PathBuf>,

    /// Enable Amazon Web Services client.
    #[clap(
        help_heading("Features"),
        long,
        default_value_t = false,
        env("BIMINI_ENABLE_AWS_CLIENT"),
        groups(["aws-env-provider"]),
        requires("aws-cred-provider"),
    )]
    enable_aws_client: bool,

    /// Disable Amazon Web Services client.
    #[clap(
        help_heading("AWS Client"),
        hide(true),
        long,
        default_value_t = true,
        default_value_if("enable_aws_client", ArgPredicate::Equals("true".into()), "false"),
        overrides_with("enable_aws_client"),
        env("BIMINI_DISABLE_AWS_CLIENT"),
    )]
    _disable_aws_client: bool,

    /// AWS Region for for Hashicorp Vault RBAC auth
    #[clap(
        help_heading("AWS Client"),
        long,
        env,
        required_if_eq("enable_aws_client", "true")
    )]
    aws_region: Option<String>,

    /// AWS credentials URI path for Hashicorp Vault RBAC auth
    #[clap(
        help_heading("AWS Client"),
        long,
        env,
        groups(["aws-cred-provider"]),
    )]
    aws_container_credentials_relative_uri: Option<String>,

    /// AWS credentials URI for Hashicorp Vault RBAC auth
    #[clap(
        help_heading("AWS Client"),
        long,
        env,
        groups(["aws-cred-provider"]),
        overrides_with("aws_container_credentials_relative_uri"),
    )]
    aws_container_credentials_full_uri: Option<url::Url>,

    /// AWS access key for Hashicorp Vault RBAC auth
    #[clap(
        help_heading("AWS Client"),
        long,
        env,
        groups(["aws-cred-provider"]),
        requires("aws_secret_access_key"),
    )]
    aws_access_key_id: Option<String>,

    /// AWS secret key for Hashicorp Vault RBAC auth
    #[clap(help_heading("AWS Client"), long, env, requires("aws_access_key_id"))]
    aws_secret_access_key: Option<String>,

    /// AWS session token for Hashicorp Vault RBAC auth
    #[clap(
        help_heading("AWS Client"),
        long,
        env,
        requires("aws_access_key_id"),
        requires("aws_secret_access_key")
    )]
    aws_session_token: Option<String>,

    /// Enable AWS credentials injection into spawn environment
    #[clap(
        help_heading("Features"),
        long,
        env("BIMINI_ENABLE_AWS_CREDS_ENV_INJECTION"),
        default_value_t = false,
        requires("aws-env-provider")
    )]
    enable_aws_creds_env_injection: bool,

    /// Disable AWS credentials injection into spawn environment
    #[clap(
        help_heading("AWS Client"),
        hide(true),
        long,
        default_value_t = true,
        default_value_if("enable_aws_creds_env_injection", ArgPredicate::Equals("true".into()), "false"),
        overrides_with("enable_aws_creds_env_injection"),
        env("BIMINI_DISABLE_AWS_CREDS_ENV_INJECTION"),
    )]
    _disable_aws_creds_env_injection: bool,

    /// Enable Hashicorp Vault client
    #[clap(
        help_heading("Features"),
        long,
        default_value_t = false,
        env("BIMINI_ENABLE_VAULT_CLIENT"),
        requires("vault_addr"),
        requires("vault-creds-provider")
    )]
    enable_vault_client: bool,

    /// Disable Hashicorp Vault client
    #[clap(
        help_heading("Vault Client"),
        hide(true),
        long,
        default_value_t = true,
        default_value_if("enable_vault_client", ArgPredicate::Equals("true".into()), "false"),
        overrides_with("enable_vault_client"),
        env("BIMINI_DISABLE_VAULT_CLIENT")
    )]
    _disable_vault_client: bool,

    /// Fully qualified domain of the Hashicorp Vault server
    #[clap(help_heading("Vault Client"), long, env)]
    vault_addr: Option<url::Url>,

    /// Vault authentication token.
    #[clap(
        help_heading("Vault Client"),
        long,
        env,
        groups(["vault-creds-provider"])
    )]
    vault_token: Option<String>,

    /// Vault authentication role.
    #[clap(
        help_heading("Vault Client"),
        long,
        env,
        groups(["vault-creds-provider"]),
        requires("vault_addr")
    )]
    vault_role: Option<String>,

    /// Path to a PEM-encoded CA certificate file on the local disk. This file
    /// is used to verify the Vault server's SSL certificate. This environment
    /// variable takes precedence over VAULT_CAPATH.
    #[clap(
        help_heading("Vault Client"),
        long,
        env,
        requires("vault_addr"), groups(["vault-ca-provider"])
    )]
    vault_cacert: Option<String>,

    /// Path to a directory of PEM-encoded CA certificate files on the local
    /// disk. These certificates are used to verify the Vault server's SSL
    /// certificate.
    #[clap(
        help_heading("Vault Client"),
        long,
        env,
        requires("vault_addr"),
        groups(["vault-ca-provider"])
    )]
    vault_capath: Option<String>,

    /// Path to a PEM-encoded client certificate on the local disk. This file
    /// is used for TLS communication with the Vault server.
    #[clap(
        help_heading("Vault Client"),
        long,
        env,
        requires("vault_addr"),
        requires("vault_client_key")
    )]
    vault_client_cert: Option<String>,

    /// Path to an unencrypted, PEM-encoded private key on disk which
    /// corresponds to the matching client certificate.
    #[clap(help_heading("Vault Client"), long, env, requires("vault_addr"))]
    vault_client_key: Option<String>,

    /// Vault API timeout variable. The default value is 60s.
    #[clap(
        help_heading("Vault Client"),
        long,
        env,
        default_value = "60",
        requires("vault_addr")
    )]
    vault_client_timeout: Option<u64>,

    /// X-Vault-AWS-IAM-Server-ID value
    #[clap(help_heading("Vault Client"), long, env, requires("vault_addr"))]
    vault_security_header: Option<String>,

    /// Enable SSL certificate generation via Hashicorp Vault
    #[clap(
        help_heading("Features"),
        long,
        default_value_t = false,
        env("BIMINI_ENABLE_VAULT_CERT_GENERATION"),
        requires("vault-creds-provider"),
        requires("vault_addr"),
        requires("vault_cert_role"),
        requires("vault_cert_request")
    )]
    enable_vault_cert_generation: bool,

    /// Disable SSL certificate generation via Hashicorp Vault
    #[clap(
        hide(true),
        long,
        default_value_t = true,
        default_value_if("enable_vault_cert_generation", ArgPredicate::Equals("true".into()), "false"),
        overrides_with("enable_vault_cert_generation"),
        env("BIMINI_DISABLE_VAULT_CERT_GENERATION")
    )]
    _disable_vault_cert_generation: bool,

    /// Hashicorp Vault pki engine name
    #[clap(
        help_heading("Vault Cert Generation"),
        long,
        env,
        default_value = "pki"
    )]
    vault_cert_engine: String,

    /// Hashicorp Vault pki role name
    #[clap(help_heading("Vault Cert Generation"), long, env)]
    vault_cert_role: Option<String>,

    /// Hashicorp Vault pki certificate request
    #[clap(help_heading("Vault Cert Generation"), long, env)]
    vault_cert_request: Option<String>,

    /// Program to spawn and track.
    #[clap()]
    command: String,

    /// Arguments to pass to child program.
    #[clap()]
    args: Vec<String>,
}

#[tracing::instrument(skip_all)]
fn find_aws_credentials(cli_args: &CliArgs) -> BiminiResult<Option<aws::Credentials>> {
    if let Some(ref path) = cli_args.aws_container_credentials_relative_uri {
        tracing::info!("Using AWS credentials from auth provider: {path}");
        aws::Credentials::from_url_path(path).map(Some)
    } else if let Some(ref url) = cli_args.aws_container_credentials_full_uri {
        tracing::info!("Using AWS credentials from auth provider: {url}");
        aws::Credentials::from_url(url).map(Some)
    } else if cli_args.aws_access_key_id.is_some() && cli_args.aws_secret_access_key.is_some() {
        tracing::info!("Using provided AWS IAM credentials.");
        aws::CredentialsBuilder::default()
            .access_key_id(cli_args.aws_access_key_id.clone().unwrap())
            .secret_access_key(cli_args.aws_secret_access_key.clone().unwrap())
            .token(cli_args.aws_session_token.clone())
            .build()
            .map(Some)
    } else {
        Ok(None)
    }
}

#[tracing::instrument(skip_all)]
fn find_vault_settings(
    cli_args: &CliArgs,
    aws_client: Option<&AwsClient>,
) -> BiminiResult<Option<vault::Settings>> {
    if cli_args.vault_token.is_none() && aws_client.is_none() {
        return Err(BiminiError::VaultCreds(
            "Either a vault token or AWS credentials are required.".to_string(),
        ));
    }

    let mut settings = vault::SettingsBuilder::default()
        .address(cli_args.vault_addr.clone().unwrap())
        .token(cli_args.vault_token.as_ref().cloned())
        .cacert(cli_args.vault_cacert.as_ref().cloned())
        .capath(cli_args.vault_capath.as_ref().cloned())
        .client_cert(cli_args.vault_client_cert.as_ref().cloned())
        .client_key(cli_args.vault_client_key.as_ref().cloned())
        .client_timeout(cli_args.vault_client_timeout.unwrap())
        .security_header(cli_args.vault_security_header.as_ref().cloned())
        .build()?;

    if settings.token.is_none() {
        tracing::info!("Not Vault token found, authenticating to Vault via AWS Credentials.");
        let client = VaultClient::from(settings.clone());
        let auth = client.activate::<AwsIamAuthEngine>("auth");
        let login_response = auth.login(
            cli_args.vault_role.as_ref().unwrap(),
            aws_client.as_ref().unwrap(),
        )?;
        settings.token = login_response.auth.map(|auth| auth.client_token);
    }

    Ok(Some(settings))
}

#[tracing::instrument(skip_all)]
fn generate_vault_certs(
    vault_client: Option<&VaultClient>,
    pki_engine_mount: &str,
    vault_role: Option<&String>,
    request: Option<&String>,
) -> BiminiResult<()> {
    let vault_pki = vault_client
        .as_ref()
        .map(|vc| vc.activate::<PkiEngine>(pki_engine_mount))
        .ok_or(BiminiError::CertGeneration(
            "Missing vault pki engine".to_string(),
        ))?;

    let request_json = request
        .map(|r| serde_json::from_str::<PkiIssueRequest>(r))
        .ok_or(BiminiError::CertGeneration(
            "Missing vault pki request".to_string(),
        ))??;

    vault_pki.generate_cert(
        vault_role.ok_or(BiminiError::CertGeneration(
            "Missing vault role".to_string(),
        ))?,
        &request_json,
    )?;

    Ok(())
}

fn main() -> BiminiResult<process::ExitCode> {
    let cli_args = CliArgs::parse();

    let trace_formatter = tracing_subscriber::fmt::layer()
        .with_level(true)
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_thread_names(true);

    let registry =
        Registry::default().with::<LevelFilter>(Into::<LevelFilter>::into(&cli_args.log_level));

    match cli_args.log_format {
        LogFormat::Json => registry.with(trace_formatter.json()).init(),
        LogFormat::Pretty => registry.with(trace_formatter.pretty()).init(),
        _ => registry.with(trace_formatter.compact()).init(),
    };

    let aws_credentials = if cli_args.enable_aws_client {
        tracing::info!("AWS Client enabled, searching for credentials.");
        find_aws_credentials(&cli_args)?
    } else {
        tracing::info!("AWS Client disabled, skipping credential search.");
        None
    };

    let aws_client = aws_credentials.map(|credentials| {
        AwsClient::from(credentials).with_region(cli_args.aws_region.as_ref().unwrap())
    });

    let vault_settings = if cli_args.enable_vault_client {
        tracing::info!("Vault Client enabled, building for settings.");
        find_vault_settings(&cli_args, aws_client.as_ref())?
    } else {
        tracing::info!("Vault Client disabled, skipping settings search.");
        None
    };

    let vault_client = vault_settings.map(VaultClient::from);

    if cli_args.enable_vault_cert_generation {
        tracing::info!("Vault cert generation enabled, starting generation.");
        generate_vault_certs(
            vault_client.as_ref(),
            cli_args.vault_cert_engine.as_str(),
            cli_args.vault_cert_role.as_ref(),
            cli_args.vault_cert_request.as_ref(),
        )?;
    } else {
        tracing::info!("Vault cert generation disabled, skipping generation.");
    }

    tracing::info!("Starting process controller.");
    proc::Controller::default()
        .mask_signals()?
        .spawn(
            proc::ChildBuilder::default()
                .command(cli_args.command)
                .args(cli_args.args)
                .user_spec(
                    cli_args
                        .spawn_userspec
                        .map(|s| UserSpec::from_str(s.as_str()))
                        .transpose()?,
                )
                .spawn_directory(cli_args.spawn_directory)
                .aws_client(if cli_args.enable_aws_creds_env_injection {
                    aws_client
                } else {
                    None
                })
                .vault_client(vault_client),
        )?
        .start_signal_forwarder()?
        .run_reaper()
}
