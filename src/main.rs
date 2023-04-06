use anyhow::{Context, Result};
use bimini::aws_client::{aws_credentials::AwsCredentials, AwsClient};
use bimini::user_spec::UserSpec;
use bimini::vault_api::engine::{kv2::Kv2GetResponse, pki::PkiIssueRequest};
use bimini::vault_api::VaultApi;
use clap::Parser as ClapParser;
use nix::sys::{signal, time, wait};
use nix::{errno, libc, unistd};
use std::collections::HashMap;
use std::fmt::Debug;
use std::os::unix::process::CommandExt;
use std::str::FromStr;
use std::{env, process};

#[derive(Debug)]
struct SignalConfig {
    parent_signals: signal::SigSet,
    source_signals: signal::SigSet,
    sigttin_action: signal::SigAction,
    sigttou_action: signal::SigAction,
}

const PKG_NAME: &str = env!("CARGO_PKG_NAME");
const SIG_TIMED_WAIT_TS: &time::TimeSpec = &time::TimeSpec::new(1, 0);

#[derive(ClapParser, Debug)]
struct CliArgs {
    /// Log level (off|error|warn|info|debug|trace).
    #[clap(long, default_value = "info", env = "BIMINI_LOG_LEVEL")]
    log_level: String,

    /// Log format (plain|pretty|json).
    #[clap(long, default_value = "auto", env = "BIMINI_LOG_FORMAT")]
    log_format: String,

    /// Spawn command as user spec.
    #[clap(long = "spawn-as", env = "BIMINI_SPAWN_AS")]
    spawn_userspec: Option<String>,

    /// Spawn command as user spec.
    #[clap(long = "spawn-directory", env = "BIMINI_SPAWN_DIRECTORY")]
    spawn_directory: Option<String>,

    /// Turn off AWS credentials management management.
    #[clap(long, env = "BIMINI_AWS_CLIENT_DISABLED", default_value = "false")]
    aws_client_disabled: bool,

    /// AWS Region for for Hashicorp Vault RBAC auth
    #[clap(long, env)]
    aws_region: Option<String>,

    /// AWS credentials URI for Hashicorp Vault RBAC auth
    #[clap(long, env)]
    aws_container_credentials_relative_uri: Option<String>,

    /// AWS credentials URI for Hashicorp Vault RBAC auth
    #[clap(long, env)]
    aws_container_credentials_full_uri: Option<String>,

    /// AWS access key for Hashicorp Vault RBAC auth
    #[clap(long, env)]
    aws_access_key_id: Option<String>,

    /// AWS secret key for Hashicorp Vault RBAC auth
    #[clap(long, env)]
    aws_secret_access_key: Option<String>,

    /// AWS session token for Hashicorp Vault RPAB auth
    #[clap(long, env)]
    aws_session_token: Option<String>,

    /// Turn off Hashicorp Vault secrets injection.
    #[clap(long, env = "BIMINI_VAULT_CLIENT_DISABLED", default_value = "false")]
    vault_client_disabled: bool,

    /// Fully qualified domain of the Hashicorp Vault server
    #[clap(long, env)]
    vault_addr: Option<String>,

    /// X-Vault-AWS-IAM-Server-ID value
    #[clap(long, env)]
    vault_security_header: Option<String>,

    /// Hashicorp Vault role to authenticate as
    #[clap(long, env)]
    vault_role: Option<String>,

    /// Hashicorp Vault token.
    #[clap(long, env)]
    vault_token: Option<String>,

    /// Turn off Hashicorp Vault certificates generation.
    #[clap(
        long,
        env = "BIMINI_VAULT_CERT_GENERATION_DISABLED",
        default_value = "false"
    )]
    vault_cert_generation_disabled: bool,

    /// Hashicorp Vault pki engine name
    #[clap(long, env, default_value = "pki")]
    vault_cert_engine: String,

    /// Hashicorp Vault pki role name
    #[clap(long, env)]
    vault_cert_role: Option<String>,

    /// Hashicorp Vault pki certificate request
    #[clap(long, env)]
    vault_cert_request: Option<String>,

    /// Program to spawn and track.
    #[clap()]
    command: String,

    /// Arguments to pass to command.
    #[clap()]
    args: Vec<String>,
}

fn mask_signals() -> Result<SignalConfig> {
    tracing::info!("Masking signals.");

    let protected_signals = vec![
        signal::SIGFPE,
        signal::SIGILL,
        signal::SIGSEGV,
        signal::SIGBUS,
        signal::SIGABRT,
        signal::SIGTRAP,
        signal::SIGSYS,
        signal::SIGTTIN,
        signal::SIGTTOU,
    ];

    let mut parent_signals = signal::SigSet::all();
    for signal in protected_signals {
        parent_signals.remove(signal)
    }

    let mut source_signals = signal::SigSet::empty();
    signal::sigprocmask(
        signal::SigmaskHow::SIG_SETMASK,
        Some(&parent_signals),
        Some(&mut source_signals),
    )?;

    let ignore_action = signal::SigAction::new(
        signal::SigHandler::SigIgn,
        signal::SaFlags::empty(),
        signal::SigSet::empty(),
    );

    unsafe {
        let sigttin_action = signal::sigaction(signal::SIGTTIN, &ignore_action)?;
        let sigttou_action = signal::sigaction(signal::SIGTTOU, &ignore_action)?;

        Ok(SignalConfig {
            parent_signals,
            source_signals,
            sigttin_action,
            sigttou_action,
        })
    }
}

fn unmask_signals(signal_config: &SignalConfig) -> Result<()> {
    tracing::info!("Unmasking signals.");

    signal::sigprocmask(
        signal::SigmaskHow::SIG_SETMASK,
        Some(&signal_config.source_signals),
        None,
    )
    .map_err(|err| {
        tracing::error!("Failure configuring signals -- {err}");
        err
    })?;

    unsafe {
        signal::sigaction(signal::SIGTTIN, &signal_config.sigttin_action)?;
        signal::sigaction(signal::SIGTTOU, &signal_config.sigttou_action)?;
    }

    Ok(())
}

fn isolate_child() -> Result<()> {
    tracing::info!("Isolating child process in a new process group.");

    let zero_pid = unistd::Pid::from_raw(0);
    if let Err(errno) = unistd::setpgid(zero_pid, zero_pid) {
        tracing::error!("setpgid failed {}", errno.desc());
        return Err(errno.into());
    }

    match unistd::tcsetpgrp(libc::STDIN_FILENO, unistd::getpgrp()) {
        Err(errno::Errno::ENOTTY | errno::Errno::ENXIO) => {
            tracing::debug!("tcsetpgrp failed safely, continuing.");
            Ok(())
        }

        Err(errno) => {
            tracing::error!("tcsetpgrp failed {}", errno.desc());
            Err(errno.into())
        }

        _ => Ok(()),
    }
}

fn cwd_str() -> Result<String, errno::Errno> {
    unistd::getcwd()
        .map(|current_directory| {
            current_directory
                .into_os_string()
                .into_string()
                .expect("Current working directory should be a valid string.")
        })
        .map_err(|errno| {
            tracing::error!("Failed to get current working directory - {errno}");
            errno
        })
}

fn switch_user(
    userspec: String,
    spawn_directory: Option<String>,
) -> Result<HashMap<String, String>> {
    tracing::info!("Switching UID:GID to userspec: {userspec}");

    let mut user_env = HashMap::<String, String>::new();
    let UserSpec { user, group } = UserSpec::from_str(&userspec)?;

    if let Some(group) = group {
        unistd::setgid(group.gid).map_err(|errno| {
            tracing::error!("Failed to set GID to {} - {errno}", group.gid);
            errno
        })?;
        user_env.insert(String::from("GROUP"), group.name);
    }

    let mut user_home = None;
    if let Some(user) = user {
        unistd::setuid(user.uid).map_err(|errno| {
            tracing::error!("Failed to set UID to {} - {errno}", user.uid);
            errno
        })?;

        let home = user
            .dir
            .into_os_string()
            .into_string()
            .expect("Directory should be a valid string.");

        user_env.extend([
            (String::from("USER"), String::from(&user.name)),
            (String::from("LOGNAME"), String::from(&user.name)),
            (String::from("HOME"), home.clone()),
        ]);

        user_home = Some(home);
    }

    let initial_working_directory = cwd_str()?;

    vec![spawn_directory, user_home, Some(String::from("/"))]
        .iter()
        .find_map(|possible_directory| {
            possible_directory.as_ref().and_then(|dir| {
                unistd::chdir::<str>(dir.as_ref())
                    .map(|_| {
                        tracing::info!("Working directory changed to {dir}");
                    })
                    .map_err(|errno| {
                        tracing::warn!("Failed to change directory to: {dir} - {errno}");
                        errno
                    })
                    .ok()
            })
        });

    user_env.extend([
        (String::from("PWD"), cwd_str()?),
        (String::from("OLDPWD"), initial_working_directory),
    ]);

    Ok(user_env)
}

pub fn resolve_vault_env_keys(vault_api: &VaultApi, env: env::Vars) -> HashMap<String, String> {
    tracing::info!("Resolving Hashicorp Vault keys in ENV.");

    let mut vault_cache = HashMap::<String, Option<Kv2GetResponse>>::new();

    env.filter(|(_, val)| val.starts_with("vault:"))
        .map(|(env_key, val)| {
            (
                String::from(&env_key), //
                {
                    let fields: Vec<&str> = val.split(':').collect();
                    let (_, engine, path, key) = (fields[0], fields[1], fields[2], fields[3]);

                    let cache_page = vault_cache
                        .entry(format!("{engine}:{path}"))
                        .or_insert_with(|| vault_api.kv2_get(engine, path, None).ok());

                    cache_page
                        .as_ref()
                        .and_then(|json| json.data.data.get(key).map(String::from))
                        .unwrap_or_else(|| {
                            tracing::warn!(
                                "Failed to resolve Hashicorp Vault ENV - Key: {env_key} Value: {val}"
                            );
                            String::from(&val)
                        })
                },
            )
        })
        .collect()
}

fn spawn(
    signal_config: &SignalConfig,
    aws_client: &Option<AwsClient>,
    vault_api: &Option<VaultApi>,
    userspec: Option<String>,
    spawn_directory: Option<String>,
    command: String,
    args: &Vec<String>,
) -> Result<unistd::Pid> {
    match unsafe { unistd::fork() } {
        Ok(unistd::ForkResult::Child) => {
            let mut proc = process::Command::new(&command);

            proc.args(args);
            proc.envs(env::vars().collect::<HashMap<String, String>>());

            if let Some(vault_api) = vault_api {
                proc.envs(resolve_vault_env_keys(vault_api, env::vars()));
            }

            if let Some(aws_client) = aws_client {
                tracing::info!("Injecting AWS credentials into ENV.");
                proc.envs(aws_client.as_envs());
            }

            if let Some(userspec) = userspec {
                proc.envs(switch_user(userspec, spawn_directory)?);
            }

            isolate_child()?;

            unmask_signals(signal_config)?;

            tracing::info!("Handing execution off to child proc: {command}");
            let error = proc.exec();

            tracing::error!("execvp failed: {error}");
            Err(error.into())
        }

        Ok(unistd::ForkResult::Parent { child }) => {
            tracing::info!("Spawning child proc: {child}");
            Ok(child)
        }

        Err(errno) => {
            tracing::error!("fork failed: {}", errno.desc());
            Err(errno.into())
        }
    }
}

fn reap_zombies(child_pid: unistd::Pid) -> Result<i32> {
    tracing::trace!("Reaping zombie procs.");

    let any_proc = unistd::Pid::from_raw(-1);
    let mut child_exitcode = -1;

    loop {
        match wait::waitpid(any_proc, Some(wait::WaitPidFlag::WNOHANG)) {
            Ok(wait::WaitStatus::StillAlive) => {
                tracing::trace!("No child to reap.");
                break;
            }

            Ok(wait::WaitStatus::Exited(pid, status)) if pid == child_pid => {
                let exit_status = libc::WEXITSTATUS(status);
                tracing::info!("Main child exited normally with status: {exit_status}");
                child_exitcode = exit_status;
            }

            Ok(wait::WaitStatus::Signaled(pid, signal, _)) if pid == child_pid => {
                tracing::info!("Main child exited with signal: {}", signal.to_string());
                child_exitcode = 128 + signal as i32;
            }

            Ok(wait::WaitStatus::Exited(pid, _)) => {
                tracing::debug!("Reaped child with pid: {pid}");
                if pid == child_pid {
                    tracing::error!("Main child exited for an unknown reason.");
                    // Unknown error
                    return Err(errno::Errno::from_i32(42).into());
                }
            }

            Ok(_) => todo!(),

            Err(nix::Error::ECHILD) => {
                tracing::trace!("No child to wait.");
                break;
            }

            Err(errno) => {
                tracing::error!("Error while waiting for pids: {}", errno.desc());
                return Err(anyhow::Error::from(errno));
            }
        }
    }

    Ok(child_exitcode)
}

fn sigtimedwait(parent_signals: &signal::SigSet) -> Result<libc::siginfo_t, errno::Errno> {
    let mut siginfo = std::mem::MaybeUninit::uninit();
    let result = unsafe {
        libc::sigtimedwait(
            parent_signals.as_ref(),
            siginfo.as_mut_ptr(),
            SIG_TIMED_WAIT_TS.as_ref(),
        )
    };

    errno::Errno::result(result)?;
    Ok(unsafe { siginfo.assume_init() })
}

fn forward_signals(parent_signals: &signal::SigSet, child_pid: unistd::Pid) -> Result<()> {
    tracing::trace!("Forwarding signals from {PKG_NAME} to child proc.");

    match sigtimedwait(parent_signals) {
        Err(errno @ errno::Errno::EAGAIN | errno @ errno::Errno::EINTR) => {
            tracing::info!("Expected error, passing: {}", errno.desc());
        }

        Err(errno) => {
            tracing::error!("Unexpected error in sigtimedwait: {}", errno.desc());
            return Err(errno.into());
        }

        Ok(siginfo) => match signal::Signal::try_from(siginfo.si_signo) {
            Ok(signal::SIGCHLD) => tracing::debug!("Received SIGCHLD"),
            Ok(signal) => {
                tracing::debug!("Passing signal: {}", signal.to_string());

                signal::kill(child_pid, signal).map_err(|errno| {
                    if errno == errno::Errno::ESRCH {
                        tracing::warn!("Child was dead when forwarding signal");
                    }
                    anyhow::Error::from(errno)
                })?;
            }

            Err(errno) => {
                tracing::error!("{}", errno.desc());
                return Err(errno.into());
            }
        },
    }

    Ok(())
}

fn generate_cert(vault_api: &VaultApi, engine: &str, role: &str, request_json: &str) -> Result<()> {
    let request = serde_json::from_str::<PkiIssueRequest>(request_json)?;
    let response = vault_api.pki_issue(engine, role, &request)?;

    let ssl_path = std::path::Path::new("/opt").join(PKG_NAME).join("ssl");
    let ssl_private_path = ssl_path.join("private");
    let ssl_certs_path = ssl_path.join("certs");

    std::fs::create_dir_all(&ssl_path)?;
    std::fs::create_dir_all(&ssl_private_path)?;
    std::fs::create_dir_all(&ssl_certs_path)?;

    let key_format = &request
        .private_key_format
        .unwrap_or_else(|| String::from("der"));
    let cert_format = &request.format.unwrap_or_else(|| String::from("pem"));

    tracing::warn!("Creating private key");
    let mut ssl_private_key_path = ssl_private_path.join("key");
    ssl_private_key_path.set_extension(&key_format);
    std::fs::write(
        &ssl_private_key_path,
        format!("{}\n", &response.data.private_key),
    )?;

    tracing::warn!("Creating certificate");
    let mut ssl_cert_path = ssl_certs_path.join("certificate");
    ssl_cert_path.set_extension(&cert_format);
    std::fs::write(&ssl_cert_path, format!("{}\n", &response.data.certificate))?;

    tracing::warn!("Creating issuing-ca");
    let mut ssl_ca_cert_path = ssl_certs_path.join("issuing-ca");
    ssl_ca_cert_path.set_extension(&cert_format);
    std::fs::write(
        &ssl_ca_cert_path,
        format!("{}\n", &response.data.certificate),
    )?;

    tracing::warn!("Creating ca-chain");
    let mut ssl_ca_chain_path = ssl_certs_path.join("ca-chain");
    ssl_ca_chain_path.set_extension(&cert_format);
    std::fs::write(
        &ssl_ca_chain_path,
        format!("{}\n", &response.data.ca_chain.join("\n")),
    )?;

    Ok(())
}

fn main() -> Result<process::ExitCode> {
    let cli_args = CliArgs::parse();

    // Set up tracing
    let subscriber_builder = tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_new(cli_args.log_level).context("Invalid log level")?,
    );

    match cli_args.log_format.as_str() {
        "json" => subscriber_builder.json().init(),
        "pretty" => subscriber_builder.pretty().init(),
        _ => subscriber_builder.init(),
    };

    let aws_creds = if cli_args.aws_client_disabled {
        None
    } else if let (Some(access_key), Some(secret_key)) =
        (cli_args.aws_access_key_id, cli_args.aws_secret_access_key)
    {
        tracing::info!("Using provided AWS IAM credentials.");
        Some(
            AwsCredentials::new()
                .access_key_id(access_key)
                .secret_access_key(secret_key)
                .token(cli_args.aws_session_token)
                .build(),
        )
    } else if cli_args.aws_container_credentials_relative_uri.is_some()
        || cli_args.aws_container_credentials_full_uri.is_some()
    {
        tracing::info!("Loading AWS IAM credentials from container identity service.");
        if let Some(creds) = AwsCredentials::from_container_credential_env_vars(
            cli_args.aws_container_credentials_relative_uri,
            cli_args.aws_container_credentials_full_uri,
        ) {
            Some(creds?)
        } else {
            None
        }
    } else {
        None
    };

    let mut aws_client = match aws_creds {
        Some(aws_creds) => {
            tracing::info!("Building AWS API Client.");
            Some(
                aws_creds.to_client(
                    cli_args
                        .aws_region
                        .unwrap_or_else(|| String::from("us-east-1")),
                ),
            )
        }
        _ => None,
    };

    // Build Hashicorp Vault client
    let mut vault_api = if cli_args.vault_client_disabled {
        None
    } else {
        tracing::info!("Building Hashicorp Vault client.");
        Some(VaultApi::new(
            cli_args.vault_addr.unwrap_or_else(|| {
                tracing::error!("VAULT_ADDR required for Hashicorp Vault client integration.");
                process::exit(1);
            }),
            cli_args.vault_security_header,
            cli_args.vault_token,
        ))
    };

    (vault_api, aws_client) = match (vault_api, aws_client) {
        (Some(mut vault_api), Some(aws_client)) => {
            if let Some(vault_role) = cli_args.vault_role {
                vault_api.auth_aws_login(&vault_role, &aws_client)?;
            } else {
                tracing::error!("VAULT_ROLE required for vault / aws login.");
                process::exit(1);
            }
            (Some(vault_api), Some(aws_client))
        }
        (Some(vault_api), None) if vault_api.token.is_none() => {
            tracing::error!("Either a vault token or AWS credentials are required.");
            process::exit(1);
        }
        (vault_api, aws_client) => (vault_api, aws_client),
    };

    if !cli_args.vault_cert_generation_disabled {
        if let (Some(vault_api), Some(role), Some(request_json)) = (
            &vault_api,
            cli_args.vault_cert_role,
            cli_args.vault_cert_request,
        ) {
            tracing::info!("Generating client certificates.");
            if let Err(err) =
                generate_cert(vault_api, &cli_args.vault_cert_engine, &role, &request_json)
            {
                tracing::error!("Failed to generate vault issued certs - {err}");
                process::exit(1);
            }
        } else {
            tracing::error!(
                "Hashicorp Vault cert generation requires vault credentials and a Cert role."
            );
            process::exit(1);
        }
    }

    // Mask signals
    let signal_config = match mask_signals() {
        Ok(sigset) => sigset,
        Err(err) => {
            tracing::error!("Failure configuring signals: {err}");
            return Err(err);
        }
    };

    // Spawn proc
    let child_pid = spawn(
        &signal_config,
        &aws_client,
        &vault_api,
        cli_args.spawn_userspec,
        cli_args.spawn_directory,
        cli_args.command,
        &cli_args.args,
    )?;

    // Management loop
    loop {
        forward_signals(&signal_config.parent_signals, child_pid)?;

        let child_exitcode = reap_zombies(child_pid)?;

        if child_exitcode != -1 {
            process::exit(child_exitcode);
        }
    }
}
