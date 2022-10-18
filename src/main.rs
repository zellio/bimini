use anyhow::{Context, Result};
use bimini::aws_client::{AwsClient, AwsClientBuilder, AwsCredentials};
use bimini::vault_client::VaultClient;
use clap::Parser as ClapParser;
use nix::sys::{signal, time, wait};
use nix::{errno, libc, unistd};
use std::fmt::Debug;
use std::os::unix::process::CommandExt;
use std::process;

#[derive(Debug)]
struct SignalConfig {
    parent_signals: signal::SigSet,
    source_signals: signal::SigSet,
    sigttin_action: signal::SigAction,
    sigttou_action: signal::SigAction,
}

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

    /// AWS Region for for Vault RBAC auth
    #[clap(long, env)]
    aws_region: Option<String>,

    /// AWS credentials URI for Vault RBAC auth
    #[clap(long, env)]
    aws_container_credentials_relative_uri: Option<String>,

    /// AWS credentials URI for Vault RBAC auth
    #[clap(long, env)]
    aws_container_credentials_full_uri: Option<String>,

    /// AWS access key for Vault RBAC auth
    #[clap(long, env)]
    aws_access_key_id: Option<String>,

    /// AWS secret key for Vault RBAC auth
    #[clap(long, env)]
    aws_secret_access_key: Option<String>,

    /// AWS session token for Vault RPAB auth
    #[clap(long, env)]
    aws_session_token: Option<String>,

    /// Turn off Vault secrets injection.
    #[clap(long, env = "BIMINI_VAULT_CLIENT_DISABLED", default_value = "false")]
    vault_client_disabled: bool,

    /// Fully qualified domain of the Vault server
    #[clap(long, env)]
    vault_addr: Option<String>,

    /// X-Vault-AWS-IAM-Server-ID value
    #[clap(long, env)]
    vault_security_header: Option<String>,

    /// Vault role to authenticate as
    #[clap(long, env)]
    vault_role: Option<String>,

    /// Vault token.
    #[clap(long, env)]
    vault_token: Option<String>,

    /// Program to spawn and track.
    #[clap()]
    command: String,

    /// Arguments to pass to command.
    #[clap()]
    args: Vec<String>,
}

fn mask_signals() -> Result<SignalConfig> {
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

fn switch_user(user_spec: String, spawn_directory: Option<String>) -> Result<()> {
    let user_spec: Vec<&str> = user_spec.split(':').collect();

    // // switch gid
    if let Some(group_name) = user_spec.get(1) {
        match unistd::Group::from_name(group_name) {
            Ok(Some(group)) => {
                unistd::setgid(group.gid).map_err(|errno| {
                    tracing::error!("Failed to set GID to {} - {errno}", group.gid);
                    errno
                })?;
            }
            Ok(None) => tracing::warn!("No group named {group_name} found - Not setting GID"),
            Err(errno) => {
                tracing::error!("Failed to lookup group name: {group_name} - {errno}");
                return Err(errno.into());
            }
        }
    }

    if let Some(user_name) = user_spec.first() {
        match unistd::User::from_name(user_name) {
            Ok(Some(user)) => {
                unistd::setuid(user.uid).map_err(|errno| {
                    tracing::error!("Failed to set UID to {} - {errno}", user.uid);
                    errno
                })?;

                if let Err(errno) = unistd::chdir(&user.dir) {
                    tracing::error!(
                        "Failed to chdir to user homedir, defaulting to root - {}",
                        errno
                    );
                    unistd::chdir("/")?;
                }
            }
            Ok(None) => tracing::warn!("No user named {user_name} found - Not setting UID"),
            Err(errno) => {
                tracing::error!("Failed to lookup user name: {user_name} - {errno}");
                return Err(errno.into());
            }
        }
    }

    if let Some(spawn_dir) = spawn_directory {
        tracing::info!("chdir to provided spawn directory: {}", spawn_dir);
        unistd::chdir(spawn_dir.as_str())?;
    }

    Ok(())
}

fn spawn(
    signal_config: &SignalConfig,
    aws_client: &Option<AwsClient>,
    vault_client: &Option<VaultClient>,
    userspec: Option<String>,
    spawn_directory: Option<String>,
    command: String,
    args: &Vec<String>,
) -> Result<unistd::Pid> {
    match unsafe { unistd::fork() } {
        Ok(unistd::ForkResult::Child) => {
            let mut proc = process::Command::new(command);
            proc.args(args);

            proc.envs(if let Some(vault_client) = vault_client {
                vault_client.process_env_map(std::env::vars())
            } else {
                std::env::vars().collect()
            });

            if let Some(aws_client) = aws_client {
                proc.envs(aws_client.as_env_map());
            }

            if let Some(userspec) = userspec {
                switch_user(userspec, spawn_directory)?;
            }

            isolate_child()?;

            unmask_signals(signal_config)?;

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
                tracing::trace!("No child to wait");
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

static SIG_TIMED_WAIT_TS: &time::TimeSpec = &time::TimeSpec::new(1, 0);

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
    tracing::info!("In forward signals");
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

    // Build AWS Client
    let aws_credentials = if let (Some(access_key), Some(secret_key)) =
        (cli_args.aws_access_key_id, cli_args.aws_secret_access_key)
    {
        Some(
            AwsCredentials::new()
                .access_key_id(access_key)
                .expiration(None)
                .role_arn(None)
                .secret_access_key(secret_key)
                .token(cli_args.aws_session_token)
                .build(),
        )
    } else {
        AwsCredentials::lookup(
            cli_args.aws_container_credentials_relative_uri,
            cli_args.aws_container_credentials_full_uri,
        )
    };

    let mut aws_client = match aws_credentials {
        Some(aws_creds) if !cli_args.aws_client_disabled => Some(
            AwsClientBuilder::from(aws_creds)
                .region(
                    cli_args
                        .aws_region
                        .unwrap_or_else(|| String::from("us-east-1")),
                )
                .build(),
        ),
        _ => None,
    };

    // Build Hashicorp Vault client
    let mut vault_client = if cli_args.vault_client_disabled {
        None
    } else {
        tracing::info!("Building Hashicorp Vault client.");
        Some(
            VaultClient::new()
                .addr(cli_args.vault_addr.unwrap_or_else(|| {
                    tracing::error!("VAULT_ADDR required for vault client integration.");
                    process::exit(1);
                }))
                .security_header(cli_args.vault_security_header.unwrap_or_else(|| {
                    tracing::error!("VAULT_SECURITY_HEADER required for vault client integration.");
                    process::exit(1);
                }))
                .role(cli_args.vault_role.unwrap_or_else(|| {
                    tracing::error!("VAULT_ROLE required for vault client integration.");
                    process::exit(1);
                }))
                .token(cli_args.vault_token)
                .build(),
        )
    };

    (vault_client, aws_client) = match (vault_client, aws_client) {
        (Some(mut vault_client), Some(aws_client)) => {
            vault_client.authenticate(&aws_client)?;
            (Some(vault_client), Some(aws_client))
        }
        (Some(vault_client), None) if vault_client.token.is_none() => {
            tracing::error!("Either a vault token or AWS credentials are required.");
            process::exit(1);
        }
        (vault_client, aws_client) => (vault_client, aws_client),
    };

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
        &vault_client,
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
