use crate::{
    aws::AwsClient,
    error::{BiminiError, BiminiResult},
    nix::{SignalConfig, SpawnDirectory, ToEnv, UserSpec},
    vault::VaultClient,
};
use derive_builder::Builder;
use nix::{errno, unistd};
use std::{collections::HashMap, env, os::unix::process::CommandExt, process};

#[derive(Builder)]
#[builder(build_fn(error = "BiminiError"), pattern = "owned")]
pub struct Child<'a> {
    signal_config: &'a mut SignalConfig,

    #[builder(default)]
    user_spec: Option<UserSpec>,

    #[builder(default)]
    spawn_directory: Option<SpawnDirectory>,

    #[builder(default)]
    aws_client: Option<AwsClient>,

    #[builder(default)]
    vault_client: Option<VaultClient>,

    command: String,

    args: Vec<String>,
}

impl<'a> Child<'a> {
    #[tracing::instrument(skip_all)]
    fn isolate(&self) -> BiminiResult<()> {
        tracing::info!("Isolating child proc in a new proc namespace.");

        let zero_pid = unistd::Pid::from_raw(0);
        if let Err(errno) = unistd::setpgid(zero_pid, zero_pid) {
            return Err(BiminiError::from(errno));
        }

        match unistd::tcsetpgrp(libc::STDIN_FILENO, unistd::getpgrp()) {
            Err(errno::Errno::ENOTTY | errno::Errno::ENXIO) => Ok(()),

            Err(errno) => Err(BiminiError::from(errno)),

            _ => Ok(()),
        }
    }

    #[tracing::instrument(skip_all)]
    pub fn spawn(&mut self) -> BiminiResult<unistd::Pid> {
        tracing::info!("Constructing child proc for spawnning.");

        let mut proc = process::Command::new(&self.command);

        proc.args(&self.args);

        proc.envs(env::vars());
        proc.envs(self.to_env());

        if let Some(aws_client) = &self.aws_client {
            tracing::debug!("AWS Client provided, injecting environment");
            proc.envs(aws_client.to_env());
        }

        if let Some(vault_client) = &self.vault_client {
            tracing::debug!("Vault client provided, resolving env keys");
            proc.envs(vault_client.to_env());
        }

        if let Some(user_spec) = &self.user_spec {
            tracing::debug!("UserSpec provided, switching executing user");
            user_spec.switch_user()?;
            proc.envs(user_spec.to_env());
        }

        if let Some(spawn_directory) = &self.spawn_directory {
            tracing::debug!("Spawn directory provided, changing proc root");
            spawn_directory.chdir()?;
            proc.envs(spawn_directory.to_env());
        }

        self.isolate()?;
        self.signal_config.unmask()?;

        let error = proc.exec();

        if let Some(errno) = error.raw_os_error() {
            process::exit(errno);
        }

        Err(BiminiError::from(error))
    }
}

impl<'a> ToEnv for Child<'a> {
    fn to_env(&self) -> HashMap<String, String> {
        HashMap::from([
            (String::from("BIMINI"), String::from("true")),
            (
                String::from("BIMINI_VERSION"),
                String::from(env!("CARGO_PKG_VERSION")),
            ),
            (
                String::from("BIMINI_CHILD_PID"),
                format!("{}", unistd::getpid()),
            ),
        ])
    }
}
