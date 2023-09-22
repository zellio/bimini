use crate::{
    aws::AwsClient,
    error::{BiminiError, BiminiResult},
    nix::{SignalConfig, SpawnDirectory, ToEnv, UserSpec},
    vault::{
        engine::{Engine, Kv2Engine, Kv2ReadResponse},
        Client, VaultClient,
    },
};
use derive_builder::Builder;
use nix::{errno, unistd};
use std::{collections::HashMap, env, os::unix::process::CommandExt, process};

#[derive(Builder)]
#[builder(build_fn(error = "BiminiError"), pattern = "owned")]
pub struct Child<'a> {
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

    signal_config: &'a mut SignalConfig,
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
    fn vault_resolved_env(&self) -> HashMap<String, String> {
        tracing::info!("Resolving vault environment keys.");

        let mut engine_cache = HashMap::<String, Kv2Engine>::default();
        let mut page_cache = HashMap::<(String, String), Option<Kv2ReadResponse>>::default();

        env::vars()
            .filter(|(_, value)| value.starts_with("vault:") && value.matches(':').count() == 3)
            .map(|(name, value)| {
                (name, {
                    let fields: Vec<&str> = value.split(':').collect();
                    let (_, engine, path, key) = (fields[0], fields[1], fields[2], fields[3]);

                    let client = engine_cache.entry(engine.to_string()).or_insert_with(|| {
                        self.vault_client
                            .as_ref()
                            .unwrap()
                            .activate(engine.to_string())
                    });

                    let page = page_cache
                        .entry((engine.to_string(), path.to_string()))
                        .or_insert_with(|| client.get(path).map(|response| response.data).ok());

                    page.as_ref()
                        .and_then(|page| page.data.get(key))
                        .map_or_else(
                            || {
                                tracing::warn!(
                                    "Failed to resolve Hashicorp Vault ENV - Key: {key} Value: {value}"
                                );
                                String::from(&value)
                            },
                            String::from,
                        )
                })
            })
            .collect()
    }

    #[tracing::instrument(skip_all)]
    pub fn spawn(&mut self) -> BiminiResult<unistd::Pid> {
        tracing::info!("Constructing child proc for spawnning.");

        let mut proc = process::Command::new(&self.command);
        proc.args(&self.args);

        proc.envs(env::vars());

        if let Some(vault_client) = &self.vault_client {
            tracing::debug!("Vault client provided, resolving env keys.");
            proc.envs(vault_client.to_env());
            proc.envs(self.vault_resolved_env());
        }

        if let Some(aws_client) = &self.aws_client {
            tracing::debug!("AWS Client provided, injecting environment.");
            proc.envs(aws_client.to_env());
        }

        if let Some(user_spec) = &self.user_spec {
            tracing::debug!("UserSpec provided, switching executing user.");
            user_spec.switch_user()?;
            proc.envs(user_spec.to_env());
        }

        if let Some(spawn_directory) = &self.spawn_directory {
            tracing::debug!("Spawn directory provided, changing proc root.");
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
