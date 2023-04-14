use anyhow::Result;
use nix::{errno, unistd};
use std::collections::HashMap;

#[derive(Debug)]
pub struct SpawnDirectory {
    pub initial_directory: String,
    pub path: Option<String>,
}

impl SpawnDirectory {
    pub fn new(path: Option<String>) -> Result<Self> {
        Ok(SpawnDirectory {
            path,
            initial_directory: SpawnDirectory::cwd_str()?,
        })
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

    pub fn as_env(&self) -> Result<HashMap<String, String>> {
        Ok(HashMap::from([
            (
                String::from("OLDPWD"),
                String::from(&self.initial_directory),
            ),
            (String::from("PWD"), SpawnDirectory::cwd_str()?),
        ]))
    }

    pub fn switch_directory(&self) -> Result<HashMap<String, String>> {
        let user_home = unistd::User::from_uid(unistd::getuid())?.map(|u| {
            u.dir
                .into_os_string()
                .into_string()
                .expect("Directory should be a valid string.")
        });

        vec![&self.path, &user_home, &Some(String::from("/"))]
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

        self.as_env()
    }
}
