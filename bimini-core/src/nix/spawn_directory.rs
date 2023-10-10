use nix::unistd;
use std::{collections::HashMap, path::PathBuf};

use crate::{error::BiminiResult, nix::ToEnv};

#[derive(Clone, Debug)]
pub struct SpawnDirectory {
    user: unistd::User,
    path: PathBuf,
    initial_dir: PathBuf,
}

impl SpawnDirectory {
    pub fn new(user: unistd::User, path: PathBuf) -> BiminiResult<Self> {
        Ok(SpawnDirectory {
            user,
            path,
            initial_dir: unistd::getcwd()?,
        })
    }

    pub fn chdir(&self) -> BiminiResult<()> {
        [&self.path, &self.user.dir, &PathBuf::from("/")]
            .iter()
            .find_map(|path| path.as_os_str().to_str().map(unistd::chdir))
            .transpose()?;

        Ok(())
    }
}

impl ToEnv for SpawnDirectory {
    fn to_env(&self) -> HashMap<String, String> {
        let mut env = HashMap::new();

        if let Ok(path) = self.initial_dir.clone().into_os_string().into_string() {
            env.insert("OLDPWD".to_string(), path);
        }

        if let Ok(path) = self.path.clone().into_os_string().into_string() {
            env.insert("PWD".to_string(), path);
        }

        env
    }
}
