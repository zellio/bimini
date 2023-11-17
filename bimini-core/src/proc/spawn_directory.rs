use crate::nix::ToEnv;
use nix::unistd;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

pub struct SpawnDirectory {
    path: Option<PathBuf>,
    user: Option<unistd::User>,

    pwd: Option<PathBuf>,
    old_pwd: Option<PathBuf>,
}

impl Default for SpawnDirectory {
    fn default() -> Self {
        Self {
            path: None,
            user: None,
            pwd: unistd::getcwd().ok(),
            old_pwd: None,
        }
    }
}

impl ToEnv for SpawnDirectory {
    fn to_env(&self) -> std::collections::HashMap<String, String> {
        HashMap::from([
            (
                "OLDPWD".to_string(),
                self.old_pwd
                    .as_deref()
                    .and_then(Path::to_str)
                    .map(String::from)
                    .unwrap_or_default(),
            ),
            (
                "PWD".to_string(),
                self.pwd
                    .as_deref()
                    .and_then(Path::to_str)
                    .map(String::from)
                    .unwrap_or_default(),
            ),
        ])
    }
}

impl SpawnDirectory {
    pub fn new(path: Option<PathBuf>, user: Option<unistd::User>) -> Self {
        Self {
            path,
            user,
            ..Default::default()
        }
    }

    pub fn chdir(&mut self) {
        let old_pwd = self.pwd.clone();

        let target_paths = [
            &self.path,
            &self.user.as_ref().map(|user| user.dir.clone()),
            &self.pwd,
            &Some(PathBuf::from("/")),
        ];

        for target_path in target_paths {
            match target_path.as_deref().map(unistd::chdir) {
                Some(Ok(_)) => break,

                Some(Err(errno)) => {
                    tracing::warn!(
                        "chdir failed for {:?} - {errno}",
                        target_path.as_ref().unwrap()
                    );
                }

                None => {}
            }
        }

        let pwd = unistd::getcwd().ok();

        if pwd != old_pwd {
            self.old_pwd = old_pwd;
            self.pwd = pwd;
        }
    }
}
