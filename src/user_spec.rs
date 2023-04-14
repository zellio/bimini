use anyhow::Result;
use builder_pattern::Builder;
use nix::{errno, unistd};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Builder)]
pub struct UserSpec {
    pub user: Option<unistd::User>,
    pub group: Option<unistd::Group>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct UserSpecError;

impl UserSpec {
    pub fn as_env(&self) -> HashMap<String, String> {
        let mut env = HashMap::new();

        if let Some(user) = &self.user {
            env.extend([
                (String::from("USER"), String::from(&user.name)),
                (String::from("LOGNAME"), String::from(&user.name)),
                (
                    String::from("HOME"),
                    user.dir
                        .clone()
                        .into_os_string()
                        .into_string()
                        .expect("Directory should be a valid string."),
                ),
            ]);
        }

        if let Some(group) = &self.group {
            env.extend([(String::from("GROUP"), String::from(&group.name))]);
        }

        env
    }

    pub fn homedir(&self) -> Option<String> {
        self.user.as_ref().map(|user| {
            user.dir
                .clone()
                .into_os_string()
                .into_string()
                .expect("Directory should be a valid string.")
        })
    }

    pub fn switch_user(
        &self, /*, spawn_directory: Option<String>*/
    ) -> Result<HashMap<String, String>> {
        if let Some(group) = &self.group {
            unistd::setgid(group.gid).map_err(|errno| {
                tracing::error!("Failed to set GID to {} - {errno}", group.gid);
                errno
            })?;
        }

        if let Some(user) = &self.user {
            unistd::setuid(user.uid).map_err(|errno| {
                tracing::error!("Failed to set UID to {} - {errno}", user.uid);
                errno
            })?;
        }

        Ok(self.as_env())
    }
}

impl FromStr for UserSpec {
    type Err = errno::Errno;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let userspec = s.split(':').collect::<Vec<&str>>();

        Ok(UserSpec::new()
            .user(userspec.first().and_then(|user_name| {
                unistd::User::from_name(user_name)
                    .map_err(|errno| {
                        tracing::error!("Failed to lookup user: {user_name} - {errno}");
                        errno
                    })
                    .ok()?
            }))
            .group(userspec.get(1).and_then(|group_name| {
                unistd::Group::from_name(group_name)
                    .map_err(|errno| {
                        tracing::error!("Failed to lookup group: {group_name} - {errno}");
                        errno
                    })
                    .ok()?
            }))
            .build())
    }
}

impl fmt::Display for UserSpec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}:{}",
            self.user
                .as_ref()
                .map(|user| user.name.clone())
                .unwrap_or_default(),
            self.group
                .as_ref()
                .map(|group| group.name.clone())
                .unwrap_or_default()
        )
    }
}

impl Default for UserSpec {
    fn default() -> UserSpec {
        UserSpec {
            user: unistd::User::from_uid(unistd::getuid()).unwrap_or(None),
            group: unistd::Group::from_gid(unistd::getgid()).unwrap_or(None),
        }
    }
}
