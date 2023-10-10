use nix::{errno, unistd};
use std::{collections::HashMap, str::FromStr};

#[cfg(target_env = "gnu")]
use crate::nix::GroupsIter;

use crate::{error::BiminiResult, nix::ToEnv};

#[derive(Clone, Debug)]
pub struct UserSpec {
    user: Option<unistd::User>,
    group: Option<unistd::Group>,
}

impl UserSpec {
    #[tracing::instrument(skip_all)]
    pub fn switch_user(&self) -> BiminiResult<Self> {
        let current_userspec = UserSpec::default();

        if let Some(group) = &self.group {
            unistd::setgid(group.gid).map_err(|errno| {
                tracing::error!("Failed to set GID to {} - {errno}", group.gid);
                errno
            })?;
        }

        #[cfg(target_env = "gnu")]
        if let Self {
            user: Some(user),
            group: Some(_group),
        } = &self
        {
            let gids = GroupsIter
                .filter_map(|group| match group {
                    Ok(group) if group.mem.contains(&user.name) => Some(group.gid),
                    _ => None,
                })
                .collect::<Vec<unistd::Gid>>();

            unistd::setgroups(gids.as_slice())?;
        }

        if let Some(user) = &self.user {
            unistd::setuid(user.uid).map_err(|errno| {
                tracing::error!("Failed to set UID to {} - {errno}", user.uid);
                errno
            })?;
        }

        Ok(current_userspec)
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

impl std::fmt::Display for UserSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self {
                user: Some(user),
                group: Some(group),
            } => write!(f, "{}:{}", user.name, group.name),

            Self {
                user: Some(user),
                group: None,
            } => write!(f, "{}", user.name),

            Self {
                user: None,
                group: Some(group),
            } => write!(f, ":{}", group.name),

            Self {
                user: None,
                group: None,
            } => write!(f, ":"),
        }
    }
}

impl FromStr for UserSpec {
    type Err = errno::Errno;

    #[tracing::instrument(skip_all)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let tokens = s.split(':').collect::<Vec<&str>>();

        let user = if let Some(user_name) = tokens.first() {
            let user = unistd::User::from_name(user_name)?;

            if user.is_none() && !user_name.is_empty() {
                tracing::warn!("Failed to resolve user name: {user_name}");
            }

            user
        } else {
            None
        };

        let group = if let Some(group_name) = tokens.get(1) {
            let group = unistd::Group::from_name(group_name)?;

            if group.is_none() && !group_name.is_empty() {
                tracing::warn!("Failed to resolve group name: {group_name}");
            }

            group
        } else {
            None
        };

        Ok(Self { user, group })
    }
}

impl ToEnv for unistd::User {
    fn to_env(&self) -> HashMap<String, String> {
        HashMap::from([
            ("USER".to_string(), String::from(&self.name)),
            ("LOGNAME".to_string(), String::from(&self.name)),
            (
                "HOME".to_string(),
                self.dir
                    .clone()
                    .into_os_string()
                    .into_string()
                    .expect("Home directory should be a valid string."),
            ),
        ])
    }
}

impl ToEnv for unistd::Group {
    fn to_env(&self) -> HashMap<String, String> {
        HashMap::from([("GROUP".to_string(), String::from(&self.name))])
    }
}

impl ToEnv for UserSpec {
    fn to_env(&self) -> HashMap<String, String> {
        let mut env = HashMap::default();

        if let Some(user) = &self.user {
            env.extend(user.to_env())
        }

        if let Some(group) = &self.user {
            env.extend(group.to_env())
        }

        env
    }
}
