use nix::{errno, unistd};
use std::{collections::HashMap, str::FromStr};

#[cfg(target_env = "gnu")]
use crate::nix::GroupsIter;

use crate::{error::BiminiResult, nix::ToEnv};

#[derive(Clone, Debug)]
pub struct UserSpec {
    pub user: Option<unistd::User>,
    pub group: Option<unistd::Group>,
}

impl UserSpec {
    #[tracing::instrument(skip_all)]
    pub fn switch_user(&self) -> BiminiResult<Self> {
        let current_userspec = UserSpec::default();

        if let Some(group) = &self.group {
            tracing::info!("Switching to group {}", group.name);

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
            tracing::info!("Setting secondary user groups");

            let gids = GroupsIter
                .filter_map(|group| match group {
                    Ok(group) if group.mem.contains(&user.name) => Some(group.gid),
                    _ => None,
                })
                .collect::<Vec<unistd::Gid>>();

            unistd::setgroups(gids.as_slice())?;
        }

        if let Some(user) = &self.user {
            tracing::info!("Switching to user {}", user.name);

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

fn resolve_user(s: &str) -> Result<Option<unistd::User>, errno::Errno> {
    if let Ok(uid) = s.parse::<u32>() {
        unistd::User::from_uid(unistd::Uid::from_raw(uid))
    } else {
        unistd::User::from_name(s)
    }
}

fn resolve_group(s: &str) -> Result<Option<unistd::Group>, errno::Errno> {
    if let Ok(uid) = s.parse::<u32>() {
        unistd::Group::from_gid(unistd::Gid::from_raw(uid))
    } else {
        unistd::Group::from_name(s)
    }
}

impl FromStr for UserSpec {
    type Err = errno::Errno;

    #[tracing::instrument(skip_all)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (user_str, group_str) = s.split_once(':').unwrap_or((s, ""));

        let user = if !user_str.is_empty() {
            let user = resolve_user(user_str)?;

            if user.is_none() {
                tracing::warn!("Failed to resolve user: {user_str}");
            }

            user
        } else {
            None
        };

        let group = if !group_str.is_empty() {
            let group = resolve_group(group_str)?;

            if group.is_none() {
                tracing::warn!("Failed to resolve group: {group_str}");
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
