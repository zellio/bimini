use crate::all_groups::AllGroups;
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

    fn set_identity(
        &self,
        user: &Option<unistd::User>,
        group: &Option<unistd::Group>,
        groups: &Option<Vec<unistd::Group>>,
    ) -> Result<HashMap<String, String>> {
        if let Some(group) = group {
            unistd::setgid(group.gid).map_err(|errno| {
                tracing::error!("Failed to set GID to {} - {errno}", group.gid);
                errno
            })?;
        }

        if let Some(groups) = groups {
            let gids: &[unistd::Gid] = &groups
                .iter()
                .map(|group| group.gid)
                .collect::<Vec<unistd::Gid>>()[..];

            unistd::setgroups(gids).map_err(|errno| {
                tracing::error!(
                    "Failed to set supplemental groups to {:?} - {errno}",
                    groups
                );
                errno
            })?;
        }

        if let Some(user) = user {
            unistd::setuid(user.uid).map_err(|errno| {
                tracing::error!("Failed to set UID to {} - {errno}", user.uid);
                errno
            })?;
            Ok(self.as_env())
        } else {
            Ok(HashMap::new())
        }
    }

    pub fn switch_user(&self) -> Result<HashMap<String, String>> {
        match self {
            UserSpec {
                user: Some(_),
                group: Some(_),
            } => self.set_identity(&self.user, &self.group, &None),

            UserSpec {
                user: Some(user),
                group: None,
            } => {
                let group = unistd::Group::from_gid(user.gid).ok().flatten();
                self.set_identity(
                    &self.user,
                    &group,
                    &Some(
                        AllGroups
                            .filter_map(|group_result| match group_result {
                                Ok(group) if group.mem.contains(&user.name) => Some(group),
                                _ => None,
                            })
                            .collect::<Vec<unistd::Group>>(),
                    ),
                )
            }

            UserSpec {
                user: None,
                group: Some(_),
            } => self.set_identity(&None, &self.group, &None),

            UserSpec {
                user: None,
                group: None,
            } => Ok(HashMap::new()),
        }
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
