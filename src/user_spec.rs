use builder_pattern::Builder;
use nix::{errno, unistd};
use std::str::FromStr;
use std::string::ToString;

#[derive(Debug, Builder)]
pub struct UserSpec {
    pub user: Option<unistd::User>,
    pub group: Option<unistd::Group>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct UserSpecError;

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

impl ToString for UserSpec {
    fn to_string(&self) -> String {
        format!(
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
