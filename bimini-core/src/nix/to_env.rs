use std::collections::HashMap;

pub trait ToEnv {
    fn to_env(&self) -> HashMap<String, String>;
}
