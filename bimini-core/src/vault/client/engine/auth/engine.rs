use serde::{Deserialize, Serialize};

use crate::{
    error::BiminiResult,
    vault::client::{Engine, Response},
};

pub trait AuthEngine {
    fn post_login<D, R>(&self, data: D) -> BiminiResult<Response<R>>
    where
        Self: Engine,
        D: Serialize + Clone + std::fmt::Debug,
        for<'de> R: Deserialize<'de>,
    {
        Engine::post(self, "login", data)
    }
}
