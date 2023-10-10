pub mod engine;
pub mod request;
pub mod response;
pub mod settings;
mod vault_client;

pub use request::{Request, RequestBuilder};
pub use response::Response;
pub use settings::{Settings, SettingsBuilder};
pub use vault_client::*;

use crate::{error::BiminiResult, vault::client::engine::Engine};

pub trait Client
where
    Self: Clone,
{
    type Settings;

    fn settings(&self) -> &Self::Settings;

    fn settings_mut(&mut self) -> &mut Self::Settings;

    fn activate<E>(&self, mount: impl ToString) -> E
    where
        E: Engine + std::convert::From<Self>;

    fn request<Rq, Rs>(&self, request: Request<Rq>) -> BiminiResult<Response<Rs>>
    where
        Rq: serde::Serialize + Clone,
        Rs: for<'de> serde::Deserialize<'de>;
}
