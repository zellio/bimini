use super::{request::RequestBuilder, Client, Request, Response};
use crate::error::BiminiResult;

pub trait Engine {
    type Client: Client;

    fn version(&self) -> &'static str {
        "v1"
    }

    fn mount(&self) -> &String;

    fn mount_mut(&mut self) -> &mut String;

    fn client(&self) -> &Self::Client;

    fn subpath(&self) -> Option<&str>;

    fn path(&self, path: &str) -> String {
        vec![
            Some(self.version()),
            Some(self.mount()),
            self.subpath(),
            Some(path),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>()
        .join("/")
    }

    fn get<D>(&self, path: &str) -> BiminiResult<Response<D>>
    where
        for<'de> D: serde::Deserialize<'de>,
    {
        let request: Request<serde_json::Value> = RequestBuilder::default()
            .method("GET")
            .path(self.path(path))
            .build()?;

        self.client().request(request)
    }

    fn post<D, R>(&self, path: &str, data: D) -> BiminiResult<Response<R>>
    where
        D: serde::Serialize + Clone,
        for<'de> R: serde::Deserialize<'de>,
    {
        let request: Request<D> = RequestBuilder::default()
            .method("POST")
            .path(self.path(path))
            .data(data)
            .build()?;

        self.client().request(request)
    }
}

pub mod auth;

mod kv2;
pub use kv2::*;

mod pki;
pub use pki::*;
