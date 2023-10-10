use crate::error::BiminiError;
use derive_builder::Builder;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Builder)]
#[builder(build_fn(error = "BiminiError"))]
pub struct Request<D>
where
    D: Serialize,
{
    #[builder(setter(into))]
    pub method: String,

    #[builder(setter(into))]
    pub path: String,

    #[builder(setter(into, strip_option), default = "None")]
    pub data: Option<D>,

    #[builder(setter(into, strip_option), default = "None")]
    pub headers: Option<HashMap<String, String>>,
}
