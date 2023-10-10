use std::collections::HashMap;

use crate::error::BiminiResult;

pub trait StsClient {
    fn get_caller_identity_request(
        &self,
        headers: Option<HashMap<&str, &str>>,
    ) -> BiminiResult<http::Request<&[u8]>>;

    fn sign_request<'a>(
        &'a self,
        request: http::Request<&'a [u8]>,
    ) -> BiminiResult<http::Request<&[u8]>>;

    fn signed_get_caller_identity_request(
        &self,
        headers: Option<HashMap<&str, &str>>,
    ) -> BiminiResult<http::Request<&[u8]>> {
        let request = self.get_caller_identity_request(headers)?;
        self.sign_request(request)
    }
}
