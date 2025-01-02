use proxy_wasm::{traits::{Context, HttpContext}, types::Action};

use crate::core::{capabilities::{auth::{jwt::JWT, okta::OktaCacheData}, cache::{Cache, CacheCapability}}, error::HttpError, expansion::ExpandedHttpContext};

pub struct TestCacheContext {
    cache_okta_data: Cache<OktaCacheData>,
}

impl ExpandedHttpContext for TestCacheContext {}

impl HttpContext for TestCacheContext {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {

        let token = match self.get_http_request_header("Authorization") {
            Some(token) => token,
            None => {
                self.send_http_error(HttpError::new(401, "Unauthorized".to_string()));
                return Action::Pause;
            }
        };

        let jwt = match JWT::from_token(&token) {
            Ok(jwt) => jwt,
            Err(http_error) => {
                self.send_http_error(http_error);
                return Action::Pause;
            }
        };

        match jwt.validate_claim_value("iss", &vec!["iss1".to_string(), "iss2".to_string()]) {
            Ok(_) => (),
            Err(http_error) => {
                self.send_http_error(http_error);
                return Action::Pause;
            }
        }

        let issuer = jwt.claims_set.get::<String>("iss").unwrap(); 

        let issuer_token = match self.read_from_cache(
            &issuer, 
            |data| {
                match serde_json::from_slice(data) {
                    Ok(okta_cache_data) => Ok(okta_cache_data),
                    Err(_) => Err(HttpError::new(500, "Error parsing Okta cache data.".to_string())),
                }
            }
        ) {
            Some(issuer_token) => issuer_token,
            None => {
                match self.write_to_cache(
                    &issuer,
                    OktaCacheData::new(
                        "issuer".to_string(), 
                        "some_e".to_string(), 
                        "some_n".to_string(), 
                        "some_exp".to_string()
                    )
                ) {
                    Ok(cache_data) => cache_data,
                    Err(http_error) => {
                        self.send_http_error(http_error);
                        return Action::Pause;
                    }
                }
            }
        };

        let issuer_token = match serde_json::to_string(issuer_token) {
            Ok(issuer_token) => issuer_token,
            Err(_) => {
                self.send_http_error(HttpError::new(500, "Error serializing Okta cache data.".to_string()));
                return Action::Pause;
            }
        };

        self.send_http_response(200, vec![("", "")], Some(issuer_token.as_bytes()));
        Action::Continue
    }
}

impl Context for TestCacheContext {

}

impl CacheCapability<OktaCacheData> for TestCacheContext {
    fn get_local_cache(&self) -> &Cache<OktaCacheData> {
        &self.cache_okta_data
    }

    fn get_mut_local_cache(&mut self) -> &mut Cache<OktaCacheData> {
        &mut self.cache_okta_data
    }
}