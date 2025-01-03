use chrono::Utc;
use proxy_wasm::{traits::{Context, HttpContext}, types::Action};

use crate::core::{capabilities::{auth::{jwt::JWT, okta::OktaCacheEntry}, cache::{Cache, CacheCapability}}, error::HttpError, expansion::ExpandedHttpContext};

pub struct TestCacheContext {
    okta_cache: Cache<OktaCacheEntry>,
}

impl TestCacheContext {
    pub fn new() -> Self {
        TestCacheContext {
            okta_cache: Cache::new(),
        }
    }

    fn fake_okta_call(&mut self, issuer: &String) -> Action {
        // In reality Okta would only send the JWK
        // The Cache Entry would be created by ourselves
        // See okta.rs::create_okta_cache_entry
        let okta_cache_entry = OktaCacheEntry::new(
            issuer.clone(), 
            "some_e".to_string(), 
            "some_n".to_string(), 
            Utc::now().timestamp() + 10
        );
        // We would also need to check KID...
        match self.write_to_cache(&issuer, okta_cache_entry) {
            Ok(_) => (),
            Err(http_error) => {
                self.send_http_error(http_error);
                return Action::Pause;
            }
        }

        Action::Continue
    }
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

        if let Err(http_error) = JWT::validate_token_format(&r"^Bearer [0-9a-zA-Z]*\.[0-9a-zA-Z]*\.[0-9a-zA-Z-_]*$".to_string(), &token) {
            self.send_http_error(http_error);
            return Action::Pause;
        }

        let token = token.split(" ").collect::<Vec<&str>>()[1].to_string();

        let jwt = match JWT::from_token(&token) {
            Ok(jwt) => jwt,
            Err(http_error) => {
                self.send_http_error(http_error);
                return Action::Pause;
            }
        };

        if let Err(http_error) = jwt.validate_claim_value("iss", &vec!["iss1".to_string(), "iss2".to_string()]) {
            self.send_http_error(http_error);
            return Action::Pause;
        }

        let issuer = jwt.claims_set.get::<String>("iss").unwrap(); 

        if let Some(issuer_token) = self.read_from_cache(
            &issuer, 
            |data| {
                match serde_json::from_slice(data) {
                    Ok(okta_cache_data) => Ok(okta_cache_data),
                    Err(_) => Err(HttpError::new(500, "Error parsing Okta cache data.".to_string())),
                }
            }
        ) {
            if Utc::now().timestamp() > issuer_token.exp {
                let _ = self.delete_from_cache(&issuer, true);
                return self.fake_okta_call(&issuer)
            }
        } else {
            return self.fake_okta_call(&issuer)
        }

        let response = format!(
            "[Cache Data] :\r\n {:?}\r\n", 
            serde_json::to_string(self.get_local_cache()).unwrap()
        );

        self.send_http_response(200, vec![], Some(response.as_bytes()));
        Action::Continue
    }
}

impl Context for TestCacheContext {

}

impl CacheCapability<OktaCacheEntry> for TestCacheContext {
    fn get_local_cache(&self) -> &Cache<OktaCacheEntry> {
        &self.okta_cache
    }

    fn get_mut_local_cache(&mut self) -> &mut Cache<OktaCacheEntry> {
        &mut self.okta_cache
    }
}