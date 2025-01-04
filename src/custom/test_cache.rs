use chrono::Utc;
use proxy_wasm::{traits::{Context, HttpContext}, types::Action};

use crate::core::{capabilities::{auth::{jwt::JWT, okta::{OktaCacheData, OktaJWK}}, cache::{Cache, CacheCapability}}, error::HttpError, expansion::ExpandedHttpContext};

pub struct TestCacheContext {
    okta_cache: Cache<OktaCacheData>,
}

impl TestCacheContext {
    pub fn new() -> Self {
        TestCacheContext {
            okta_cache: Cache::new(),
        }
    }

    fn fake_okta_call(&mut self, issuer: &String, kid: &String) -> Action {

        if let Some(jwk) = match issuer.as_str() {
            "iss1" => match kid.as_str() {
                "kid1" => Some(OktaJWK { kid: "kid1".to_string(), e: "123".to_string(), n: "123".to_string() }),
                "kid2" => Some(OktaJWK { kid: "kid2".to_string(),e: "234".to_string(), n: "234".to_string() }),
                _ => None,
            },
            "iss2" => match kid.as_str() {
                "kid1" => Some(OktaJWK { kid: "kid1".to_string(), e: "345".to_string(), n: "345".to_string() }),
                "kid2" => Some(OktaJWK { kid: "kid2".to_string(), e: "456".to_string(), n: "456".to_string() }),
                _ => None,
            },
            _ => None,
        } {
            let mut cache_entry = match self.read_from_cache(issuer.as_str(), |data| {
                serde_json::from_slice(data).map_err(|_| HttpError::new(500, "Error parsing Okta cache data.".to_string()))
            }) {
                Some(cache_entry) => cache_entry.clone(),
                None => OktaCacheData::new(issuer.clone()),
            };

            cache_entry.keys.insert(kid.clone(), (jwk, Utc::now().timestamp() + 10));
            let _ = self.write_to_cache(&issuer, cache_entry);
            return Action::Continue
        }
        
        self.send_http_error(HttpError::new(500, "Error calling Okta.".to_string()));
        Action::Pause
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

        let issuer = match jwt.claims.get::<String>("iss") {
            Ok(issuer) => issuer,
            Err(http_error) => {
                self.send_http_error(http_error);
                return Action::Pause;
            }
        };

        let kid = match jwt.claims.get::<String>("kid") {
            Ok(kid) => kid,
            Err(http_error) => {
                self.send_http_error(http_error);
                return Action::Pause;
            }
        };

        let do_call_okta = match self.read_from_cache(&issuer, |data| {
            serde_json::from_slice(data).map_err(|_| HttpError::new(500, "Error parsing Okta cache data.".to_string()))
        }) {
            // Issuer found in cache
            Some(issuer_entry) => match issuer_entry.keys.get(kid.as_str()) {
                // Issuer KID found
                Some(issuer_jwk) => {
                    if Utc::now().timestamp() < issuer_jwk.1{
                        // JWK not expired, dont need to call Okta
                        false
                    } else {
                        // JWK expired, need to call Okta
                        let _ = self.delete_from_cache(&issuer, true);
                        true
                    }
                },
                // Issuer KID not found, need to call Okta
                None => true
            },
            // Issuer not found in cache, need to call Okta
            None => true
        };
        
        if do_call_okta {
            return self.fake_okta_call(&issuer, &kid);
        }

        let response = format!(
            "[Local Cache Data] :\r\n {:?}\r\n", 
            serde_json::to_string(self.get_local_cache()).unwrap()
        );

        self.send_http_response(200, vec![], Some(response.as_bytes()));
        Action::Continue
    }
}

impl Context for TestCacheContext {}

impl CacheCapability<OktaCacheData> for TestCacheContext {
    fn get_local_cache(&self) -> &Cache<OktaCacheData> {
        &self.okta_cache
    }

    fn get_mut_local_cache(&mut self) -> &mut Cache<OktaCacheData> {
        &mut self.okta_cache
    }
}