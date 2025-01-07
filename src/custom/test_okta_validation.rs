use std::collections::HashMap;

use chrono::Utc;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;

use crate::core::capabilities::auth::jwt::*;
use crate::core::capabilities::auth::okta::OktaCacheIssuerData;
use crate::core::capabilities::auth::okta::OktaValidatorCapability;
use crate::core::capabilities::auth::okta::OktaValidatorConfig;
use crate::core::capabilities::cache::Cache;
use crate::core::capabilities::cache::CacheCapability;
use crate::core::capabilities::logger::*;
use crate::core::error::HttpError;
use crate::core::expansion::ExpandedHttpContext;

pub struct TestOktaContext {
    policy_config: TestOktaPolicyConfig,
    okta_cache: Cache<OktaCacheIssuerData>,
    okta_validator_config: OktaValidatorConfig,
    jwt : Option<JWT>,
}

#[doc = "The configuration for the policy.
\n\r Must match schema.json properties."]
#[derive(Default, Clone, Deserialize)]
pub struct TestOktaPolicyConfig {

    #[serde(alias = "do-validate-algorithm")]
    pub do_validate_algorithm: Option<bool>,

    #[serde(alias = "valid-algorithms")]
    pub valid_algorithms: Option<Vec<String>>,

    #[serde(alias = "do-validate-issuer")]
    pub do_validate_issuer: Option<bool>,

    #[serde(alias = "valid-issuers")]
    pub valid_issuers: Option<Vec<String>>,

    #[serde(alias = "do-validate-audience")]
    pub do_validate_audience: Option<bool>,

    #[serde(alias = "valid-audiences")]
    pub valid_audiences: Option<Vec<String>>,

    #[serde(alias = "do-validate-scope")]
    pub do_validate_scope: Option<bool>,

    #[serde(alias = "valid-scopes")]
    pub valid_scopes: Option<Vec<String>>,

    #[serde(alias = "do-validate-expiration")]
    pub do_validate_expiration: Option<bool>,

    #[serde(alias = "log-level")]
    pub log_level: Option<String>,
}

impl TestOktaContext {
    pub fn new(policy_config : TestOktaPolicyConfig) -> Self {

        proxy_wasm::set_log_level(match &policy_config.log_level {
            Some(log_level) => match LOG_LEVELS.get(log_level) {
                Some(log_level) => *log_level,
                None => LogLevel::Trace
            },
            None => LogLevel::Trace
        });

        let context = TestOktaContext {
            policy_config,
            okta_cache: Cache::new(),
            okta_validator_config: OktaValidatorConfig::new(
                10, 
                HashMap::from([
                    ("rlus-int-nonprod.oktapreview.com".to_string(), "okta-nonprod.default.svc".to_string()),
                    ("rlus.okta.com".to_string(), "okta-prod.default.svc".to_string()),
                    ("rlus-ext-dev.oktapreview.com".to_string(), "okta-nonprod-ext-dev.default.svc".to_string()),
                    ("rlus.oktapreview.com".to_string(), "okta-nonprod-ext-preprod.default.svc".to_string()),
                    ("rlus-ext-test.oktapreview.com".to_string(), "okta-nonprod-ext-test.default.svc".to_string()),
                    ("rlus-ext.okta.com".to_string(), "okta-prod-ext-prod.default.svc".to_string()),
                    ("rlus-int-dev.okta.com".to_string(), "rlus-okta-internal-dev.default.svc".to_string()),
                    ("rlus-int-test.okta.com".to_string(), "rlus-okta-internal-test.default.svc".to_string()),
                    ("default".to_string(), "okta-nonprod.default.svc".to_string())
                ]), 
                "okta-issuer-cache".to_string(), 
                10
            ),
            jwt : None,
        };
    
        return context;
    }
}

impl Context for TestOktaContext {
    fn on_http_call_response(&mut self, token_id: u32, num_headers: usize, body_size: usize, num_trailers: usize) {
        match self.response_okta_validation(token_id, num_headers, body_size, num_trailers) {
            Ok(()) => self.resume_http_request(),
            Err(http_error) => self.send_http_error(http_error),
        }
    }
}

impl HttpContext for TestOktaContext {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {

        let token: String = match self.get_http_request_header("Authorization") {
            Some(auth) => auth,
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
        let jwt: JWT = match JWT::from_token(&token) {
            Ok(jwt) => jwt,
            Err(http_error) => {
                self.send_http_error(http_error);
                return Action::Pause;
            }
        };

        if let Err(http_error) = {
            if self.policy_config.do_validate_algorithm.is_some() && self.policy_config.valid_algorithms.is_some() {
                let result = jwt.validate_algorithm(self.policy_config.valid_algorithms.as_ref().unwrap());
                result
            } else {Ok(())}
        }.and_then(|_| {
            if self.policy_config.do_validate_issuer.is_some() && self.policy_config.valid_issuers.is_some() {
                let result = jwt.validate_claim_value::<String>(
                    JWTRegisteredClaims::Issuer.id(), 
                    self.policy_config.valid_issuers.as_ref().unwrap(),
                );
                result
            } else {Ok(())}
        }).and_then(|_| {
            if self.policy_config.do_validate_audience.is_some() && self.policy_config.valid_audiences.is_some() {
                let result = jwt.validate_claim_value::<String>(
                    JWTRegisteredClaims::Audience.id(), 
                    self.policy_config.valid_audiences.as_ref().unwrap(),
                );
                result
            } else {Ok(())}
        }).and_then(|_| {
            if self.policy_config.do_validate_scope.is_some() && self.policy_config.valid_scopes.is_some() {
                let result = jwt.validate_claim_value::<String>(
                    "scp", 
                    self.policy_config.valid_scopes.as_ref().unwrap(),
                );
                result
            } else {Ok(())}
        }).and_then(|_| {
            if self.policy_config.do_validate_expiration.is_some() {
                let result = jwt.validate_expiration();
                result
            } else {Ok(())}
        }) {
            self.send_http_error(http_error);
            return Action::Pause;
        }

        let kid = match jwt.claims.get::<String>("kid") {
            Ok(kid) => kid,
            Err(http_error) => {
                self.send_http_error(http_error);
                return Action::Pause;
            }
        };

        let issuer = jwt.claims.get::<String>(JWTRegisteredClaims::Issuer.id()).unwrap();

        Logger::log_debug("Claims validated.");

        let do_call_okta = match self.read_from_cache(&issuer, |data| {
            serde_json::from_slice(data).map_err(|_| HttpError::new(500, "Error parsing Okta cache data.".to_string()))
        }) {
            // Issuer found in cache
            Some(issuer_data) => match issuer_data.keys.get(kid.as_str()) {
                // Issuer KID found
                Some(issuer_key_data) => {
                    if Utc::now().timestamp() < issuer_key_data.exp {
                        // JWK not expired, dont need to call Okta
                        false
                    } else {
                        // JWK expired, remove KID, need to call Okta
                        let mut issuer_data = issuer_data.clone();
                        issuer_data.keys.remove(kid.as_str());
                        let _ = self.write_to_cache(&issuer, issuer_data);
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
            match self.request_okta_validation() {
                Ok(()) => {
                    return Action::Pause;
                },
                Err(http_error) => {
                    self.send_http_error(http_error);
                    return Action::Continue;
                }
            }
        }

        Action::Continue
    }
}

impl ExpandedHttpContext for TestOktaContext {}

impl JWTHttpCapability for TestOktaContext {
    fn get_jwt(&self) -> Option<&JWT> {
        self.jwt.as_ref()
    }
    
    fn get_mut_jwt(&mut self) -> Option<&mut JWT> {
        self.jwt.as_mut()
    }
}

impl CacheCapability<OktaCacheIssuerData> for TestOktaContext {
    fn get_local_cache(&self) -> &Cache<OktaCacheIssuerData> {
        &self.okta_cache
    }

    fn get_mut_local_cache(&mut self) -> &mut Cache<OktaCacheIssuerData> {
        &mut self.okta_cache
    }
}

impl OktaValidatorCapability for TestOktaContext {
    fn get_okta_validator_config(&self) -> &OktaValidatorConfig {
        &self.okta_validator_config
    }
}