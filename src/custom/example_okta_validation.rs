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
use crate::core::error::HttpError;
use crate::core::expansion::ExpandedHttpContext;
use crate::core::logger::Logger;
use crate::core::logger::LOG_LEVELS;

/// Context for testing Okta JWT validation functionality.
/// Handles JWT validation, caching, and Okta integration.
pub struct TestOktaContext {
    policy_config: TestOktaPolicyConfig,
    okta_cache: Cache<OktaCacheIssuerData>,
    okta_validator_config: OktaValidatorConfig,
    jwt : Option<JWT>,
}

/// Configuration for the Okta JWT validation policy.
/// Must match schema.json properties.
#[derive(Default, Clone, Deserialize)]
pub struct TestOktaPolicyConfig {

    #[serde(alias = "do_validate_algorithm")]
    pub do_validate_algorithm: bool,

    #[serde(alias = "valid_algorithms")]
    pub valid_algorithms: Vec<String>,

    #[serde(alias = "do_validate_issuer")]
    pub do_validate_issuer: bool,

    #[serde(alias = "valid_issuers")]
    pub valid_issuers: Vec<String>,

    #[serde(alias = "do_validate_audience")]
    pub do_validate_audience: bool,

    #[serde(alias = "valid_audiences")]
    pub valid_audiences: Vec<String>,

    #[serde(alias = "do_validate_scope")]
    pub do_validate_scope: bool,

    #[serde(alias = "valid_scopes")]
    pub valid_scopes: Vec<String>,

    #[serde(alias = "do_validate_expiration")]
    pub do_validate_expiration: bool,

    #[serde(alias = "log_level")]
    pub log_level: String,
}

impl TestOktaContext {
    pub fn new(policy_config : TestOktaPolicyConfig) -> Self {

        // Set log level from policy config, defaulting to Trace if not specified or invalid
        proxy_wasm::set_log_level(match LOG_LEVELS.get(&policy_config.log_level) {
                Some(log_level) => *log_level,
                None => LogLevel::Trace
            },
        );

        // Create new context with default configuration and predefined Okta endpoints
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
                10
            ),
            jwt : None,
        };
    
        return context;
    }
}

impl Context for TestOktaContext {
    fn on_http_call_response(&mut self, _: u32, _: usize, body_size: usize, _: usize) {
        // Process Okta validation response and resume or error the HTTP request accordingly
        match self.response_okta_validation(body_size) {
            Ok(()) => self.resume_http_request(),
            Err(http_error) => self.send_http_error(http_error),
        }
    }
}

impl HttpContext for TestOktaContext {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        // Extract Authorization header
        let token: String = match self.get_http_request_header("Authorization") {
            Some(auth) => auth,
            None => {
                self.send_http_error(HttpError::new(401, "Unauthorized".to_string()));
                return Action::Pause;
            }
        };

        // Validate token format matches Bearer token pattern
        Logger::log_info("Validating Bearer...");
        if let Err(http_error) = JWT::validate_token_format_with_bearer(&token) {
            self.send_http_error(http_error);
            return Action::Pause;
        }

        // Parse JWT from token
        Logger::log_info("Parsing JWT...");
        let token = token.split(" ").collect::<Vec<&str>>()[1].to_string();
        self.jwt = match JWT::from_token(&token) {
            Ok(jwt) => Some(jwt),
            Err(http_error) => {
                self.send_http_error(http_error);
                return Action::Pause;
            }
        };

        let jwt = self.jwt.as_ref().unwrap();
        Logger::log_debug(format!("JWT {:?}", jwt).as_str());

        // Perform all configured validations
        Logger::log_info("Starting Validations...");

        // Algorithm Validation
        if self.policy_config.do_validate_algorithm && !self.policy_config.valid_algorithms.is_empty() {
            Logger::log_info("Validating Algorithm");
            if let Err(http_error) = jwt.validate_header_value("alg", &self.policy_config.valid_algorithms) {
                self.send_http_error(http_error);
                return Action::Pause;
            }
        }

        // Issuer Validation
        if self.policy_config.do_validate_issuer && !self.policy_config.valid_issuers.is_empty() {
            Logger::log_info("Validating Issuers");
            if let Err(http_error) = jwt.validate_claim_value::<String>("iss",&self.policy_config.valid_issuers) {
                self.send_http_error(http_error);
                return Action::Pause;
            }
        }

        // Audience Validation
        if self.policy_config.do_validate_audience && !self.policy_config.valid_audiences.is_empty() {
            Logger::log_info("Validating Audiences");
            if let Err(http_error) = jwt.validate_claim_value::<String>("aud",&self.policy_config.valid_audiences) {
                self.send_http_error(http_error);
                return Action::Pause;
            }
        }

        // Scope Validation
        if self.policy_config.do_validate_scope && !self.policy_config.valid_scopes.is_empty() {
            Logger::log_info("Validating Scopes");
            if let Err(http_error) = jwt.validate_multiple_claim_values::<String>("scp",&self.policy_config.valid_scopes) {
                self.send_http_error(http_error);
                return Action::Pause;
            }
        }

        // Expiration Validation
        if self.policy_config.do_validate_expiration {
            Logger::log_info("Validating Expiration");
            if let Err(http_error) = jwt.validate_expiration() {
                self.send_http_error(http_error);
                return Action::Pause;
            }
        }

        // KID Expected
        Logger::log_info("Expecting KID...");
        if let Err(http_error) = jwt.expect_header("kid") {
            self.send_http_error(http_error);
            return Action::Pause;
        }

        Logger::log_info("Validating KID...");
        // Extract key ID from JWT header
        // We can unwrap since we've already expected "kid"
        let kid = jwt.header.get::<String>("kid").unwrap();

        // Get issuer from claims
        // We can unwrap since we've already validated "iss"
        let issuer = jwt.claims.get::<String>("iss").unwrap();

        // Check if we need to call Okta for validation
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
                        // Overwrite entry with updated issuer data
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
            Logger::log_info("Calling Okta...");
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
    fn get_jwt(&self) -> &JWT {
        self.jwt.as_ref().unwrap()
    }
    
    fn get_mut_jwt(&mut self) -> &mut JWT {
        self.jwt.as_mut().unwrap()
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