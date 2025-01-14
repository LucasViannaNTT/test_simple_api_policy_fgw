use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;

use crate::core::capabilities::auth::jwt::*;
use crate::core::error::HttpError;
use crate::core::expansion::ExpandedHttpContext;
use crate::core::logger::Logger;
use crate::core::logger::LOG_LEVELS;

pub struct TestJwtContext {
    policy_config: PolicyConfig,
    jwt : Option<JWT>,
}

#[doc = "The configuration for the policy.
\n\r Must match schema.json properties."]
#[derive(Default, Clone, Deserialize)]
pub struct PolicyConfig {

    #[serde(alias = "do-validate-issuer")]
    pub do_validate_issuer: Option<bool>,

    #[serde(alias = "do-validate-audience")]
    pub do_validate_audience: Option<bool>,

    #[serde(alias = "do-validate-expiration")]
    pub do_validate_expiration: Option<bool>,

    #[serde(alias = "do-validate-algorithm")]
    pub do_validate_algorithm: Option<bool>,

    #[serde(alias = "valid-issuers")]
    pub valid_issuers: Option<Vec<String>>,

    #[serde(alias = "valid-audiences")]
    pub valid_audiences: Option<Vec<String>>,

    #[serde(alias = "valid-algorithms")]
    pub valid_algorithms: Option<Vec<String>>,

    #[serde(alias = "log-level")]
    pub log_level: Option<String>,
}

impl TestJwtContext {
    pub fn new(policy_config : PolicyConfig) -> Self {
        let _ = match &policy_config.log_level {
            Some(log_level) => match LOG_LEVELS.get(log_level) {
                Some(log_level) => *log_level,
                None => LogLevel::Trace
            },
            None => LogLevel::Trace
        };

        let context = TestJwtContext {
            policy_config,
            jwt : None,
        };
    
        return context;
    }
}

impl Context for TestJwtContext {}

impl HttpContext for TestJwtContext {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {

        let token: String = match self.get_http_request_header("Authorization") {
            Some(auth) => auth,
            None => {
                self.send_http_error(HttpError::new(401, "Unauthorized".to_string()));
                return Action::Pause;
            }
        };

        if let Err(http_error) = JWT::validate_token_format_with_bearer(&token) {
            self.send_http_error(http_error);
            return Action::Pause;
        }

        let token = token.split(" ").collect::<Vec<&str>>()[1].to_string();
        self.jwt = match JWT::from_token(&token) {
            Ok(jwt) => Some(jwt),
            Err(http_error) => {
                self.send_http_error(http_error);
                return Action::Pause;
            }
        };

        let jwt = self.jwt.as_ref().unwrap();

        if let Err(http_error) = {
            if self.policy_config.do_validate_algorithm.is_some() && self.policy_config.valid_algorithms.is_some() {
                jwt.validate_claim_value("alg", self.policy_config.valid_algorithms.as_ref().unwrap())
            } else {Ok(())}
        }.and_then(|_| {
            if self.policy_config.do_validate_issuer.is_some() && self.policy_config.valid_issuers.is_some() {
                jwt.validate_claim_value::<String>("iss", self.policy_config.valid_issuers.as_ref().unwrap())
            } else {Ok(())}
        }).and_then(|_| {
            if self.policy_config.do_validate_audience.is_some() && self.policy_config.valid_audiences.is_some() {
                jwt.validate_claim_value::<String>("aud", self.policy_config.valid_audiences.as_ref().unwrap())
            } else {Ok(())}
        }).and_then(|_| {
            if self.policy_config.do_validate_expiration.is_some() {
                jwt.validate_expiration()
            } else {Ok(())}
        })
        {
            Logger::log_debug("Error validating claims.");
            self.send_http_error(http_error);
            return Action::Pause;
        }

        Logger::log_debug("Claims validated.");
        Action::Continue
    }
}

impl ExpandedHttpContext for TestJwtContext {}

impl JWTHttpCapability for TestJwtContext {
    fn get_jwt(&self) -> &JWT {
        self.jwt.as_ref().unwrap()
    }
    
    fn get_mut_jwt(&mut self) -> &mut JWT {
        self.jwt.as_mut().unwrap()
    }
}