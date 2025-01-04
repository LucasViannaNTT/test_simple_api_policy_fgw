use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;

use crate::core::capabilities::auth::jwt::*;
use crate::core::capabilities::logger::*;
use crate::core::error::HttpError;
use crate::core::expansion::ExpandedHttpContext;

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

        Logger::log_debug("Checking for Authorization header...");
        let token: String = match self.get_http_request_header("Authorization") {
            Some(auth) => auth,
            None => {
                self.send_http_error(HttpError::new(401, "Unauthorized".to_string()));
                return Action::Pause;
            }
        };
        Logger::log_debug("Token found in Authorization header.");

        Logger::log_debug("Validating token format...");
        if let Err(http_error) = JWT::validate_token_format(&r"^Bearer [0-9a-zA-Z]*\.[0-9a-zA-Z]*\.[0-9a-zA-Z-_]*$".to_string(), &token) {
            self.send_http_error(http_error);
            return Action::Pause;
        }
        Logger::log_debug("Token format validated.");

        Logger::log_debug("Decoding JWT...");

        let token = token.split(" ").collect::<Vec<&str>>()[1].to_string();
        let jwt: JWT = match JWT::from_token(&token) {
            Ok(jwt) => jwt,
            Err(http_error) => {
                self.send_http_error(http_error);
                return Action::Pause;
            }
        };
        Logger::log_debug("JWT decoded.");
        Logger::log_debug("JWT: ");
        Logger::log_debug(&format!("{:?}", jwt));

        Logger::log_debug("Validating claims...");
        if let Err(http_error) = {
            if self.policy_config.do_validate_algorithm.is_some() && self.policy_config.valid_algorithms.is_some() {
                let result = jwt.validate_algorithm(self.policy_config.valid_algorithms.as_ref().unwrap());
                Logger::log_debug(&format!("Valid Algorithm: {}", result.is_ok()));
                result
            } else {Ok(())}
        }.and_then(|_| {
            if self.policy_config.do_validate_issuer.is_some() && self.policy_config.valid_issuers.is_some() {
                let result = jwt.validate_claim_value::<String>(
                    JWTRegisteredClaims::Issuer.id(), 
                    self.policy_config.valid_issuers.as_ref().unwrap(),
                );
                Logger::log_debug(&format!("Valid Issuer: {}", result.is_ok()));
                result
            } else {Ok(())}
        }).and_then(|_| {
            if self.policy_config.do_validate_audience.is_some() && self.policy_config.valid_audiences.is_some() {
                let result = jwt.validate_claim_value::<String>(
                    JWTRegisteredClaims::Audience.id(), 
                    self.policy_config.valid_audiences.as_ref().unwrap(),
                );
                Logger::log_debug(&format!("Valid Audience: {}", result.is_ok()));
                result
            } else {Ok(())}
        }).and_then(|_| {
            if self.policy_config.do_validate_expiration.is_some() {
                let result = jwt.validate_expiration();
                Logger::log_debug(&format!("Valid Expiration: {}", result.is_ok()));
                result
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
    fn get_jwt(&self) -> Option<&JWT> {
        self.jwt.as_ref()
    }
    
    fn get_mut_jwt(&mut self) -> Option<&mut JWT> {
        self.jwt.as_mut()
    }
}