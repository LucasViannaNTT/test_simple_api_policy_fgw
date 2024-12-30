use std::collections::HashMap;

use okta::OktaValidator;
use okta::OktaValidatorConfig;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

use crate::config::*;
use crate::core::capabilities::auth::jwt::*;
use crate::core::capabilities::cache::*;
use crate::core::capabilities::logger::*;
use crate::core::http::error::HttpError;
use crate::core::http::expansion::ExpandedHttpContext;
use crate::POLICY_ID;

pub struct CustomHttpContext {
    policy_config: PolicyConfig,
    okta_validator_config : OktaValidatorConfig,
    logger: Logger,
    storage: Storage,
    jwt : Option<JWT>,
}

impl Context for CustomHttpContext {}

impl HttpContext for CustomHttpContext {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {

        self.logger.log_debug("Checking for Authorization header...");
        let token: String = match self.get_http_request_header("Authorization") {
            Some(auth) => auth,
            None => {
                self.send_http_error(HttpError::new(401, "Unauthorized".to_string()));
                return Action::Pause;
            }
        };
        self.logger.log_debug("Token found in Authorization header.");

        self.logger.log_debug("Validating token format...");
        if let Err(http_error) = JWT::validate_token_format(&r"^Bearer [0-9a-zA-Z]*\.[0-9a-zA-Z]*\.[0-9a-zA-Z-_]*$".to_string(), &token) {
            self.send_http_error(http_error);
            return Action::Pause;
        }
        self.logger.log_debug("Token format validated.");

        self.logger.log_debug("Decoding JWT...");

        let token = token.split(" ").collect::<Vec<&str>>()[1].to_string();
        let jwt: JWT = match JWT::from_token(&token) {
            Ok(jwt) => jwt,
            Err(http_error) => {
                self.send_http_error(http_error);
                return Action::Pause;
            }
        };
        self.logger.log_debug("JWT decoded.");
        self.logger.log_debug("JWT: ");
        self.logger.log_debug(&format!("{:?}", jwt));

        self.logger.log_debug("Validating claims...");
        if let Err(http_error) = {
            if self.policy_config.do_validate_algorithm.is_some() && self.policy_config.valid_algorithms.is_some() {
                let result = jwt.validate_algorithm(self.policy_config.valid_algorithms.as_ref().unwrap());
                self.logger.log_debug(&format!("Valid Algorithm: {}", result.is_ok()));
                result
            } else {Ok(())}
        }.and_then(|_| {
            if self.policy_config.do_validate_issuer.is_some() && self.policy_config.valid_issuers.is_some() {
                let result = jwt.validate_claim_value::<String>(
                    JWTRegisteredClaims::Issuer.id(), 
                    self.policy_config.valid_issuers.as_ref().unwrap(),
                );
                self.logger.log_debug(&format!("Valid Issuer: {}", result.is_ok()));
                result
            } else {Ok(())}
        }).and_then(|_| {
            if self.policy_config.do_validate_audience.is_some() && self.policy_config.valid_audiences.is_some() {
                let result = jwt.validate_claim_value::<String>(
                    JWTRegisteredClaims::Audience.id(), 
                    self.policy_config.valid_audiences.as_ref().unwrap(),
                );
                self.logger.log_debug(&format!("Valid Audience: {}", result.is_ok()));
                result
            } else {Ok(())}
        }).and_then(|_| {
            if self.policy_config.do_validate_expiration.is_some() {
                let result = jwt.validate_expiration();
                self.logger.log_debug(&format!("Valid Expiration: {}", result.is_ok()));
                result
            } else {Ok(())}
        }).and_then(|_| {
            self.request_okta_validation()
        })
        {
            self.logger.log_debug("Error validating claims.");
            self.send_http_error(http_error);
            return Action::Pause;
        }
        
        self.logger.log_debug("Claims validated.");
        Action::Continue
    }
}

impl ExpandedHttpContext for CustomHttpContext {
    fn new(policy_config : PolicyConfig) -> Self {
        let log_level = match &policy_config.log_level {
            Some(log_level) => match LOG_LEVELS.get(log_level) {
                Some(log_level) => *log_level,
                None => LogLevel::Trace
            },
            None => LogLevel::Trace
        };

        let context = CustomHttpContext {
            policy_config,
            okta_validator_config : OktaValidatorConfig {
                timeout: 60,
                upstream : HashMap::from([
                    ("rlus-int-nonprod.oktapreview.com".to_string(), "okta-nonprod.default.svc".to_string())
                ]),
                jwk_cache_id : "okta-jwk-cache".to_string(),
                jwk_cache_ttl : 1000,
            },
            logger : Logger::new(POLICY_ID.to_string(), log_level),
            storage : Storage::new(),
            jwt : None,
        };
        return context;
    }
    
    fn get_policy_config(&self) -> &PolicyConfig {
        &self.policy_config
    }
}

impl LoggerContext for CustomHttpContext {
    fn get_logger(&self) -> &Logger {
        &self.logger
    }
}

impl JWTHttpContext for CustomHttpContext {
    fn get_jwt(&self) -> Option<&JWT> {
        self.jwt.as_ref()
    }
    
    fn get_mut_jwt(&mut self) -> Option<&mut JWT> {
        self.jwt.as_mut()
    }
}

impl StorageContext for CustomHttpContext {
    fn get_mut_storage(&mut self) -> &mut Storage {
        &mut self.storage
    }
    
    fn get_storage(&self) -> &Storage {
        &self.storage
    }
}

impl OktaValidator for CustomHttpContext {
    fn get_okta_validator_config(&self) -> &OktaValidatorConfig {
        &self.okta_validator_config
    }
}