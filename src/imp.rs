use proxy_wasm::traits::*;
use proxy_wasm::types::*;

use crate::config::*;
use crate::core::auth::jwt::JWT;
use crate::core::cache::Cache;
use crate::core::cache::CacheHttpContext;
use crate::core::http::expansion::ExpandedHttpContext;
use crate::core::logger::Logger;
use crate::core::logger::LoggerHttpContext;

#[derive(Default)]
pub struct CustomHttpContext {
    pub policy_config: PolicyConfig,
    pub logger: Logger,
    pub cache: Cache,
}

impl Context for CustomHttpContext {}

impl HttpContext for CustomHttpContext {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {

        let token: String = match self.get_http_request_header("Authorization") {
            Some(auth) => auth,
            None => {
                self.send_http_error_custom(401, "Unauthorized");
                return Action::Pause;
            }
        };

        if let Err(http_error) = JWT::validate_token_format(&r"^Bearer [0-9a-zA-Z]*\.[0-9a-zA-Z]*\.[0-9a-zA-Z-_]*$".to_string(), &token) {
            self.send_http_error(http_error);
            return Action::Pause;
        }

        let jwt: JWT = match JWT::from_token(&token) {
            Ok(jwt) => jwt,
            Err(http_error) => {
                self.send_http_error(http_error);
                return Action::Pause;
            }
        };

        if let Err(http_error) = {
                if self.policy_config.do_validate_algorithm  {jwt.validate_algorithm(&self.policy_config.valid_algorithms)} else {Ok(())}
            }.and_then(|_| {
                if self.policy_config.do_validate_issuer {jwt.validate_issuer(&self.policy_config.valid_issuers)} else {Ok(())}
            }).and_then(|_| {
                if self.policy_config.do_validate_audience {jwt.validate_audience(&self.policy_config.valid_audiences)} else {Ok(())}
            }).and_then(|_| {
                if self.policy_config.do_validate_expiration {jwt.validate_expiration()} else {Ok(())}
            })
        {
            self.send_http_error(http_error);
            return Action::Pause;
        }
        
        Action::Continue
    }
}

impl ExpandedHttpContext for CustomHttpContext {
    fn new(policy_config : PolicyConfig) -> Self {
        let context = CustomHttpContext {
            policy_config,
            logger: Logger::new(),
            cache: Cache::new(),
        };
        return context;
    }
    
    fn get_policy_config(&self) -> &PolicyConfig {
        &self.policy_config
    }
}

impl CacheHttpContext for CustomHttpContext {
    fn get_cache(&self) -> &Cache {
        &self.cache
    }
}

impl LoggerHttpContext for CustomHttpContext {
    fn get_logger(&self) -> &Logger {
        &self.logger
    }
}