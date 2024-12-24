use proxy_wasm::traits::*;
use proxy_wasm::types::*;

use crate::config::*;
use crate::core::auth::jwt::Jwt;
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

        let _x_custom_auth = match self.get_http_request_header("x-custom-auth") {
            Some(value) => value,
            None => {
                self.send_http_error_custom(401, "Unauthorized");
                return Action::Pause;
            }
        };

        let auth = match self.get_http_request_header("Authorization") {
            Some(auth) => auth,
            None => {
                self.send_http_error_custom(401, "Unauthorized");
                return Action::Pause;
            }
        };

        let jwt = match Jwt::from_token(auth) {
            Ok(jwt) => jwt,
            Err(http_error) => {
                self.send_http_error(http_error);
                return Action::Pause;
            }
        };

        if let Err(http_error) = jwt.validate_algorithm("HS256") {
            self.send_http_error(http_error);
            return Action::Pause;
        }
        
        self.send_http_error_custom(401, "Unauthorized");
        Action::Pause
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