use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use chrono::Utc;

use crate::config::*;
use crate::core::http::error::*;

#[derive(Default)]
pub struct ExpandedHttpContext {
    pub policy_config: PolicyConfig,
}

impl ExpandedHttpContext {
    pub fn new(policy_config : PolicyConfig) -> Self {
        ExpandedHttpContext {
            policy_config,
        }
    }
}

impl Context for ExpandedHttpContext {}

impl HttpContext for ExpandedHttpContext {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {

        if let Some(value) = self.get_http_request_header("x-custom-auth") {
            if self.policy_config.secret_value == value {
                return Action::Continue;
            }
        }

        let status = 401;
        let error = ErrorBody::with_message(
            status, 
            Utc::now().to_rfc3339().to_string(), 
            "Message Error".to_string()
        );

        self.send_http_response(
            error.status, 
            Vec::new(), 
            Some(error.build().as_bytes())
        );

        Action::Pause
    }
}
