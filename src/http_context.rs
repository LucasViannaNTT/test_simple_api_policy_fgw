use proxy_wasm::traits::*;
use proxy_wasm::types::*;

use crate::config::*;

pub struct CustomAuthHttpContext {
    pub config: CustomAuthConfig,
}

impl Context for CustomAuthHttpContext {}

impl HttpContext for CustomAuthHttpContext {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {

        if let Some(value) = self.get_http_request_header("x-custom-auth") {
            if self.config.secret_value == value {
                return Action::Continue;
            }
        }

        self.send_http_response(401, Vec::new(), None);

        Action::Pause
    }
}