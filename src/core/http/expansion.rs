use chrono::Utc;
use proxy_wasm::traits::HttpContext;

use crate::PolicyConfig;

use super::error::{HttpError, HttpErrorBody};

pub trait ExpandedHttpContext: HttpContext {

    fn new(policy_config : PolicyConfig) -> Self;

    fn get_policy_config(&self) -> &PolicyConfig;

    fn send_http_error(&self, http_error : HttpError) {
        self.send_http_error_custom(http_error.status, http_error.error_message.as_str());
    }

    fn send_http_error_custom(&self, status: u32, error_message: &str) {
        let timestamp: String = Utc::now().to_rfc3339().to_string();
        let error: HttpErrorBody = HttpErrorBody::with_message(
            status, 
            timestamp, 
            error_message.to_string()
        );

        // TODO Add Headers
        self.send_http_response(
            error.status,
            Vec::new(), 
            Some(error.build().as_bytes())
        );
    }
}