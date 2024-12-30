use chrono::Utc;
use proxy_wasm::traits::HttpContext;

use crate::PolicyConfig;

use super::error::{HttpError, HttpErrorBody};

pub trait ExpandedHttpContext: HttpContext {

    fn new(policy_config : PolicyConfig) -> Self;

    fn get_policy_config(&self) -> &PolicyConfig;

    fn send_http_error(&self, http_error : HttpError) {
        let timestamp: String = Utc::now().to_rfc3339().to_string();
        let error: HttpErrorBody = HttpErrorBody::with_message(
            http_error.status, 
            timestamp, 
            http_error.error_message
        );

        // TODO Add Headers
        self.send_http_response(
            error.status,
            Vec::new(), 
            Some(error.to_json().as_bytes())
        );
    }
}