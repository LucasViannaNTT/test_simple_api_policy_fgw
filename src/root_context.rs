use proxy_wasm::traits::*;
use proxy_wasm::types::*;

use crate::config::*;
use crate::http_context::*;

pub struct CustomAuthRootContext {
    pub config: CustomAuthConfig,
}

impl Context for CustomAuthRootContext {}

impl RootContext for CustomAuthRootContext {

    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(CustomAuthHttpContext {
            config: self.config.clone(),
        }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn on_configure(&mut self, _: usize) -> bool {
        if let Some(config_bytes) = self.get_plugin_configuration() {
            self.config = serde_json::from_slice(config_bytes.as_slice()).unwrap();
        }

        true
    }
}