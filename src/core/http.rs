pub mod error;

use proxy_wasm::traits::*;
use proxy_wasm::types::*;

use crate::config::*;

pub struct HttpRootContext {
    pub policy_config: PolicyConfig,
    pub create_http_context: fn(PolicyConfig) -> Box<dyn HttpContext>,
}

impl HttpRootContext {
    pub fn new(
        policy_config : PolicyConfig, 
        create_http_context : fn(PolicyConfig) -> Box<dyn HttpContext>
    ) -> Self {
        HttpRootContext {
            policy_config,
            create_http_context,
        }
    }
}

impl Context for HttpRootContext {}

impl RootContext for HttpRootContext {

    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        Some((self.create_http_context)(self.policy_config.clone()))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn on_configure(&mut self, _: usize) -> bool {
        if let Some(config_bytes) = self.get_plugin_configuration() {
            self.policy_config = serde_json::from_slice(config_bytes.as_slice()).unwrap();
        }

        true
    }
}