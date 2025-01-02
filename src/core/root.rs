
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

pub struct HttpRootContext<T: Clone> {
    pub policy_config: T,
    pub serialize: fn(&[u8]) -> T,
    pub create_http_context: fn(T) -> Box<dyn HttpContext>,
}

impl<T: Clone> HttpRootContext<T> {
    pub fn new(
        policy_config : T, 
        serialize : fn(&[u8]) -> T,
        create_http_context : fn(T) -> Box<dyn HttpContext>
    ) -> Self {
        HttpRootContext {
            policy_config,
            serialize,
            create_http_context,
        }
    }
}

impl<T: Clone> Context for HttpRootContext<T> {}

impl<T: Clone> RootContext for HttpRootContext<T> {

    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        Some((self.create_http_context)(self.policy_config.clone()))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn on_configure(&mut self, _: usize) -> bool {
        if let Some(config_bytes) = self.get_plugin_configuration() {
            self.policy_config = (self.serialize)(config_bytes.as_slice());
        }

        true
    }
}