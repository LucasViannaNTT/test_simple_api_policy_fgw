pub mod root_context;
pub mod http_context;
pub mod config;

use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use root_context::*;
use config::*;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(CustomAuthRootContext {
            config: CustomAuthConfig::default(),
        })
    });
}}