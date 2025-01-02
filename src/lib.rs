pub mod core;
pub mod config;
pub mod context;

use core::root::HttpRootContext;

use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use test_jwt_validation::CustomHttpContext;
use config::*;
use context::*;

pub const POLICY_ID: &str = "test-simple-api-policy-fgw";

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Debug);
    proxy_wasm::set_root_context(create_root_context);
}}

fn create_root_context(_: u32) -> Box<dyn RootContext> {
    Box::new(HttpRootContext::<PolicyConfig>::new(
        PolicyConfig::default(), 
        serialize_policy_config,
        create_http_context
    ))
}

fn serialize_policy_config(data: &[u8]) -> PolicyConfig {
    match serde_json::from_slice(data) {
        Ok(policy_config) => policy_config,
        Err(_) => PolicyConfig::default(),
    }
}

fn create_http_context(policy_config : PolicyConfig) -> Box<dyn HttpContext> {
    Box::new(CustomHttpContext::new(policy_config))
}