#[doc = "Base functionality for Custom Rust Proxy-Wasm development."]
pub mod core;
#[doc = "Custom functionality for Custom Rust Proxy-Wasm development."]
pub mod custom;

use core::root::HttpRootContext;

use custom::test_cache::TestCacheContext;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use custom::test_jwt_validation::*;

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

fn create_http_context(_ : PolicyConfig) -> Box<dyn HttpContext> {
    Box::new(TestCacheContext::new())
}