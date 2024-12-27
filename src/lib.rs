pub mod core;
pub mod config;
pub mod imp;

use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use core::http::expansion::ExpandedHttpContext;
use core::http::root::*;
use config::*;
use imp::*;

pub static POLICY_ID: &str = "test-simple-api-policy-fgw";

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(create_root_context);
}}

fn create_root_context(_: u32) -> Box<dyn RootContext> {
    Box::new(HttpRootContext::new(PolicyConfig::default(), create_http_context))
}

fn create_http_context(policy_config : PolicyConfig) -> Box<dyn HttpContext> {
    Box::new(CustomHttpContext::new(policy_config))
}