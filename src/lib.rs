#[doc = "Base functionality for Custom Rust Proxy-Wasm development."]
pub mod core;
#[doc = "Custom functionality for Custom Rust Proxy-Wasm development."]
pub mod custom;

use core::logger::Logger;
use core::root::HttpRootContext;

use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use custom::rlus_policy_poc::*;

pub const POLICY_ID: &str = "test-simple-api-policy-fgw";

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Debug);
    proxy_wasm::set_root_context(create_root_context);
}}

fn create_root_context(_: u32) -> Box<dyn RootContext> {
    Box::new(HttpRootContext::<RLUSOktaPolicyConfig>::new(
        RLUSOktaPolicyConfig::default(), 
        serialize_policy_config,
        create_http_context
    ))
}

fn serialize_policy_config(data: &[u8]) -> RLUSOktaPolicyConfig {
    match serde_json::from_slice(data) {
        Ok(policy_config) => policy_config,
        Err(error) => {
            Logger::log_info(format!("Error parsing policy config: {:?}", error).as_str());
            RLUSOktaPolicyConfig::default()
        },
    }
}

fn create_http_context(policy_config : RLUSOktaPolicyConfig) -> Box<dyn HttpContext> {
    Box::new(RLUSOktaContext::new(policy_config))
}