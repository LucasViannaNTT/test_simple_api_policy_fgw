use std::{collections::HashMap, sync::LazyLock};
use proxy_wasm::{hostcalls::log, types::LogLevel};

use crate::POLICY_ID;

pub const LOG_LEVEL_TRACE: &str = "TRACE";
pub const LOG_LEVEL_DEBUG: &str = "DEBUG";
pub const LOG_LEVEL_INFO: &str = "INFO";
pub const LOG_LEVEL_WARN: &str = "WARN";
pub const LOG_LEVEL_ERROR: &str = "ERROR";

#[doc = "Log Levels for Deserialization."]
// LazyLock enables the creation of the hashmap on its first access.
pub const LOG_LEVELS: LazyLock<HashMap<String, LogLevel>> = LazyLock::new(|| { 
    HashMap::from([
        (String::from(LOG_LEVEL_INFO), LogLevel::Info),
        (String::from(LOG_LEVEL_ERROR), LogLevel::Error),
        (String::from(LOG_LEVEL_WARN), LogLevel::Warn),
        (String::from(LOG_LEVEL_DEBUG), LogLevel::Debug),
        (String::from(LOG_LEVEL_TRACE), LogLevel::Trace),
    ])
});

/// Provides logging functionality
pub struct Logger {}

impl Logger {

    /// Logs a trace message.
    pub fn log_trace(message: &str) {
        let message = format!("[{}] [TRACE]: {}", POLICY_ID, message);
        let _ = log(LogLevel::Trace, message.as_str());
    }

    /// Logs an info message.
    pub fn log_info(message: &str) {
        let message = format!("[{}] [INFO]: {}", POLICY_ID, message);
        let _ = log(LogLevel::Info, message.as_str());
    }
    
    /// Logs a debug message.
    pub fn log_debug(message: &str) {
        let message = format!("[{}] [DEBUG]: {}", POLICY_ID, message);
        let _ = log(LogLevel::Debug, message.as_str());
    }

    /// Logs an warn message.
    pub fn log_warn(message: &str) {
        let message = format!("[{}] [WARN]: {}", POLICY_ID, message);
        let _ = log(LogLevel::Warn, message.as_str());
    }
    
    /// Logs an error message.
    pub fn log_error(message: &str) {
        let message = format!("[{}] [ERROR]: {}", POLICY_ID, message);
        let _ = log(LogLevel::Error, message.as_str());
    }
}