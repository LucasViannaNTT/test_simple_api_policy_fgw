use std::{collections::HashMap, sync::LazyLock};

use log::{debug, error, info, trace, warn};
use proxy_wasm::{traits::Context, types::LogLevel};

pub const LOG_LEVEL_TRACE: &str = "TRACE";
pub const LOG_LEVEL_DEBUG: &str = "DEBUG";
pub const LOG_LEVEL_INFO: &str = "INFO";
pub const LOG_LEVEL_WARN: &str = "WARN";
pub const LOG_LEVEL_ERROR: &str = "ERROR";
pub const LOG_LEVEL_CRITICAL: &str = "CRITICAL";

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

#[doc = "The logger for the policy."]
pub struct Logger {
    log_id : u64,
    policy_id : String,
    log_level : LogLevel,
}

impl Logger {

    #[doc = "Creates a new logger."]
    pub fn new(policy_id : String, log_level : LogLevel)-> Self {
        Logger {
            log_id : 0,
            policy_id,
            log_level
        }
    }

    #[doc = "Logs a trace message."]
    pub fn log_trace(&mut self, message: &str) {
        if self.should_log(&LogLevel::Trace) {
            let message = format!("[{}] [TRACE]: {} - {}", self.policy_id, self.log_id, message);
            self.log_id += 1;
            trace!("{}", message);
        }
    }

    #[doc = "Logs an info message."]
    pub fn log_info(&mut self, message: &str) {
        if self.should_log(&LogLevel::Info) {
            let message = format!("[{}] [INFO]: {} - {}", self.policy_id, self.log_id, message);
            self.log_id += 1;
            info!("{}", message);
        }
    }
    
    #[doc = "Logs a debug message."]
    pub fn log_debug(&mut self, message: &str) {
        if self.should_log(&LogLevel::Debug) {
            let message = format!("[{}] [DEBUG]: {} - {}", self.policy_id, self.log_id, message);
            self.log_id += 1;
            debug!("{}", message);
        }
    }

    #[doc = "Logs a warn message."]
    pub fn log_warn(&mut self, message: &str) {
        if self.should_log(&LogLevel::Warn) {
            let message = format!("[{}] [WARN]: {} - {}", self.policy_id, self.log_id, message);
            self.log_id += 1;
            warn!("{}", message);
        }
    }
    
    #[doc = "Logs an error message."]
    pub fn log_error(&mut self, message: &str) {
        if self.should_log(&LogLevel::Error) {
            let message = format!("[{}] [ERROR]: {} - {}", self.policy_id, self.log_id, message);
            self.log_id += 1;
            error!("{}", message);
        }
    }

    #[doc = "Determines if the logger should log the message."]
    fn should_log(&self, log_level: &LogLevel) -> bool {
        match self.log_level {
            LogLevel::Trace => match log_level {
                _ => true
            },
            LogLevel::Debug => match log_level {
                LogLevel::Trace => false,
                _ => true
            },
            LogLevel::Info => match log_level {
                LogLevel::Trace => false,
                LogLevel::Debug => false,
                _ => true
            },
            LogLevel::Warn => match log_level {
                LogLevel::Trace => false,
                LogLevel::Debug => false,
                LogLevel::Info => false,
                _ => true
            }
            LogLevel::Error => match log_level {
                LogLevel::Trace => false,
                LogLevel::Debug => false,
                LogLevel::Info => false,
                LogLevel::Warn => false,
                _ => true
            }
            LogLevel::Critical => match log_level {
                LogLevel::Trace => false,
                LogLevel::Debug => false,
                LogLevel::Info => false,
                LogLevel::Warn => false,
                LogLevel::Error => false,
                _ => true
            }
        }
    }
}

pub trait LoggerCapability: Context {
    fn get_logger(&self) -> &Logger;
}