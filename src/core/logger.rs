use log::{debug, info, error};

use crate::POLICY_ID;

use super::http::expansion::ExpandedHttpContext;

#[derive(Default)]
pub struct Logger {
    // define as mutable
    log_id : u64
}

impl Logger {

    pub fn new()-> Self {
        Logger {
            ..Default::default()
        }
    }

    pub fn log_info(&mut self, message: &str) {
        let message = format!("[{}] [INFO]: {} - {}", POLICY_ID, self.log_id, message);
        self.log_id += 1;
        info!("{}", message);
    }
    
    pub fn log_debug(&mut self, message: &str) {
        let message = format!("[{}] [DEBUG]: {} - {}", POLICY_ID, self.log_id, message);
        self.log_id += 1;
        debug!("{}", message);
    }
    
    pub fn log_error(&mut self, message: &str) {
        let message = format!("[{}] [ERROR]: {} - {}", POLICY_ID, self.log_id, message);
        self.log_id += 1;
        error!("{}", message);
    }
}

pub trait LoggerHttpContext: ExpandedHttpContext {
    fn get_logger(&self) -> &Logger;
}