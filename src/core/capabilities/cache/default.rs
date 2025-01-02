use std::collections::HashMap;

use chrono::Utc;
use serde::{de::DeserializeOwned, Serialize};

use crate::core::http::error::HttpError;

use super::Cache;

/// DefaultCache is a concrete implementation of Cache.
pub struct DefaultCache<T: Serialize + DeserializeOwned> {
    id: String,
    data: HashMap<String, T>,
    last_updated: i64,
}

impl<T: Serialize + DeserializeOwned> Cache<T> for DefaultCache<T> {
    fn from_empty(id: &str) -> Self {
        let mut cache = Self {
            data: HashMap::new(),
            id: id.to_string(),
            last_updated: 0, // Never updated initially
        };
        cache.set_last_updated(Utc::now().timestamp());
        cache
    }

    fn from_vec_u8(id: &str, vec: Vec<u8>) -> Result<Self, HttpError> {
        let data = serde_json::from_slice(&vec).map_err(|_| HttpError::new(500, "Error parsing cache data.".to_string()))?;

        let mut cache = Self {
            data,
            id: id.to_string(),
            last_updated: 0, // Never updated initially
        };
        cache.set_last_updated(Utc::now().timestamp());
        Ok(cache)
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn get(&self, key: &str) -> Option<&T> {
        self.data.get(key)
    }

    fn insert(&mut self, key: String, value: T) {
        self.data.insert(key, value);
    }

    fn remove(&mut self, key: &str) {
        self.data.remove(key);
    }

    fn clear(&mut self) {
        self.data.clear();
    }

    fn load(&mut self, data: Vec<u8>) {
        self.data = serde_json::from_slice(&data).unwrap();
    }
    
    fn get_last_updated(&self) -> i64 {
        self.last_updated
    }
    
    fn set_last_updated(&mut self, timestamp: i64) {
        self.last_updated = timestamp;
    }
    
    fn get_data(&self) -> &HashMap<String, T> {
        &self.data
    }
}
