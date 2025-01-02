use std::collections::HashMap;

use chrono::Utc;
use serde::{de::DeserializeOwned, Serialize};

use crate::core::http::error::HttpError;

use super::{Cache, CacheContext};

pub trait StagedCacheContext<T: Serialize + DeserializeOwned> : CacheContext<StagedCache<T>, T> {}

pub struct StagedCache<T: Serialize + DeserializeOwned> {
    id: String,
    data: HashMap<String, T>,
    staged_inserts: HashMap<String, T>,
    staged_removals: Vec<String>,
    last_updated: i64,
}

impl<T: Serialize + DeserializeOwned> StagedCache<T> {

    fn update_data<C: Cache<T>>(&mut self, ctx : &dyn CacheContext<C, T>) {

        let state = match ctx.read_cache_state() {
            Ok(state) => state.clone(),
            Err(_) => return,
        };

        if self.get_last_updated() < state.last_updated {
            let (data, _) = ctx.get_shared_data(self.id.as_str());
            let data = match data {
                Some(data) => data,
                None => return,
            };

            self.load(data);
            self.last_updated = state.last_updated;
        }
    }

    fn apply_changes<C: Cache<T>>(&mut self, ctx : &dyn CacheContext<C, T>) {
        if !self.staged_inserts.is_empty() || !self.staged_removals.is_empty() {
            self.update_data(ctx);

            for (key, value) in self.staged_inserts.drain() {
                self.data.insert(key, value);
            };

            for value in self.staged_removals.drain(..) {
                self.data.remove(&value);
            };
        };

        let serialized_data = serde_json::to_string(&self.staged_inserts).unwrap();
        let byte_data = serialized_data.as_bytes().to_vec();
        let _ =ctx.set_shared_data(self.id.as_str(), Some(&byte_data[..]), None);
    }
    
    fn cancel_changes(&mut self) {
        self.staged_inserts.clear();
        self.staged_removals.clear();
    }
}

impl<T: Serialize + DeserializeOwned> Cache<T> for StagedCache<T> {
    fn from_empty(id: &str) -> Self where Self: Sized {
        let mut cache = Self {
            id: id.to_string(),
            data: HashMap::new(),
            staged_inserts: HashMap::new(),
            staged_removals: Vec::new(),
            last_updated: 0, // Never updated initially
        };

        cache.set_last_updated(Utc::now().timestamp());
        cache
    }
    
    fn from_vec_u8(id: &str, vec: Vec<u8>) -> Result<Self, HttpError> where Self: Sized {
        let data = serde_json::from_slice(&vec).map_err(|_| HttpError::new(500, "Error parsing cache data.".to_string()))?;

        let mut cache = Self {
            id: id.to_string(),
            data,
            staged_inserts: HashMap::new(),
            staged_removals: Vec::new(),
            last_updated: 0, // Never updated initially
        };

        cache.set_last_updated(Utc::now().timestamp());
        Ok(cache)
    }
    
    fn id(&self) -> &str {
        self.id.as_str()
    }
    
    fn get(&self, key: &str) -> Option<&T> {
        self.data.get(key)
    }

    fn get_data(&self) -> &HashMap<String, T> {
        &self.data
    }
    
    fn insert(&mut self, key: String, value: T) {
        self.staged_inserts.insert(key, value);
    }
    
    fn remove(&mut self, key: &str) {
        self.staged_removals.push(key.to_string());
    }
    
    fn clear(&mut self) {
        for (key, _) in self.data.iter() {
            self.staged_removals.push(key.clone());
        }
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
}