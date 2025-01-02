pub mod staged;
pub mod default;

use std::{any::Any, collections::HashMap, sync::{Arc, RwLock}};
use lazy_static::lazy_static;
use proxy_wasm::traits::Context;
use serde::{Serialize, de::DeserializeOwned};

use crate::core::http::error::HttpError;

lazy_static! {
    /// Shared state for all cache instances.
    static ref CACHE_STATES: Arc<RwLock<HashMap<String, CacheState>>> = 
        Arc::new(RwLock::new(HashMap::new()));
}

/// Represents the state of a cache, including the last updated timestamp.
#[derive(Clone)]
pub struct CacheState {
    pub last_updated: i64,
}

pub struct CacheSystem {
    caches: RwLock<HashMap<String, Box<dyn Any>>>,
}

impl CacheSystem {
    pub fn new() -> Self {
        Self {
            caches: RwLock::new(HashMap::new()),
        }
    }

    pub fn get<T: 'static>(&self, id: &str) -> Option<Arc<dyn Cache<T>>> {
        let caches = self.caches.read().unwrap();
        caches.get(id).and_then(|cache| {
            // Attempt to downcast from `dyn Any` to the specific `Cache<T>`
            cache.downcast_ref::<Arc<dyn Cache<T>>>()
        }).cloned()
    }
}

/// The Cache trait defines cache operations. It is intended to be used
/// within the context of a CacheContext.
pub trait Cache<T: Serialize + DeserializeOwned> {
    /// Creates a new empty cache instance.
    fn from_empty(id: &str) -> Self where Self: Sized;

    /// Creates a cache instance from a serialized byte vector.
    fn from_vec_u8(id: &str, vec: Vec<u8>) -> Result<Self, HttpError> where Self: Sized;

    /// Gets the id of this cache instance.
    fn id(&self) -> &str;

    /// Retrieves the value associated with a specific key from the cache.
    fn get(&self, key: &str) -> Option<&T>;

    /// Retrieves all data in the cache.
    fn get_data(&self) -> &HashMap<String, T>;

    /// Inserts a key-value pair into the cache.
    fn insert(&mut self, key: String, value: T);

    /// Removes the entry associated with a specific key from the cache.
    fn remove(&mut self, key: &str);

    /// Clears all entries in the cache.
    fn clear(&mut self);

    /// Loads new data into the cache from a serialized byte vector.
    fn load(&mut self, data: Vec<u8>);

    /// Sets the last updated timestamp for the cache.
    fn get_last_updated(&self) -> i64;

    /// Sets the last updated timestamp for the cache.
    fn set_last_updated(&mut self, timestamp: i64);
}

/// The CacheContext trait defines operations that interact with the cache.
pub trait CacheContext<C: Cache<T>, T: Serialize + DeserializeOwned>: Context {
    /// Internal method to get the mutable cache instance.
    fn get_mut_cache(&mut self) -> &mut C;

    /// Internal method to get the cache instance (immutable).
    fn get_cache(&self) -> &C;

    fn is_cache_data_old(&self) -> bool {
        self.get_cache().get_last_updated() < self.read_cache_state().unwrap().last_updated
    }

    /// Reads the state (e.g., last updated timestamp) of the cache.
    fn read_cache_state(&self) -> Result<CacheState, String> {
        CACHE_STATES
            .read()
            .map_err(|e| e.to_string())
            .and_then(|states| {
                states.get(self.get_cache().id())
                    .cloned()
                    .ok_or_else(|| "Cache state not found.".to_string())
            })
    }

    /// Writes the cache's state (e.g., last updated timestamp) to the shared state.
    fn write_cache_state(&self, state: CacheState) -> Result<(), String> {
        CACHE_STATES
            .write()
            .map_err(|e| e.to_string())
            .map(|mut states| {
                states.insert(self.get_cache().id().to_string(), state);
            })
    }
}