use std::collections::HashMap;
use std::result::Result::Ok;
use proxy_wasm::traits::Context;
use serde::{Deserialize, Serialize};

use crate::core::error::HttpError;
use super::logger::Logger;

#[doc = "Cache structure for storing data."]
#[derive(Serialize, Deserialize)]
pub struct Cache<T> {
    entries: HashMap<String, Entry<T>>,
}

impl<T> Cache<T> {
    pub fn new() -> Self {
        Cache {
            entries: HashMap::new(),
        }
    }

    fn get_entry(&self, key: &str) -> Option<&Entry<T>> {
        self.entries.get(key)
    }

    fn remove_entry(&mut self, key: &str) -> Option<Entry<T>> {
        self.entries.remove(key)
    }

    fn insert_entry(&mut self, key: String, entry: Entry<T>) -> &T {
        self.entries.insert(key.clone(), entry);
        self.entries.get(&key).unwrap().get_data()
    }
}

#[doc = "Data structure to hold Cache entry data."]
#[derive(Serialize, Deserialize)]
struct Entry<T> {
    data: T,
    last_cas: u32, 
}

impl<T> Entry<T> {
    fn get_data(&self) -> &T {
        &self.data
    }

    fn new(data: T, last_cas: u32) -> Self {
        Entry { data, last_cas }
    }
}

#[doc = "Trait for enabling reading and writing to cache."]
pub trait CacheCapability<T>: Context {
    fn get_local_cache(&self) -> &Cache<T>;
    fn get_mut_local_cache(&mut self) -> &mut Cache<T>;

    #[doc = "Reads data from cache, using local cache when possible to avoid deserialization.
    \r\nReturns None if the data does not exist or could not be deserialized."]
    fn read_from_cache(&mut self, key: &str, fn_deserialization: fn(&[u8]) -> Result<T, HttpError>) -> Option<&T> {
        let shared = self.get_shared_data(key);
        
        match shared {
            // Shared Data for the entry exists
            (Some(data), Some(shared_cas)) => {
                let local_cas = self.get_local_cache().get_entry(key).map(|e| e.last_cas);
                match local_cas {
                    // Local Data for the entry exists
                    Some(local_cas) if local_cas == shared_cas => {
                        // Local Data is valid, so we return it
                        self.get_local_cache().get_entry(key).map(|e| e.get_data())
                    }
                    // Local Data does not exist or invalid
                    _ => {
                        match fn_deserialization(&data) {
                            Ok(value) => {
                                // Serialize the data and update the Local Cache with the new CAS value
                                let entry = Entry::new(value, shared_cas);
                                let cache = self.get_mut_local_cache();
                                Some(cache.insert_entry(key.to_string(), entry))
                            }
                            // Errror deserializing the data
                            Err(_) => None
                        }
                    }
                }
            }
            // Shared Data for the entry does not exist, so we remove the Local entry
            _ => {
                self.get_mut_local_cache().remove_entry(key);
                None
            }
        }
    }

    #[doc = "Writes data to both shared and local cache.
    \r\nReturns an error if the data could not be serialized or written to shared data."]
    fn write_to_cache(&mut self, key: &str, data: T) -> Result<&T, HttpError> 
    where T: Serialize {
        let serialized = serde_json::to_string(&data)
            .map_err(|e| HttpError::new(500, format!("Error serializing data: {}", e)))?;

        let shared_cas = self.get_shared_data(key).1
            .unwrap_or(0);

        Logger::log_info(&format!("Shared CAS Before: {}", shared_cas));

        // TODO Add Cache Namespace Prefix for the key, so different caches do not write to the same shared data key
        self.set_shared_data(key, Some(serialized.as_bytes()), Some(shared_cas))
            .map_err(|_| HttpError::new(500, "Error writing to shared data.".to_string()))?;

        let shared_cas = self.get_shared_data(key).1
            .unwrap_or(0);

        Logger::log_info(&format!("Shared CAS After: {}", shared_cas));

        let entry = Entry::new(data, shared_cas);

        let cached = self.get_mut_local_cache().insert_entry(key.to_string(), entry);
    
        Ok(cached)
    }

    #[doc = "Deletes data from cache.
    \r\nIf lazy is true, only the shared data is removed, otherwise both shared and local data are removed.
    \r\nReturns an error if the shared data could not be removed.
    \r\nNote: Shared Data will still contain a key with no value as there is no API provided by proxy-wasm to completly remove data."]
    fn delete_from_cache(&mut self, key: &str, lazy: bool) -> Result<(), HttpError> {
        // This will also increase CAS
        self.set_shared_data(key, None, None)
            .map_err(|_| HttpError::new(500, "Error removing from shared data.".to_string()))?;

        if !lazy {
            self.get_mut_local_cache().remove_entry(key);
        }
        
        Ok(())
    }
}