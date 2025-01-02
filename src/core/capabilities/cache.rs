use std::collections::HashMap;

use std::result::Result::Ok;
use proxy_wasm::traits::Context;
use serde::Serialize;

use crate::core::error::HttpError;


#[doc = "Cache structure for storing data."]
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
}

#[doc = "Data structure to hold Cache entry data."]
struct Entry<T> {
    data: T,
    last_cas: u32, 
}

impl<T> Entry<T> {
    fn get_data(&self) -> &T {
        &self.data
    }
}

#[doc = "Trait for enabling reading and writing to cache."]
pub trait CacheCapability<T>: Context {
    fn get_local_cache(&self) -> &Cache<T>;
    fn get_mut_local_cache(&mut self) -> &mut Cache<T>;

    #[doc = "Reads data from cache, using local cache when possible to avoid deserialization."]
    fn read_from_cache(&mut self, key: &str, fn_deserialization : fn(&[u8]) -> Result<T, HttpError>) -> Option<&T> {
        
        let shared = self.get_shared_data(key);
        let cache = self.get_mut_local_cache();
        
        // Check if in local cache and get last CAS
        let entry_last_cas = match cache.get_entry(key) {
            Some(entry) => Some(entry.last_cas),
            None => None,
        };

        // Check if last CAS is still valid 
        if let Some(last_cas) = entry_last_cas {
            if last_cas == match shared {
                (Some(_), Some(cas)) => cas,
                (_, _) => 0,
            } {
                // Return data from local cache
                let data = cache.get_entry(key).unwrap().get_data();
                return Some(data);
            }
        };

        // If not in local cache, or local cache is not valid
        // Try to read from shared data
        match shared {
            // If the is some data
            (Some(data), Some(cas)) => {

                // Deserialize data
                let value: T = match fn_deserialization(&data) {
                    Ok(value) => value,
                    Err(_) => return None, // TODO Throw this error to distinguish between no value and serialization error
                };
                
                // Update local cache
                cache.entries.insert(
                    key.to_string(),
                    Entry {
                        data: value,
                        last_cas: cas,
                    },
                );

                Some(cache.get_entry(key)?.get_data())
            },
            // If there is no data
            (_, _) => None,
        }
    }

    #[doc = "Writes data to both shared and local cache."]
    fn write_to_cache(&mut self, key: &str, data: T) -> Result<&T, HttpError> where T: Serialize {

        let serialized = match serde_json::to_string(&data) {
            Ok(serialized) => serialized,
            Err(e) => return Err(HttpError::new(500, format!("Error serializing data: {}", e))),
        };

        let serialized = serialized.as_bytes();

        let last_cas = match self.get_local_cache().get_entry(key) {
            Some(entry) => entry.last_cas,
            None => 0,
        };
    
        // Write to shared data with our timestamp as the CAS
        if self.set_shared_data(key, Some(&serialized), None).is_ok() {
            self.get_mut_local_cache().entries.insert(
                key.to_string(),
                Entry {
                    data: data,
                    last_cas: last_cas + 1,
                },
            );
        } else {
            return Err(HttpError::new(500, "Error writing to shared data.".to_string()));
        };

        Ok(self.get_local_cache().get_entry(key).unwrap().get_data())
    }
}