use std::collections::HashMap;
use std::result::Result::Ok;
use proxy_wasm::traits::Context;
use serde::{Deserialize, Serialize};

use crate::core::error::HttpError;

#[doc = "Cache structure for storing local data."]
#[derive(Serialize, Deserialize)]
pub struct Cache<T> {
    #[serde(flatten)]
    entries: HashMap<String, Entry<T>>,
}

impl<T> Cache<T> {
    pub fn new() -> Self {
        Cache {
            entries: HashMap::new(),
        }
    }

    #[doc = "Returns some Entry from the cache.
    \r\nIf no entry is found, returns None."]
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

#[doc = "Contains Data and CAS of a Cache Entry."]
#[derive(Serialize, Deserialize)]
struct Entry<T> {
    data: T,
    last_cas: u32, 
}

impl<T> Entry<T> {
    #[doc ="Returns the data contained by the entry."]
    fn get_data(&self) -> &T {
        &self.data
    }

    #[doc = "Creates a new Entry containing Data and CAS."]
    fn new(data: T, last_cas: u32) -> Self {
        Entry { data, last_cas }
    }
}

/// Enables use of Local Cache and abstracts proxy-wasm's shared data.
pub trait CacheCapability<T>: Context {
    fn get_local_cache(&self) -> &Cache<T>;
    fn get_mut_local_cache(&mut self) -> &mut Cache<T>;

    /// Reads data from cache, using local cache when possible to avoid deserialization.
    /// 
    /// **Returns None:** if <code>key</code> not in Shared Data or <code>Entry</code> deserialization failed.
    /// 
    /// # Examples
    /// ```
    /// // Suppose Shared Data contains {"k1":"d1"} (with CAS 1) as an entry
    /// // Suppose Local Cache does not contain "k1" as an entry.
    /// self.read_from_cache("k1", |data| serde_json::from_slice(data).map_err(|_| HttpError::new(500, "Error parsing cache data.".to_string())));
    /// // Entry not in local cache, Entry is deserialized and added to local cache
    /// // Local Cache now contains {"k1":{"data":{"d1"}, "last_cas":1}}
    /// 
    /// self.read_from_cache("k1", |data| serde_json::from_slice(data).map_err(|_| HttpError::new(500, "Error parsing cache data.".to_string())));
    /// // Entry in local cache, CAS matches, Entry is directly returned from local cache
    /// 
    /// // Suppose Shared Data entry "k1" changed to {"k1":"d2"} (with CAS 2)
    /// self.read_from_cache("k1", |data| serde_json::from_slice(data).map_err(|_| HttpError::new(500, "Error parsing cache data.".to_string())));
    /// // Entry in local cache, CAS doesnt match, Entry is deserialized and added to local cache
    /// // Local Cache now contains {"k1":{"data":{"d1"}, "last_cas":2}}
    /// 
    /// // Suppose Shared Data entry "k1" changed to {"k1":""} (with CAS 3)
    /// self.read_from_cache("k1", |data| serde_json::from_slice(data).map_err(|_| HttpError::new(500, "Error parsing cache data.".to_string())));
    /// // Entry Data is None in Shared Data, Entry is removed from local cache
    /// // Local Cache now does not contain "k1"
    /// ```
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

    /// Writes data to both Shared Data and Local Cache.
    /// 
    /// **Returns Err:** if <code>data</code> serialization failed or failed to write to Shared Data.
    /// 
    /// # Examples
    /// ```
    /// // Suppose Shared Data and Local Cache do not contain "k1" as an entry.
    /// self.write_to_cache("k1", "d1".to_string());
    /// // Shared Data now contains {"k1":"d1"} (with CAS 1) as an entry
    /// // Local Cache now contains {"k1":{"data":"d1","last_cas":1}} as an entry
    /// 
    /// self.write_to_cache("k1", "d2".to_string());
    /// // Shared Data now contains {"k1":"d2"} (with CAS 2) as an entry
    /// // Local Cache now contains {"k1":{"data":"d2","last_cas":2}} as an entry
    /// ```
    fn write_to_cache(&mut self, key: &str, data: T) -> Result<&T, HttpError> 
    where T: Serialize {
        let serialized = serde_json::to_string(&data)
            .map_err(|e| HttpError::new(500, format!("Error serializing data: {}", e)))?;

        let shared_cas = self.get_shared_data(key).1
            .unwrap_or(0);

        // TODO Add Cache Namespace Prefix for the key, so different caches do not write to the same shared data key
        self.set_shared_data(key, Some(serialized.as_bytes()), Some(shared_cas))
            .map_err(|_| HttpError::new(500, "Error writing to shared data.".to_string()))?;

        let shared_cas = self.get_shared_data(key).1
            .unwrap_or(0);

        let entry = Entry::new(data, shared_cas);

        let cached = self.get_mut_local_cache().insert_entry(key.to_string(), entry);
    
        Ok(cached)
    }
    /// Deletes an <code>Entry</code> from both Shared Data and Local Cache. If <code>lazy</code> is <code>true</code>, only the Shared Data is removed, otherwise both are removed.
    /// 
    /// **Returns Err:** if <code>key</code> could not be removed.
    /// 
    /// **Note:** Shared Data will still contain a key with no value as there is no API provided by proxy-wasm to completly remove data.
    /// 
    /// # Examples
    /// ```
    /// // Suppose Shared Data contains {"k1":"d1"} (with CAS 1) as an entry
    /// // Suppose Local Cache contains {"k1":{"data":"d1", "last_cas":1}} as an entry
    /// self.delete_from_cache("k1", false);
    /// // Shared Data now contains {"k1":""} (with CAS 2) as an entry
    /// // Local Cache now does not contain "k1" as an entry
    /// 
    /// // Suppose Shared Data contains {"k2":"d1"} (with CAS 1) as an entry
    /// // Suppose Local Cache contains {"k2":{"data":"d1", "last_cas":1}} as an entry
    /// self.delete_from_cache("k2", true);
    /// // Shared Data now contains {"k2":""} (with CAS 2) as an entry
    /// // Local Cache still contains {"k2":{"data":"d1", "last_cas":1}} as an entry
    /// ```
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