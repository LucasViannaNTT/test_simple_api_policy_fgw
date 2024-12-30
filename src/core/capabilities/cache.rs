use std::{any::Any, collections::HashMap, sync::RwLock};

use chrono::Utc;
use dashmap::DashMap;
use proxy_wasm::traits::Context;

use crate::core::http::error::HttpError;

pub trait Cache<T> {
    fn new(id : &str) -> Self where Self : Sized;
    fn from_vec_u8(vec: Vec<u8>) -> Result<Self, HttpError> where Self : Sized;
    fn id(&self) -> &str;
    fn get(&self, key: &str) -> Option<&T>;
    fn set(&mut self, key: &str, value: T);
    fn remove(&mut self, key: &str);
    fn clear(&mut self);
    fn size(&self) -> usize;
    fn is_dirty(&self) -> bool;
}

pub trait StorageContext: Context {
    fn get_mut_storage(&mut self) -> &mut Storage;
    fn get_storage(&self) -> &Storage;

    fn get_cache<T:'static>(&self, id : &str) -> Option<&Box<dyn Cache<T>>> {

        let cache = match self.get_storage().get(id) {
            Some(cache) => match cache.downcast_ref::<Box<dyn Cache<T>>>() {
                Some(cache) => cache,
                None => return None,
            },
            None => return None,
        };

        if cache.is_dirty() {
            let shared_cache = match self.get_shared_data(cache.id()).0 {
                Some(shared_cache) => shared_cache,
                None => return None,
            };

            let shared_cache = 
        }

        return Some(cache);
    }

    fn get_mut_cache<T:'static>(&mut self, id : &str) -> Option<&mut Box<dyn Cache<T>>> {
        match self.get_mut_storage().get_mut(id) {
            Some(cache) => cache.downcast_mut(),
            None => None,
        }
    }

    fn create_cache<T:'static>(&mut self, id : &str) -> Result<&Box<dyn Cache<T>>, HttpError> {
        if let None = self.get_storage().get(id) {
            let new_cache: Box<dyn Cache<T>> = Box::new(CacheSharedHashMap::<T>::new(id));
            self.get_mut_storage().insert(id.to_string(), Box::new(new_cache));
            return Ok(self.get_storage().get(id).unwrap().downcast_ref().unwrap());
        }

        Err(HttpError::new(500, format!("Cache '{}' already exists", id)))
    }

    fn create_mut_cache<T:'static>(&mut self, id : &str) -> Result<&mut Box<dyn Cache<T>>, HttpError> { 
        if let None = self.get_mut_storage().get_mut(id) {
            let new_cache: Box<dyn Cache<T>> = Box::new(CacheSharedHashMap::<T>::new(id));
            self.get_mut_storage().insert(id.to_string(), Box::new(new_cache));
            return Ok(self.get_mut_storage().get_mut(id).unwrap().downcast_mut().unwrap());
        }

        Err(HttpError::new(500, format!("Cache '{}' already exists", id)))
    }

    fn delete_cache(&mut self, id : &str) {
        self.get_mut_storage().remove(id);
    }
}

pub struct Storage {
    collection : HashMap<String, Box<dyn Any>>,
}

impl Storage {
    pub fn new() -> Self {
        Storage {
            collection: HashMap::new(),
        }
    }

    pub fn get(&self, key: &str) -> Option<&Box<dyn Any>> {
        self.collection.get(key)
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut Box<dyn Any>> {
        self.collection.get_mut(key)
    }

    pub fn insert(&mut self, key: String, value: Box<dyn Any>) {
        self.collection.insert(key, value);
    }

    pub fn remove(&mut self, key: &str) {
        self.collection.remove(key);
    }

    pub fn clear(&mut self) {
        self.collection.clear();
    }
}

pub struct CacheState {
    pub last_updated: i64,
    pub is_dirty: bool,
}

#[derive(Default)]
pub struct CacheSharedHashMap<T> {
    pub data : HashMap<String, T>,
    id : String,
    _last_updated: RwLock<i64>,
    _is_dirty: RwLock<bool>,
}

impl<T> CacheSharedHashMap<T> {

    fn update_last_updated(&self) {
        let current_time = Utc::now().timestamp();
        let mut last_updated = self._last_updated.write().unwrap();
        *last_updated = current_time;
    }

    fn mark_dirty(&self) {
        let mut is_dirty = self._is_dirty.write().unwrap();
        *is_dirty = true;
    }

    fn mark_clean(&self) {
        let mut is_dirty = self._is_dirty.write().unwrap();
        *is_dirty = false;
    }
}

impl<T> Cache<T> for CacheSharedHashMap<T> {

    fn new(id : &str) -> Self {
        CacheSharedHashMap {
            data: HashMap::new(),
            _last_updated: RwLock::new(0),
            _is_dirty: RwLock::new(false),
            id,
        }
    }

    fn from_vec_u8(vec: Vec<u8>) -> Result<Self, HttpError> where Self : Sized {
        let data: HashMap<String, T> = match serde_json::from_slice(&vec) {
            Ok(data) => data,
            Err(e) => return Err(HttpError::new(500, format!("Error decoding cache data: {}", e))),
        };

        let mut cache = CacheSharedHashMap {
            data,
            _last_updated: RwLock::new(0),
            _is_dirty: RwLock::new(false),
            id: id.to_string(),
        };

        return Ok(cache)
    }

    fn get(&self, key: &str) -> Option<&T> {
        self.data.get(key)
    }

    fn set(&mut self, key: &str, value: T) {
        self.data.insert(key.to_string(), value);
    }

    fn remove(&mut self, key: &str) {
        self.data.remove(key);
    }

    fn clear(&mut self) {
        self.data.clear();
    }

    fn size(&self) -> usize {
        self.data.len()
    }

    fn is_dirty(&self) -> bool {
        *self._is_dirty.read().unwrap()
    }
    
    fn id(&self) -> &str {
        self.id.as_str()
    }
}