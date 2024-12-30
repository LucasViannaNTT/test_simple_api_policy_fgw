use proxy_wasm::traits::Context;

#[derive(Default)]
pub struct Cache {}

impl Cache {

    pub fn new() -> Self {
        Cache {}
    }
}

pub trait CacheContext: Context {
    fn get_cache(&self) -> &Cache;
}