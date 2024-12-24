use super::http::expansion::ExpandedHttpContext;


#[derive(Default)]
pub struct Cache {}

impl Cache {

    pub fn new() -> Self {
        Cache {}
    }
}

pub trait CacheHttpContext: ExpandedHttpContext {
    fn get_cache(&self) -> &Cache;
}