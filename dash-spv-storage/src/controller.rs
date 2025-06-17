use std::os::raw::c_void;
use std::sync::Arc;
use crate::entity::Entity;
use crate::error::StorageError;
use crate::predicate::Predicate;
use crate::StorageContext;

#[derive(Clone)]
pub struct StorageController {
    pub get: Arc<dyn Fn(StorageContext, Predicate) -> Result<Entity, StorageError> + Send + Sync>,
    pub get_many: Arc<dyn Fn(StorageContext, Predicate) -> Result<Vec<Entity>, StorageError> + Send + Sync>,
    pub set: Arc<dyn Fn(StorageContext, Entity) -> Result<bool, StorageError> + Send + Sync>,
    pub set_many: Arc<dyn Fn(StorageContext, Vec<Entity>) -> Result<bool, StorageError> + Send + Sync>,
    pub has: Arc<dyn Fn(StorageContext, Predicate) -> Result<bool, StorageError> + Send + Sync>,
    pub delete: Arc<dyn Fn(StorageContext, Predicate) -> Result<bool, StorageError> + Send + Sync>,
    pub count: Arc<dyn Fn(StorageContext, Predicate) -> Result<usize, StorageError> + Send + Sync>,

    pub get_raw: Arc<dyn Fn(StorageContext, Predicate) -> *const c_void + Send + Sync>,
    pub set_raw: Arc<dyn Fn(StorageContext, *const c_void) -> Result<bool, StorageError> + Send + Sync>,
}

#[ferment_macro::export]
impl StorageController {
    pub fn new<
        GET: Fn(StorageContext, Predicate) -> Result<Entity, StorageError> + Send + Sync + 'static,
        GETMany: Fn(StorageContext, Predicate) -> Result<Vec<Entity>, StorageError> + Send + Sync + 'static,
        SET: Fn(StorageContext, Entity) -> Result<bool, StorageError> + Send + Sync + 'static,
        SETMany: Fn(StorageContext, Vec<Entity>) -> Result<bool, StorageError> + Send + Sync + 'static,
        HAS: Fn(StorageContext, Predicate) -> Result<bool, StorageError> + Send + Sync + 'static,
        DEL: Fn(StorageContext, Predicate) -> Result<bool, StorageError> + Send + Sync + 'static,
        COUNT: Fn(StorageContext, Predicate) -> Result<usize, StorageError> + Send + Sync + 'static,
        GetRaw: Fn(StorageContext, Predicate) -> *const c_void + Send + Sync + 'static,
        SetRaw: Fn(StorageContext, *const c_void) -> Result<bool, StorageError> + Send + Sync + 'static,
    >(
        get: GET,
        get_many: GETMany,
        set: SET,
        set_many: SETMany,
        has: HAS,
        delete: DEL,
        count: COUNT,
        get_raw: GetRaw,
        set_raw: SetRaw,
    ) -> Self {
        Self {
            get: Arc::new(get),
            get_many: Arc::new(get_many),
            set: Arc::new(set),
            set_many: Arc::new(set_many),
            has: Arc::new(has),
            delete: Arc::new(delete),
            count: Arc::new(count),
            get_raw: Arc::new(get_raw),
            set_raw: Arc::new(set_raw),
        }
    }
    pub fn get(&self, predicate: Predicate, context: StorageContext) -> Result<Entity, StorageError> {
        (self.get)(context, predicate)
    }
    pub fn get_many(&self, predicate: Predicate, context: StorageContext) -> Result<Vec<Entity>, StorageError> {
        (self.get_many)(context, predicate)
    }
    pub fn set(&self, value: Entity, context: StorageContext) -> Result<bool, StorageError> {
        (self.set)(context, value)
    }
    pub fn set_many(&self, value: Vec<Entity>, context: StorageContext) -> Result<bool, StorageError> {
        (self.set_many)(context, value)
    }
    pub fn has(&self, predicate: Predicate, context: StorageContext) -> Result<bool, StorageError> {
        (self.has)(context, predicate)
    }
    pub fn delete(&self, predicate: Predicate, context: StorageContext) -> Result<bool, StorageError> {
        (self.delete)(context, predicate)
    }
    pub fn count(&self, predicate: Predicate, context: StorageContext) -> Result<usize, StorageError> {
        (self.count)(context, predicate)
    }
    pub fn get_raw(&self, predicate: Predicate, context: StorageContext) -> *const c_void {
        (self.get_raw)(context, predicate)
    }
    pub fn set_raw(&self, context: StorageContext, entity: *const c_void) -> Result<bool, StorageError> {
        (self.set_raw)(context, entity)
    }
}