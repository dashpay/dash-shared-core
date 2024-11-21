use std::future::Future;
use std::time::Duration;

pub const NONE_ERROR: &str = "Platform returned none while some was expected";


pub trait Validator<T> {
    fn validate(&self, value: &T) -> bool;
}

pub trait StreamSpec {
    type Validator: Validator<Self::Result>;
    type Error: MaxRetryError + ValidationError;
    type Result;
}
pub trait Pagination {
    type Item;
    fn has_next(&self) -> bool;
    fn len(&self) -> usize;
    fn extend(&mut self, items: Vec<Self::Item>);
    fn into_items(self) -> Vec<Self::Item>;
}

pub trait NoneCondition {
    type Error: ValidationError;
    fn error_if_condition<T>(&self, result: &T) -> bool;
}

pub trait ValidationError {
    fn validation_error() -> Self;
}
pub trait MaxRetryError {
    fn max_retry_error() -> Self;
}
#[derive(Clone)]
#[ferment_macro::export]
pub enum RetryStrategy {
    None,
    Linear(u32),
    SlowingDown20Percent(u32),
    SlowingDown50Percent(u32),
}
// #[derive(Clone)]
pub struct StreamSettings<SPEC> where SPEC: StreamSpec {
    pub delay: u64,
    pub limit: u64,

    pub validator: Option<SPEC::Validator>,
    pub max_retry_composer: Option<SPEC::Error>,
}
impl<SPEC> Default for StreamSettings<SPEC> where SPEC: StreamSpec {
    fn default() -> Self {
        StreamSettings {
            delay: 1000,
            limit: 10000,
            validator: None,
            max_retry_composer: None,
        }
    }
}

// #[derive(Clone)]
pub struct StreamStrategy<SPEC> where SPEC: StreamSpec {
    pub settings: StreamSettings<SPEC>,
    pub retry: Option<RetryStrategy>,
}

impl<SPEC> StreamStrategy<SPEC> where SPEC: StreamSpec {
    pub fn has_retries_after(&self, num_of_attempts: &mut u32) -> bool {
        match self.retry {
            Some(RetryStrategy::Linear(max_retry_count)) |
            Some(RetryStrategy::SlowingDown20Percent(max_retry_count)) |
            Some(RetryStrategy::SlowingDown50Percent(max_retry_count)) => {
                if max_retry_count > *num_of_attempts {
                    *num_of_attempts += 1;
                    true
                } else { false }
            },
            _ => false
        }
    }
    pub fn initial_delay(&self) -> u64 {
        self.settings.delay
    }
    pub fn limit(&self) -> u64 {
        self.settings.limit
    }
    pub fn delay(&self) -> Duration {
        match self.retry {
            Some(RetryStrategy::Linear(_max_retry_count))=>
                Duration::from_millis(self.settings.delay)
                    .min(Duration::from_millis(self.settings.limit)),
            Some(RetryStrategy::SlowingDown20Percent(_max_retry_count)) =>
                Duration::from_millis(self.settings.delay)
                    .mul_f32(1.2)
                    .min(Duration::from_millis(self.settings.limit)),
            Some(RetryStrategy::SlowingDown50Percent(_max_retry_count)) =>
                Duration::from_millis(self.settings.delay)
                    .mul_f32(1.5)
                    .min(Duration::from_millis(self.settings.limit)),
            _ => Duration::from_millis(0)
        }
    }

    pub fn with_retry(retry: RetryStrategy) -> Self {
        Self {
            settings: StreamSettings::default(),
            retry: Some(retry),
        }
    }
    pub fn with_validator(mut self, composer: SPEC::Validator) -> Self {
        self.settings.validator = Some(composer);
        self
    }

    pub fn on_max_retries_reached(mut self, composer: SPEC::Error) -> Self {
        self.settings.max_retry_composer = Some(composer);
        self
    }
    pub async fn stream<F, Fut>(self, f: F) -> Result<SPEC::Result, SPEC::Error>
    where F: Fn() -> Fut,
          Fut: Future<Output = Result<SPEC::Result, SPEC::Error>> {
        let mut retry_count = 0u32;
        loop {
            match f().await {
                Ok(result) => {
                    if let Some(ref validator) = self.settings.validator {
                        if !validator.validate(&result) {
                            return Err(SPEC::Error::validation_error());
                        }
                    }
                    return Ok(result);
                },
                Err(_err) if self.has_retries_after(&mut retry_count) =>
                    tokio::time::sleep(self.delay()).await,
                Err(err) =>
                    return Err(err)
            }
        }

    }
    pub async fn paginated_stream<F, Fut, BN>(
        self,
        f: F,
        mut shift: u32,
        mut notifier: BN,
    ) -> Result<SPEC::Result, SPEC::Error>
    where SPEC::Result: Pagination + Default,
        // N: Pagination + NoneCondition<E> + Default,
        F: Fn(u32) -> Fut,
        Fut: Future<Output = Result<SPEC::Result, SPEC::Error>>,
        BN: FnMut(&SPEC::Result) {
        let mut results = SPEC::Result::default();
        let mut retry_count = 0u32;
        loop {
            match f(shift).await {
                Ok(batch) => {
                    if let Some(ref validator) = self.settings.validator {
                        if !validator.validate(&batch) {
                            return Err(SPEC::Error::validation_error());
                        }
                    }
                    notifier(&batch);
                    results.extend(batch.into_items());
                    if !results.has_next() {
                        return Ok(results);
                    }
                    shift += results.len() as u32;
                    retry_count = 0;
                }
                Err(_err) if self.has_retries_after(&mut retry_count) =>
                    tokio::time::sleep(self.delay()).await,
                Err(err) =>
                    return Err(err),
            }
        }
    }
}

impl<SPEC> Default for StreamStrategy<SPEC>
where SPEC: StreamSpec {
    fn default() -> Self {
        Self {
            settings: StreamSettings::default(),
            retry: None,
        }
    }
}
