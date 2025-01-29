use std::future::Future;
use std::time::Duration;
use dash_sdk::dapi_client::transport::TransportRequest;
use dash_sdk::mock::MockResponse;
use dash_sdk::platform::{DocumentQuery, Fetch, FetchMany, Query};
use dash_sdk::Sdk;
use dpp::data_contract::DataContract;
use dpp::data_contracts::SystemDataContract;
use dpp::document::Document;
use drive_proof_verifier::FromProof;
use indexmap::IndexMap;
use platform_value::Identifier;
use dash_spv_crypto::network::ChainType;
use crate::error::Error;

pub const NONE_ERROR: &str = "Platform returned none while some was expected";


pub trait Validator<T> {
    fn validate(&self, value: &T) -> bool;
}

pub trait StreamSpec {
    type Validator: Validator<Self::Result> + Validator<Self::ResultMany>;
    type Error: MaxRetryError + ValidationError;
    type Result;
    type ResultMany;
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

impl<SPEC> StreamSettings<SPEC> where SPEC: StreamSpec {
    pub fn with_delay(mut self, delay: u64) -> Self {
        self.delay = delay;
        self
    }
}

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
    pub fn with_retry_and_settings(retry: RetryStrategy, settings: StreamSettings<SPEC>) -> Self {
        Self {
            settings,
            retry: Some(retry),
        }
    }
    pub fn with_validator(mut self, composer: SPEC::Validator) -> Self {
        self.settings.validator = Some(composer);
        self
    }
    pub fn with_delay(mut self, delay: u64) -> Self {
        self.settings.delay = delay;
        self
    }
    pub fn with_limit(mut self, limit: u64) -> Self {
        self.settings.limit = limit;
        self
    }
    pub fn with_settings(mut self, settings: StreamSettings<SPEC>) -> Self {
        self.settings = settings;
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
    pub async fn stream_many<F, Fut>(self, f: F) -> Result<SPEC::ResultMany, SPEC::Error>
    where F: Fn() -> Fut,
          Fut: Future<Output = Result<SPEC::ResultMany, SPEC::Error>> {
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

pub trait StreamManager: Send + Sync {
    fn sdk_ref(&self) -> &Sdk;
    fn chain_type(&self) -> &ChainType;

    fn stream<SPEC, ITEM, Q>(
        &self,
        query: Q,
        retry: RetryStrategy,
        validator: SPEC::Validator,
    ) -> impl Future<Output = Result<SPEC::Result, Error>> + Send
    where
        SPEC: StreamSpec<Result = Option<ITEM>, Error = dash_sdk::Error>,
        SPEC::Validator: Send,
        ITEM: Fetch + Send,
        Q: Query<<ITEM as Fetch>::Request> + Clone + Sync {
        async move {
            let strategy = StreamStrategy::<SPEC>::with_retry(retry)
                .with_validator(validator)
                .on_max_retries_reached(dash_sdk::Error::Generic("Max retry reached".to_string()));
            self.stream_with_strategy(query, strategy).await
        }
    }

    fn stream_with_settings<SPEC, ITEM, Q>(
        &self,
        query: Q,
        retry: RetryStrategy,
        stream_settings: StreamSettings<SPEC>,
        validator: SPEC::Validator,
    ) -> impl Future<Output = Result<SPEC::Result, Error>> + Send
    where
        SPEC: StreamSpec<Result = Option<ITEM>, Error = dash_sdk::Error>,
        SPEC::Validator: Send,
        ITEM: Fetch + Send,
        Q: Query<<ITEM as Fetch>::Request> + Clone + Sync {
        async move {
            let strategy = StreamStrategy::<SPEC>::with_retry_and_settings(retry, stream_settings)
                .with_validator(validator)
                .on_max_retries_reached(dash_sdk::Error::Generic("Max retry reached".to_string()));
            self.stream_with_strategy(query, strategy).await
        }
    }

    fn stream_with_strategy<SPEC, ITEM, Q>(
        &self,
        query: Q,
        strategy: StreamStrategy<SPEC>,
    ) -> impl Future<Output = Result<SPEC::Result, Error>> + Send
    where
        SPEC: StreamSpec<Result = Option<ITEM>, Error = dash_sdk::Error>,
        SPEC::Validator: Send,
        ITEM: Fetch + Send,
        Q: Query<<ITEM as Fetch>::Request> + Clone + Sync {
        async move {
            strategy.stream(|| {
                let query = query.clone();
                async { ITEM::fetch(self.sdk_ref(), query).await }
            })
                .await
                .map_err(Error::from)
        }
    }

    fn stream_many<SPEC, ITEM, Q>(
        &self,
        query: Q,
        retry: RetryStrategy,
        validator: SPEC::Validator,
    ) -> impl Future<Output = Result<SPEC::ResultMany, Error>> + Send
    where
        SPEC: StreamSpec<Error = dash_sdk::Error>,
        SPEC::Validator: Send,
        SPEC::ResultMany: MockResponse
            + FromIterator<(Identifier, Option<ITEM>)>
            + FromProof<ITEM::Request, Request=ITEM::Request, Response=<ITEM::Request as TransportRequest>::Response>
            + Send
            + Default,
        ITEM: FetchMany<Identifier, SPEC::ResultMany>
            + Send,
        Q: Query<ITEM::Request>
            + Clone
            + Sync,
        // O: MockResponse
        //     + FromIterator<(Identifier, Option<ITEM>)>
        //     + FromProof<ITEM::Request, Request=ITEM::Request, Response=<ITEM::Request as TransportRequest>::Response>
        //     + Send
        //     + Default
    {
        async move {
            let strategy = StreamStrategy::<SPEC>::with_retry(retry)
                .with_validator(validator)
                .on_max_retries_reached(dash_sdk::Error::Generic("Max retry reached".to_string()));
            self.stream_many_with_strategy(query, strategy).await
        }
    }

    fn stream_many_with_strategy<SPEC, ITEM, Q>(
        &self,
        query: Q,
        strategy: StreamStrategy<SPEC>,
    ) -> impl Future<Output = Result<SPEC::ResultMany, Error>> + Send
    where
        SPEC: StreamSpec<Error = dash_sdk::Error>,
        SPEC::Validator: Send,
        SPEC::ResultMany: MockResponse
        + FromIterator<(Identifier, Option<ITEM>)>
        + FromProof<ITEM::Request, Request=ITEM::Request, Response=<ITEM::Request as TransportRequest>::Response>
        + Send
        + Default,
    ITEM: FetchMany<Identifier, SPEC::ResultMany>
            + Send,
        Q: Query<ITEM::Request>
            + Clone
            + Sync,
        // O: MockResponse
        //     + FromIterator<(Identifier, Option<ITEM>)>
        //     + FromProof<ITEM::Request, Request=ITEM::Request, Response=<ITEM::Request as TransportRequest>::Response>
        //     + Send
        //     + Default
    {
        async move {
            strategy.stream_many(|| {
                let query = query.clone();
                async {
                    ITEM::fetch_many(self.sdk_ref(), query).await
                }
            })
                .await
                .map_err(Error::from)
        }
    }
    fn stream_many_with_settings<SPEC, ITEM, Q>(
        &self,
        query: Q,
        retry: RetryStrategy,
        stream_settings: StreamSettings<SPEC>,
        validator: SPEC::Validator,
    ) -> impl Future<Output = Result<SPEC::ResultMany, Error>> + Send
    where
        SPEC: StreamSpec<Error = dash_sdk::Error>,
        SPEC::Validator: Send,
        SPEC::ResultMany: MockResponse
        + FromIterator<(Identifier, Option<ITEM>)>
        + FromProof<ITEM::Request, Request=ITEM::Request, Response=<ITEM::Request as TransportRequest>::Response>
        + Send
        + Default,
        ITEM: FetchMany<Identifier, SPEC::ResultMany>
            + Send,
        Q: Query<ITEM::Request>
            + Clone
            + Sync {
        async move {
            let strategy = StreamStrategy::<SPEC>::with_retry_and_settings(retry, stream_settings)
                .with_validator(validator)
                .on_max_retries_reached(dash_sdk::Error::Generic("Max retry reached".to_string()));
            self.stream_many_with_strategy(query, strategy).await
        }
    }

    fn with_contract<F, Fut, R, Args>(
        &self,
        system_contract: SystemDataContract,
        args: Args,
        callback: F,
    ) -> impl Future<Output = Result<R, Error>> + Send
    where
        F: FnOnce(DataContract, Args) -> Fut
            + Send,
        Fut: Future<Output = Result<R, Error>>
            + Send,
        Args: Send {
        async move {
            match DataContract::fetch(self.sdk_ref(), system_contract.id()).await {
                Ok(Some(contract)) => callback(contract, args).await,
                Ok(None) => Err(Error::DashSDKError(format!("Contract {:?} not found", system_contract))),
                Err(e) => Err(Error::from(e)),
            }
        }
    }

    fn many_documents_with_query(&self, query: DocumentQuery) -> impl Future<Output = Result<IndexMap<Identifier, Option<Document>>, Error>> + Send {
        async move {
            Document::fetch_many(self.sdk_ref(), query).await
                .map_err(Error::from)
        }
    }
    fn document_with_query(&self, query: DocumentQuery) -> impl Future<Output = Result<Option<Document>, Error>> + Send
    where Self: Send + Sync {
        async move {
            Document::fetch(self.sdk_ref(), query).await
                .map_err(Error::from)
        }
    }

    // fn monitor_document_with_query(&self, q)
}
