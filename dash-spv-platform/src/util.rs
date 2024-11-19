use std::future::Future;
use std::time::Duration;

#[ferment_macro::export]
#[derive(Clone)]
pub enum Retry {
    Linear = 0,
    SlowingDown20Percent = 1,
    SlowingDown50Percent = 2,
}
impl Retry {
    pub fn delay(&self, delay: Duration, limit: Duration) -> Duration {
        match self {
            Retry::SlowingDown20Percent => delay.mul_f32(1.2),
            Retry::SlowingDown50Percent => delay.mul_f32(1.5),
            _ => delay,
        }.min(limit)
    }
    pub async fn perform<T, E, F, Fut>(self, f: F) -> Result<T, E>
    where F: Fn() -> Fut,
          Fut: Future<Output = Result<T, E>> {
        retry_on_err(f, self).await
    }
}

pub async fn retry_on_err<T, E, F, Fut>(f: F, retry: Retry) -> Result<T, E>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let delay = Duration::from_millis(500);
    let limit = Duration::from_secs(60 * 2);
    let retry_count = 0u32;
    loop {
        match f().await {
            Err(_) if retry_count > 0 =>
                tokio::time::sleep(retry.delay(delay, limit)).await,
            Ok(val) =>
                return Ok(val),
            Err(eee) =>
                return Err(eee)
        }
    }
}
