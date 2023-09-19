#[macro_export]
macro_rules! unwrap_or_return {
    ($e: expr, $re: expr) => {
        match $e {
            Ok(x) => x,
            Err(err) => return $re(),
        }
    };
}
#[macro_export]
macro_rules! ok_or_return_processing_error {
    ($e: expr) => {
        match $e {
            Ok(result) => result,
            Err(err) => return Err(ProcessingError::from(err))
        }
    }
}

#[macro_export]
macro_rules! unwrap_or_qr_processing_failure {
    ($e: expr) => {
        unwrap_or_return!($e, || crate::processing::QRInfoResult::default())
    };
}

#[macro_export]
macro_rules! unwrap_or_diff_processing_failure {
    ($e: expr) => {
        unwrap_or_return!($e, || crate::processing::MNListDiffResult::default())
    };
}
