//! Crate-wide error type.

/// Errors returned by ble-doctor.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Feature not implemented yet.
    #[error("not yet implemented (#{0})")]
    NotImplemented(u32),
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, Error>;
