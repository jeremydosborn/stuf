/// Storage abstraction — where trusted state is persisted.
///
/// stuf-tuf uses storage to persist the last trusted metadata versions
/// so rollback attacks can be detected across restarts. The implementor
/// decides how and where data is stored — filesystem, flash, EEPROM,
/// RAM, S3, etc.
///
/// The buffer type for reads is chosen by the implementor, same
/// pattern as Transport — no allocation assumptions.
pub trait Storage {
    /// The buffer type returned by get.
    type Buffer: AsRef<[u8]>;

    /// The error type for storage failures.
    type Error: core::fmt::Debug;

    /// Retrieve a stored value by key.
    /// Returns None if the key does not exist.
    fn get(&self, key: &str) -> Result<Option<Self::Buffer>, Self::Error>;

    /// Store a value under a key.
    /// Overwrites any existing value.
    fn put(&self, key: &str, value: &[u8]) -> Result<(), Self::Error>;

    /// Delete a stored value.
    /// No-op if the key does not exist.
    fn delete(&self, key: &str) -> Result<(), Self::Error>;
}
