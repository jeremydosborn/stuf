use crate::artifact::Bundle;
use crate::error::StufError;

pub struct Verified<T> {
    payload: T,
}

impl<T> Verified<T> {
    fn new(payload: T) -> Self {
        Self { payload }
    }

    pub fn into_inner(self) -> T {
        self.payload
    }

    pub fn as_ref(&self) -> &T {
        &self.payload
    }
}

pub trait Verifier<T> {
    fn verify(&self, bundle: impl Bundle) -> Result<Verified<T>, StufError>;
}
