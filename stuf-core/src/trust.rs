use crate::artifact::Bundle;
use crate::error::StufError;

pub struct Verified<T> {
    payload: T,
}

impl<T> Verified<T> {
    pub fn into_inner(self) -> T {
        self.payload
    }

    pub fn payload(&self) -> &T {
        &self.payload
    }
}

pub trait Verifier<T> {
    fn verify(&self, bundle: impl Bundle) -> Result<Verified<T>, StufError>;
}
