//! Mock transport for testing and demo.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use super::Transport;

pub struct MockTransport {
    files: BTreeMap<String, Vec<u8>>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self {
            files: BTreeMap::new(),
        }
    }

    pub fn add(mut self, name: &str, content: Vec<u8>) -> Self {
        self.files.insert(String::from(name), content);
        self
    }
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct MockTransportError(pub String);

impl Transport for MockTransport {
    type Buffer = Vec<u8>;
    type Error = MockTransportError;

    fn fetch(&self, id: &str) -> Result<Vec<u8>, MockTransportError> {
        self.files
            .get(id)
            .cloned()
            .ok_or_else(|| MockTransportError(alloc::format!("file not found: {id}")))
    }
}
