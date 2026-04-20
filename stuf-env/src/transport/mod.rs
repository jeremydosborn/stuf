//! Mock transport for testing and demo.

use std::collections::HashMap;
use stuf_tuf::env::transport::Transport;

pub struct MockTransport {
    files: HashMap<String, Vec<u8>>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self { files: HashMap::new() }
    }

    pub fn add(mut self, name: &str, content: Vec<u8>) -> Self {
        self.files.insert(name.to_string(), content);
        self
    }
}

impl Default for MockTransport {
    fn default() -> Self { Self::new() }
}

#[derive(Debug)]
pub struct TransportError(pub String);

impl Transport for MockTransport {
    type Buffer = Vec<u8>;
    type Error = TransportError;

    fn fetch(&self, id: &str) -> Result<Vec<u8>, TransportError> {
        self.files
            .get(id)
            .cloned()
            .ok_or_else(|| TransportError(format!("file not found: {id}")))
    }
}
