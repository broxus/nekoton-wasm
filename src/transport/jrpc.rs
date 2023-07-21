use std::sync::Arc;

use wasm_bindgen::prelude::*;

use crate::external::{JrpcConnector, JrpcSender};

#[wasm_bindgen]
pub struct JrpcConnection {
    #[wasm_bindgen(skip)]
    pub inner: Arc<JrpcConnector>,
}

#[wasm_bindgen]
impl JrpcConnection {
    #[wasm_bindgen(constructor)]
    pub fn new(sender: JrpcSender) -> Self {
        Self {
            inner: Arc::new(JrpcConnector::new(sender)),
        }
    }
}
