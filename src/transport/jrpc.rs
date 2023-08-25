use std::sync::Arc;

use wasm_bindgen::prelude::*;

use crate::external::IJrpcSender;

#[wasm_bindgen]
pub struct JrpcConnection {
    #[wasm_bindgen(skip)]
    pub inner: Arc<IJrpcSender>,
}

#[wasm_bindgen]
impl JrpcConnection {
    #[wasm_bindgen(constructor)]
    pub fn new(sender: IJrpcSender) -> Self {
        Self {
            inner: Arc::new(sender),
        }
    }
}
