use std::sync::Arc;

use wasm_bindgen::prelude::*;

use crate::external::{ProtoConnector, ProtoSender};

#[wasm_bindgen]
pub struct ProtoConnection {
    #[wasm_bindgen(skip)]
    pub inner: Arc<ProtoConnector>,
}

#[wasm_bindgen]
impl ProtoConnection {
    #[wasm_bindgen(constructor)]
    pub fn new(sender: ProtoSender) -> Self {
        Self {
            inner: Arc::new(ProtoConnector::new(sender)),
        }
    }
}
