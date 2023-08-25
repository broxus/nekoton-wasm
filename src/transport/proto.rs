use std::sync::Arc;

use wasm_bindgen::prelude::*;

use crate::external::IProtoSender;

#[wasm_bindgen]
pub struct ProtoConnection {
    #[wasm_bindgen(skip)]
    pub inner: Arc<IProtoSender>,
}

#[wasm_bindgen]
impl ProtoConnection {
    #[wasm_bindgen(constructor)]
    pub fn new(sender: IProtoSender) -> Self {
        Self {
            inner: Arc::new(sender),
        }
    }
}
