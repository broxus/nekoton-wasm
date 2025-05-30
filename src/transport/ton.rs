use std::sync::Arc;
use wasm_bindgen::prelude::*;
use crate::external::ITonSender;

#[wasm_bindgen]
pub struct TonConnection {
    #[wasm_bindgen(skip)]
    pub inner: Arc<ITonSender>,
}

#[wasm_bindgen]
impl TonConnection {
    #[wasm_bindgen(constructor)]
    pub fn new(sender: ITonSender) -> Self {
        Self {
            inner: Arc::new(sender),
        }
    }
}
