use std::sync::Arc;

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::*;

use crate::external::{GqlConnectionImpl, IGqlSender};
use crate::models::*;
use crate::utils::*;

#[wasm_bindgen]
#[derive(Clone)]
pub struct GqlConnection {
    #[wasm_bindgen(skip)]
    pub inner: Arc<GqlConnectionImpl>,
}

#[wasm_bindgen]
impl GqlConnection {
    #[wasm_bindgen(constructor)]
    pub fn new(sender: IGqlSender) -> Self {
        Self {
            inner: Arc::new(GqlConnectionImpl::new(sender)),
        }
    }

    #[wasm_bindgen(js_name = "getLatestBlock")]
    pub fn get_latest_block(&self, address: &str) -> Result<PromiseLatestBlock, JsValue> {
        let address = parse_address(address)?;
        let transport = self.make_transport();

        Ok(JsCast::unchecked_into(future_to_promise(async move {
            let latest_block = transport.get_latest_block(&address).await.handle_error()?;
            Ok(make_latest_block(latest_block))
        })))
    }

    #[wasm_bindgen(js_name = "waitForNextBlock")]
    pub fn wait_for_next_block(
        &self,
        current_block_id: String,
        address: &str,
        timeout: u32,
    ) -> Result<PromiseString, JsValue> {
        let address = parse_address(address)?;
        let transport = self.make_transport();

        Ok(JsCast::unchecked_into(future_to_promise(async move {
            let next_block = transport
                .wait_for_next_block(
                    &current_block_id,
                    &address,
                    std::time::Duration::from_secs(timeout as u64),
                )
                .await
                .handle_error()?;
            Ok(JsValue::from(next_block))
        })))
    }
}

impl GqlConnection {
    pub fn make_transport(&self) -> nt::transport::gql::GqlTransport {
        nt::transport::gql::GqlTransport::new(self.inner.clone())
    }
}
