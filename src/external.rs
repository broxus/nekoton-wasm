use std::sync::Arc;

use anyhow::Result;
use tokio::sync::oneshot;
use wasm_bindgen::prelude::*;

pub struct GqlConnectionImpl {
    sender: Arc<IGqlSender>,
}

impl GqlConnectionImpl {
    pub fn new(sender: IGqlSender) -> Self {
        Self {
            sender: Arc::new(sender),
        }
    }
}

#[async_trait::async_trait]
impl nt::external::GqlConnection for GqlConnectionImpl {
    fn is_local(&self) -> bool {
        self.sender.is_local()
    }

    async fn post(&self, data: &str) -> Result<String> {
        let (tx, rx) = oneshot::channel();

        self.sender.send(data, GqlQuery { tx });

        let response = rx.await.unwrap_or(Err(GqlQueryError::RequestDropped))?;
        Ok(response)
    }
}

#[wasm_bindgen(typescript_custom_section)]
const GQL_SENDER: &str = r#"
export interface IGqlSender {
  isLocal(): boolean;
  send(data: string, handler: GqlQuery): void;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "IGqlSender")]
    pub type IGqlSender;

    #[wasm_bindgen(method, js_name = "isLocal")]
    pub fn is_local(this: &IGqlSender) -> bool;

    #[wasm_bindgen(method)]
    pub fn send(this: &IGqlSender, data: &str, handler: GqlQuery);
}

unsafe impl Send for IGqlSender {}
unsafe impl Sync for IGqlSender {}

#[wasm_bindgen]
pub struct GqlQuery {
    #[wasm_bindgen(skip)]
    pub tx: oneshot::Sender<GqlQueryResult>,
}

#[wasm_bindgen]
impl GqlQuery {
    #[wasm_bindgen(js_name = "onReceive")]
    pub fn on_receive(self, data: String) {
        let _ = self.tx.send(Ok(data));
    }

    #[wasm_bindgen(js_name = "onError")]
    pub fn on_error(self, _: JsValue) {
        let _ = self.tx.send(Err(GqlQueryError::RequestFailed));
    }

    #[wasm_bindgen(js_name = "onTimeout")]
    pub fn on_timeout(self) {
        let _ = self.tx.send(Err(GqlQueryError::TimeoutReached));
    }
}

type GqlQueryResult = Result<String, GqlQueryError>;

#[derive(thiserror::Error, Debug)]
pub enum GqlQueryError {
    #[error("Request dropped unexpectedly")]
    RequestDropped,
    #[error("Timeout reached")]
    TimeoutReached,
    #[error("Request failed")]
    RequestFailed,
}
