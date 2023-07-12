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

    async fn post(&self, req: nt::external::GqlRequest) -> Result<String> {
        let (tx, rx) = oneshot::channel();

        self.sender.send(&req.data, GqlQuery { tx }, req.long_query);
        drop(req);

        let response = rx.await.unwrap_or(Err(GqlQueryError::RequestDropped))?;
        Ok(response)
    }
}

#[wasm_bindgen(typescript_custom_section)]
const GQL_SENDER: &str = r#"
export interface IGqlSender {
  isLocal(): boolean;
  send(data: string, handler: GqlQuery, long_query: boolean): void;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "IGqlSender")]
    pub type IGqlSender;

    #[wasm_bindgen(method, js_name = "isLocal")]
    pub fn is_local(this: &IGqlSender) -> bool;

    #[wasm_bindgen(method)]
    pub fn send(this: &IGqlSender, data: &str, handler: GqlQuery, long_query: bool);
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

unsafe impl Send for JrpcSender {}
unsafe impl Sync for JrpcSender {}

#[wasm_bindgen]
extern "C" {
    pub type JrpcSender;
    #[wasm_bindgen(method)]
    pub fn send(this: &JrpcSender, data: &str, query: JrpcQuery, requires_db: bool);
}

#[derive(Clone)]
pub struct JrpcConnector {
    sender: Arc<JrpcSender>,
}

impl JrpcConnector {
    pub fn new(sender: JrpcSender) -> Self {
        Self {
            sender: Arc::new(sender),
        }
    }
}

#[wasm_bindgen]
pub struct JrpcQuery {
    #[wasm_bindgen(skip)]
    pub tx: oneshot::Sender<JrpcQueryResult>,
}

pub type JrpcQueryResult = Result<String, JrpcError>;

#[derive(thiserror::Error, Debug)]
pub enum JrpcError {
    #[error("Request dropped unexpectedly")]
    RequestDropped,
    #[error("Timeout reached")]
    TimeoutReached,
    #[error("Request failed")]
    RequestFailed,
}

#[wasm_bindgen]
impl JrpcQuery {
    #[wasm_bindgen(js_name = "onReceive")]
    pub fn on_receive(self, data: String) {
        let _ = self.tx.send(Ok(data));
    }

    #[wasm_bindgen(js_name = "onError")]
    pub fn on_error(self, _: JsValue) {
        let _ = self.tx.send(Err(JrpcError::RequestFailed));
    }

    #[wasm_bindgen(js_name = "onTimeout")]
    pub fn on_timeout(self) {
        let _ = self.tx.send(Err(JrpcError::TimeoutReached));
    }
}

#[async_trait::async_trait]
impl nt::external::JrpcConnection for JrpcConnector {
    async fn post(&self, req: nt::external::JrpcRequest) -> Result<String> {
        let (tx, rx) = oneshot::channel();
        let query = JrpcQuery { tx };
        self.sender.send(&req.data, query, req.requires_db);
        drop(req);

        Ok(rx.await.unwrap_or(Err(JrpcError::RequestFailed))?)
    }
}

#[wasm_bindgen(typescript_custom_section)]
const PROXY_TRANSPORT: &str = r#"
export interface IProxyConnector {
  info(): TransportInfo;
  sendMessage(message: string): void;
  getContractState(address: string): RawContractState | null;
  getAccountsByCodeHash(codeHash: string, limit: number, continuation?: string): string[];
  getTransactions(address: string, fromLt: string, count: number): string[];
  getTransaction(id: string): string | null;
  getDstTransaction(msg_hash: string): string | null;
  getLatestKeyBlock(): string;
  getCapabilities(clock_offset_as_sec: string, clock_offset_as_ms: string): string[];
  getBlockchainConfig(): string[];
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "IProxyConnector")]
    pub type IProxyConnector;

    #[wasm_bindgen(method)]
    pub fn info(this: &IProxyConnector) -> JsValue;

    #[wasm_bindgen(method, js_name = "sendMessage")]
    pub fn send_message(this: &IProxyConnector, message: &str);

    #[wasm_bindgen(method, js_name = "getContractState")]
    pub fn get_contract_state(this: &IProxyConnector, address: &str) -> JsValue;

    #[wasm_bindgen(method, js_name = "getAccountsByCodeHash")]
    pub fn get_accounts_by_code_hash(
        this: &IProxyConnector,
        code_hash: &str,
        limit: u8,
        continuation: Option<String>,
    ) -> JsValue;

    #[wasm_bindgen(method, js_name = "getTransactions")]
    pub fn get_transactions(
        this: &IProxyConnector,
        address: &str,
        from_lt: &str,
        count: u8,
    ) -> JsValue;

    #[wasm_bindgen(method, js_name = "getTransaction")]
    pub fn get_transaction(this: &IProxyConnector, id: &str) -> JsValue;

    #[wasm_bindgen(method, js_name = "getDstTransaction")]
    pub fn get_dst_transaction(this: &IProxyConnector, message_hash: &str) -> JsValue;

    #[wasm_bindgen(method, js_name = "getLatestKeyBlock")]
    pub fn get_latest_key_block(this: &IProxyConnector) -> JsValue;

    #[wasm_bindgen(method, js_name = "getCapabilities")]
    pub fn get_capabilities(
        this: &IProxyConnector,
        clock_offset_as_sec: &str,
        clock_offset_as_ms: &str,
    ) -> JsValue;

    #[wasm_bindgen(method, js_name = "getBlockchainConfig")]
    pub fn get_blockchain_config(this: &IProxyConnector) -> JsValue;
}

unsafe impl Send for IProxyConnector {}
unsafe impl Sync for IProxyConnector {}
