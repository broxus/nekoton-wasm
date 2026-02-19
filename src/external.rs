use anyhow::Result;
use tokio::sync::oneshot;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const GQL_SENDER: &str = r#"
export interface IGqlSender {
  isLocal(): boolean;
  send(data: string, handler: StringQuery, long_query: boolean): void;
}

export interface IJrpcSender {
  send(data: string, handler: StringQuery, requires_db: boolean): void;
}

export interface IProtoSender {
  send(data: Uint8Array, handler: BytesQuery, requires_db: boolean): void;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "IGqlSender")]
    pub type IGqlSender;

    #[wasm_bindgen(method, js_name = "isLocal")]
    pub fn is_local(this: &IGqlSender) -> bool;

    #[wasm_bindgen(method)]
    pub fn send(this: &IGqlSender, data: &str, handler: StringQuery, long_query: bool);
}

unsafe impl Send for IGqlSender {}
unsafe impl Sync for IGqlSender {}

#[async_trait::async_trait(?Send)]
impl nt::external::GqlConnection for IGqlSender {
    fn is_local(&self) -> bool {
        self.is_local()
    }

    async fn post(&self, req: nt::external::GqlRequest) -> Result<String> {
        let (tx, rx) = oneshot::channel();

        self.send(&req.data, StringQuery { tx }, req.long_query);
        drop(req);

        let response = rx.await.unwrap_or(Err(QueryError::RequestDropped))?;
        Ok(response)
    }
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "IJrpcSender")]
    pub type IJrpcSender;

    #[wasm_bindgen(method)]
    pub fn send(this: &IJrpcSender, data: &str, query: StringQuery, requires_db: bool);
}

unsafe impl Send for IJrpcSender {}
unsafe impl Sync for IJrpcSender {}

#[async_trait::async_trait(?Send)]
impl nt::external::JrpcConnection for IJrpcSender {
    async fn post(&self, req: nt::external::JrpcRequest) -> Result<String> {
        let (tx, rx) = oneshot::channel();
        let query = StringQuery { tx };
        self.send(&req.data, query, req.requires_db);
        drop(req);

        Ok(rx.await.unwrap_or(Err(QueryError::RequestFailed))?)
    }
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "IProtoSender")]
    pub type IProtoSender;

    #[wasm_bindgen(method)]
    pub fn send(this: &IProtoSender, data: &[u8], query: BytesQuery, requires_db: bool);
}

unsafe impl Send for IProtoSender {}
unsafe impl Sync for IProtoSender {}

#[async_trait::async_trait(?Send)]
impl nt::external::ProtoConnection for IProtoSender {
    async fn post(&self, req: nt::external::ProtoRequest) -> Result<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        let query = BytesQuery { tx };
        self.send(&req.data, query, req.requires_db);
        drop(req);

        Ok(rx.await.unwrap_or(Err(QueryError::RequestFailed))?)
    }
}

#[wasm_bindgen]
pub struct BytesQuery {
    #[wasm_bindgen(skip)]
    pub tx: oneshot::Sender<BytesQueryResult>,
}

pub type BytesQueryResult = Result<Vec<u8>, QueryError>;

#[wasm_bindgen]
impl BytesQuery {
    #[wasm_bindgen(js_name = "onReceive")]
    pub fn on_receive(self, data: Vec<u8>) {
        let _ = self.tx.send(Ok(data));
    }

    #[wasm_bindgen(js_name = "onError")]
    pub fn on_error(self, _: JsValue) {
        let _ = self.tx.send(Err(QueryError::RequestFailed));
    }

    #[wasm_bindgen(js_name = "onTimeout")]
    pub fn on_timeout(self) {
        let _ = self.tx.send(Err(QueryError::TimeoutReached));
    }
}

#[wasm_bindgen]
pub struct StringQuery {
    #[wasm_bindgen(skip)]
    pub tx: oneshot::Sender<StringQueryResult>,
}

pub type StringQueryResult = Result<String, QueryError>;

#[wasm_bindgen]
impl StringQuery {
    #[wasm_bindgen(js_name = "onReceive")]
    pub fn on_receive(self, data: String) {
        let _ = self.tx.send(Ok(data));
    }

    #[wasm_bindgen(js_name = "onError")]
    pub fn on_error(self, _: JsValue) {
        let _ = self.tx.send(Err(QueryError::RequestFailed));
    }

    #[wasm_bindgen(js_name = "onTimeout")]
    pub fn on_timeout(self) {
        let _ = self.tx.send(Err(QueryError::TimeoutReached));
    }
}

#[derive(thiserror::Error, Debug)]
pub enum QueryError {
    #[error("Request dropped unexpectedly")]
    RequestDropped,
    #[error("Timeout reached")]
    TimeoutReached,
    #[error("Request failed")]
    RequestFailed,
}

#[wasm_bindgen(typescript_custom_section)]
const PROXY_TRANSPORT: &str = r#"
export interface IProxyConnector {
  info(): TransportInfo;
  sendMessage(message: string): Promise<void>;
  getContractState(address: string): Promise<string>;
  getAccountsByCodeHash(codeHash: string, limit: number, continuation?: string): Promise<string[]>;
  getTransactions(address: string, fromLt: string, count: number): Promise<string[]>;
  getTransaction(id: string): Promise<string | undefined>;
  getDstTransaction(msg_hash: string): Promise<string | undefined>;
  getLatestKeyBlock(): Promise<string>;
  getCapabilities(now_ms: string): Promise<NetworkCapabilities>;
  getBlockchainConfig(now_ms: string): Promise<BlockchainConfig>;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "IProxyConnector")]
    pub type IProxyConnector;

    #[wasm_bindgen(method, catch)]
    pub fn info(this: &IProxyConnector) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = "sendMessage")]
    pub async fn send_message(this: &IProxyConnector, message: &str) -> Result<(), JsValue>;

    #[wasm_bindgen(method, catch, js_name = "getContractState")]
    pub async fn get_contract_state(
        this: &IProxyConnector,
        address: &str,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = "getAccountsByCodeHash")]
    pub async fn get_accounts_by_code_hash(
        this: &IProxyConnector,
        code_hash: &str,
        limit: u8,
        continuation: Option<String>,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = "getTransactions")]
    pub async fn get_transactions(
        this: &IProxyConnector,
        address: &str,
        from_lt: &str,
        count: u8,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = "getTransaction")]
    pub async fn get_transaction(this: &IProxyConnector, id: &str) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = "getDstTransaction")]
    pub async fn get_dst_transaction(
        this: &IProxyConnector,
        message_hash: &str,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = "getLatestKeyBlock")]
    pub async fn get_latest_key_block(this: &IProxyConnector) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = "getCapabilities")]
    pub async fn get_capabilities(this: &IProxyConnector, now_ms: &str)
        -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = "getBlockchainConfig")]
    pub async fn get_blockchain_config(
        this: &IProxyConnector,
        now_ms: &str,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = "getLibraryCell")]
    pub async fn get_library_cell(this: &IProxyConnector, hash: &str) -> Result<JsValue, JsValue>;
}

unsafe impl Send for IProxyConnector {}
unsafe impl Sync for IProxyConnector {}
