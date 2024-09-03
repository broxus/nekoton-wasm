use std::str::FromStr;
use std::sync::Arc;

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::*;

use crate::generic_contract::*;
use crate::models::*;
use crate::utils::*;

pub mod gql;
pub mod jrpc;
pub mod proto;
pub mod proxy;

#[derive(Clone)]
pub enum TransportHandle {
    GraphQl(Arc<nt::transport::gql::GqlTransport>),
    Jrpc(Arc<nt::transport::jrpc::JrpcTransport>),
    Proto(Arc<nt::transport::proto::ProtoTransport>),
    Proxy(Arc<proxy::ProxyTransport>),
}

impl TransportHandle {
    pub async fn get_block(&self, block_id: &str) -> Result<Vec<u8>, JsValue> {
        match self {
            Self::GraphQl(transport) => transport.get_block(block_id).await.handle_error(),
            _ => Err(TransportError::MethodNotSupported).handle_error(),
        }
    }
}

impl<'a> AsRef<dyn nt::transport::Transport + 'a> for TransportHandle {
    fn as_ref(&self) -> &(dyn nt::transport::Transport + 'a) {
        match self {
            Self::GraphQl(transport) => transport.as_ref(),
            Self::Jrpc(transport) => transport.as_ref(),
            Self::Proto(transport) => transport.as_ref(),
            Self::Proxy(transport) => transport.as_ref(),
        }
    }
}

impl From<TransportHandle> for Arc<dyn nt::transport::Transport> {
    fn from(handle: TransportHandle) -> Self {
        match handle {
            TransportHandle::GraphQl(transport) => transport,
            TransportHandle::Jrpc(transport) => transport,
            TransportHandle::Proto(transport) => transport,
            TransportHandle::Proxy(transport) => transport,
        }
    }
}

#[wasm_bindgen]
pub struct Transport {
    #[wasm_bindgen(skip)]
    pub handle: TransportHandle,
    #[wasm_bindgen(skip)]
    pub clock: Arc<nt::utils::ClockWithOffset>,
}

#[wasm_bindgen]
impl Transport {
    #[wasm_bindgen(js_name = "fromGqlConnection")]
    pub fn from_gql_connection(gql: &gql::GqlConnection, clock: &ClockWithOffset) -> Transport {
        let transport = Arc::new(nt::transport::gql::GqlTransport::new(gql.inner.clone()));
        Self {
            handle: TransportHandle::GraphQl(transport),
            clock: clock.clone_inner(),
        }
    }

    #[wasm_bindgen(js_name = "fromJrpcConnection")]
    pub fn from_jrpc_connection(jrpc: &jrpc::JrpcConnection, clock: &ClockWithOffset) -> Transport {
        let transport = Arc::new(nt::transport::jrpc::JrpcTransport::new(jrpc.inner.clone()));
        Self {
            handle: TransportHandle::Jrpc(transport),
            clock: clock.clone_inner(),
        }
    }

    #[wasm_bindgen(js_name = "fromProtoConnection")]
    pub fn from_proto_connection(
        proto: &proto::ProtoConnection,
        clock: &ClockWithOffset,
    ) -> Transport {
        let transport = Arc::new(nt::transport::proto::ProtoTransport::new(
            proto.inner.clone(),
        ));
        Self {
            handle: TransportHandle::Proto(transport),
            clock: clock.clone_inner(),
        }
    }

    #[wasm_bindgen(js_name = "fromProxyConnection")]
    pub fn from_proxy_connection(
        proxy: &proxy::ProxyConnection,
        clock: &ClockWithOffset,
    ) -> Transport {
        let transport = Arc::new(proxy::ProxyTransport::new(proxy.inner.clone()));
        Self {
            handle: TransportHandle::Proxy(transport),
            clock: clock.clone_inner(),
        }
    }

    #[wasm_bindgen(js_name = "getNetworkDescription")]
    pub fn get_network_description(&self) -> PromiseNetworkDescription {
        let clock = self.clock.clone();
        let handle = self.handle.clone();

        JsCast::unchecked_into(future_to_promise(async move {
            let capabilities = handle
                .as_ref()
                .get_capabilities(clock.as_ref())
                .await
                .handle_error()?;
            Ok(make_network_description(capabilities))
        }))
    }

    #[wasm_bindgen(js_name = "getSignatureId")]
    pub fn get_signature_id(&self) -> PromiseOptionSignatureId {
        let clock = self.clock.clone();
        let handle = self.handle.clone();

        JsCast::unchecked_into(future_to_promise(async move {
            let network_id = handle
                .as_ref()
                .get_capabilities(clock.as_ref())
                .await
                .handle_error()?;
            Ok(JsValue::from(network_id.signature_id()))
        }))
    }

    #[wasm_bindgen(js_name = "getBlockchainConfig")]
    pub fn get_blockchain_config(&self, force: Option<bool>) -> PromiseString {
        let clock = self.clock.clone();
        let handle = self.handle.clone();

        JsCast::unchecked_into(future_to_promise(async move {
            let config = handle
                .as_ref()
                .get_blockchain_config(clock.as_ref(), force.unwrap_or_default())
                .await
                .handle_error()?;

            let config = serialize_into_boc(config.raw_config())?;
            Ok(JsValue::from(config))
        }))
    }

    #[wasm_bindgen(js_name = "subscribeToGenericContract")]
    pub fn subscribe_to_generic_contract_wallet(
        &self,
        address: &str,
        handler: GenericContractSubscriptionHandlerImpl,
    ) -> Result<PromiseGenericContract, JsValue> {
        let address = parse_address(address)?;

        let clock = self.clock.clone();
        let handle = self.handle.clone();
        let handler = Arc::new(GenericContractSubscriptionHandler::from(handler));

        Ok(JsCast::unchecked_into(future_to_promise(async move {
            let contract = nt::core::generic_contract::GenericContract::subscribe(
                clock,
                handle.clone().into(),
                address,
                handler,
                false,
            )
            .await
            .handle_error()?;

            Ok(JsValue::from(GenericContract::new(handle, contract)))
        })))
    }

    #[wasm_bindgen(js_name = "getFullContractState")]
    pub fn get_full_account_state(
        &self,
        address: &str,
    ) -> Result<PromiseOptionFullContractState, JsValue> {
        let address = parse_address(address)?;
        let handle = self.handle.clone();

        Ok(JsCast::unchecked_into(future_to_promise(async move {
            make_full_contract_state(
                handle
                    .as_ref()
                    .get_contract_state(&address)
                    .await
                    .handle_error()?,
            )
        })))
    }

    #[wasm_bindgen(js_name = "getAccountsByCodeHash")]
    pub fn get_accounts_by_code_hash(
        &self,
        code_hash: &str,
        limit: u8,
        continuation: Option<String>,
    ) -> Result<PromiseAccountsList, JsValue> {
        let code_hash = parse_hash(code_hash)?;
        let continuation = continuation.map(|addr| parse_address(&addr)).transpose()?;
        let handle = self.handle.clone();

        Ok(JsCast::unchecked_into(future_to_promise(async move {
            let accounts = handle
                .as_ref()
                .get_accounts_by_code_hash(&code_hash, limit, &continuation)
                .await
                .handle_error()?;

            let without_continuation = accounts.len() < limit as usize;
            Ok(make_accounts_list(accounts, without_continuation).unchecked_into())
        })))
    }

    #[wasm_bindgen(js_name = "getTransactions")]
    pub fn get_transactions(
        &self,
        address: &str,
        continuation: Option<String>,
        limit: u8,
    ) -> Result<PromiseTransactionsList, JsValue> {
        let address = parse_address(address)?;
        let from_lt = continuation
            .map(|s| u64::from_str(&s))
            .transpose()
            .handle_error()?
            .unwrap_or(u64::MAX);
        let handle = self.handle.clone();

        Ok(JsCast::unchecked_into(future_to_promise(async move {
            let raw_transactions = handle
                .as_ref()
                .get_transactions(&address, from_lt, limit)
                .await
                .handle_error()?;
            Ok(make_transactions_list(raw_transactions).unchecked_into())
        })))
    }

    #[wasm_bindgen(js_name = "getTransaction")]
    pub fn get_transaction(&self, hash: &str) -> Result<PromiseOptionTransaction, JsValue> {
        let hash = parse_hash(hash)?;
        let handle = self.handle.clone();

        Ok(JsCast::unchecked_into(future_to_promise(async move {
            Ok(
                match handle
                    .as_ref()
                    .get_transaction(&hash)
                    .await
                    .handle_error()?
                {
                    Some(transaction) => nt::core::models::Transaction::try_from((
                        transaction.hash,
                        transaction.data,
                    ))
                    .map(make_transaction)
                    .handle_error()?
                    .unchecked_into(),
                    None => JsValue::undefined(),
                },
            )
        })))
    }

    #[wasm_bindgen(js_name = "getDstTransaction")]
    pub fn get_dst_transaction(
        &self,
        message_hash: &str,
    ) -> Result<PromiseOptionTransaction, JsValue> {
        let message_hash = parse_hash(message_hash)?;
        let handle = self.handle.clone();

        Ok(JsCast::unchecked_into(future_to_promise(async move {
            Ok(
                match handle
                    .as_ref()
                    .get_dst_transaction(&message_hash)
                    .await
                    .handle_error()?
                {
                    Some(transaction) => nt::core::models::Transaction::try_from((
                        transaction.hash,
                        transaction.data,
                    ))
                    .map(make_transaction)
                    .handle_error()?
                    .unchecked_into(),
                    None => JsValue::undefined(),
                },
            )
        })))
    }
}

#[derive(thiserror::Error, Debug)]
enum TransportError {
    #[error("Method not supported")]
    MethodNotSupported,
}
