use std::sync::Arc;

use anyhow::Result;
use nt::core::models::NetworkCapabilities;
use nt::transport::models::{RawContractState, RawTransaction};
use nt::transport::{Transport, TransportInfo};
use nt::utils::Clock;
use ton_block::{Block, MsgAddressInt};
use wasm_bindgen::prelude::*;

use crate::external::IProxyConnector;
use crate::utils::*;

#[wasm_bindgen]
pub struct ProxyConnection {
    #[wasm_bindgen(skip)]
    pub inner: Arc<IProxyConnector>,
    #[wasm_bindgen(skip)]
    pub clock: Arc<nt::utils::ClockWithOffset>,
}

#[wasm_bindgen]
impl ProxyConnection {
    #[wasm_bindgen(constructor)]
    pub fn new(clock: &ClockWithOffset, proxy_connector: IProxyConnector) -> Self {
        Self {
            inner: Arc::new(proxy_connector),
            clock: clock.clone_inner(),
        }
    }
}

pub struct ProxyTransport {
    _connection: Arc<IProxyConnector>,
}

impl ProxyTransport {
    pub fn new(connection: Arc<IProxyConnector>) -> Self {
        Self {
            _connection: connection,
        }
    }
}

#[async_trait::async_trait]
impl Transport for ProxyTransport {
    fn info(&self) -> TransportInfo {
        todo!()
    }

    async fn send_message(&self, _message: &ton_block::Message) -> Result<()> {
        todo!()
    }

    async fn get_contract_state(&self, _address: &MsgAddressInt) -> Result<RawContractState> {
        todo!()
    }

    async fn get_accounts_by_code_hash(
        &self,
        _code_hash: &ton_types::UInt256,
        _limit: u8,
        _continuation: &Option<MsgAddressInt>,
    ) -> Result<Vec<MsgAddressInt>> {
        todo!()
    }

    async fn get_transactions(
        &self,
        _address: &MsgAddressInt,
        _from_lt: u64,
        _count: u8,
    ) -> Result<Vec<RawTransaction>> {
        todo!()
    }

    async fn get_transaction(&self, _id: &ton_types::UInt256) -> Result<Option<RawTransaction>> {
        todo!()
    }

    async fn get_dst_transaction(
        &self,
        _message_hash: &ton_types::UInt256,
    ) -> Result<Option<RawTransaction>> {
        todo!()
    }

    async fn get_latest_key_block(&self) -> Result<Block> {
        todo!()
    }

    async fn get_capabilities(&self, _clock: &dyn Clock) -> Result<NetworkCapabilities> {
        todo!()
    }

    async fn get_blockchain_config(
        &self,
        _clock: &dyn Clock,
        _force: bool,
    ) -> Result<ton_executor::BlockchainConfig> {
        todo!()
    }
}
