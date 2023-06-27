use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use nt::core::models::NetworkCapabilities;
use nt::transport::models::{RawContractState, RawTransaction};
use nt::transport::{Transport, TransportInfo};
use nt::utils::Clock;
use serde_json;
use ton_block::{Block, Deserializable, MsgAddressInt, Serializable};
use wasm_bindgen::prelude::*;

use crate::external::ILocalConnection;
use crate::utils::*;

#[wasm_bindgen]
pub struct LocalConnection {
    #[wasm_bindgen(skip)]
    pub inner: Arc<ILocalConnection>,
    #[wasm_bindgen(skip)]
    pub clock: Arc<nt::utils::ClockWithOffset>,
}

#[wasm_bindgen]
impl LocalConnection {
    #[wasm_bindgen(constructor)]
    pub fn new(clock: &ClockWithOffset, local_connection: ILocalConnection) -> Self {
        Self {
            inner: Arc::new(local_connection),
            clock: clock.clone_inner(),
        }
    }
}

pub struct LocalTransport {
    connection: Arc<ILocalConnection>,
}

impl LocalTransport {
    pub fn new(connection: Arc<ILocalConnection>) -> Self {
        Self { connection }
    }
}

#[async_trait::async_trait]
impl Transport for LocalTransport {
    fn info(&self) -> TransportInfo {
        todo!()
    }

    async fn send_message(&self, message: &ton_block::Message) -> Result<()> {
        Ok(self
            .connection
            .send_message(&base64::encode(message.write_to_bytes()?)))
    }

    async fn get_contract_state(&self, address: &MsgAddressInt) -> Result<RawContractState> {
        let str_state = self.connection.get_contract_state(&address.to_string());
        match str_state {
            Some(state) => Ok(serde_json::from_str::<RawContractState>(&state)?),
            None => Ok(RawContractState::NotExists),
        }
    }

    async fn get_accounts_by_code_hash(
        &self,
        code_hash: &ton_types::UInt256,
        limit: u8,
        continuation: &Option<MsgAddressInt>,
    ) -> Result<Vec<MsgAddressInt>> {
        let addr = continuation.as_ref().map(|addr| addr.to_string());
        let accs_list: StringArray =
            self.connection
                .get_accounts_by_code_hash(&code_hash.to_string(), limit, addr);
        let arr: js_sys::Array = accs_list.unchecked_into();
        Ok(arr
            .iter()
            .filter_map(|addr| {
                addr.as_string()
                    .and_then(|s| MsgAddressInt::from_str(&s).ok())
            })
            .collect())
    }

    async fn get_transactions(
        &self,
        address: &MsgAddressInt,
        from_lt: u64,
        count: u8,
    ) -> Result<Vec<RawTransaction>> {
        let response =
            self.connection
                .get_transactions(&address.to_string(), &from_lt.to_string(), count);
        let arr: js_sys::Array = response.unchecked_into();
        Ok(arr
            .iter()
            .filter_map(|boc| {
                boc.as_string()
                    .and_then(|s| decode_raw_transaction(&s).ok())
            })
            .collect())
    }

    async fn get_transaction(&self, id: &ton_types::UInt256) -> Result<Option<RawTransaction>> {
        let transaction = self.connection.get_transaction(&id.to_string());
        match transaction {
            None => Ok(None),
            Some(boc) => decode_raw_transaction(&boc).map(Some),
        }
    }

    async fn get_dst_transaction(
        &self,
        message_hash: &ton_types::UInt256,
    ) -> Result<Option<RawTransaction>> {
        let transaction = self
            .connection
            .get_dst_transaction(&message_hash.to_string());
        match transaction {
            None => Ok(None),
            Some(boc) => decode_raw_transaction(&boc).map(Some),
        }
    }

    async fn get_latest_key_block(&self) -> Result<Block> {
        let block_boc = self.connection.get_latest_key_block();
        Ok(ton_block::Block::construct_from_base64(&block_boc)?)
    }

    async fn get_capabilities(&self, clock: &dyn Clock) -> Result<NetworkCapabilities> {
        let network = self.connection.get_capabilities(
            &clock.now_sec_u64().to_string(),
            &clock.now_ms_u64().to_string(),
        );
        todo!()
    }

    async fn get_blockchain_config(
        &self,
        clock: &dyn Clock,
        force: bool,
    ) -> Result<ton_executor::BlockchainConfig> {
        todo!()
    }
}

fn decode_raw_transaction(boc: &str) -> Result<RawTransaction> {
    let bytes = base64::decode(boc)?;
    let cell = ton_types::deserialize_tree_of_cells(&mut bytes.as_slice())?;
    let hash = cell.repr_hash();
    let data = ton_block::Transaction::construct_from_cell(cell)?;
    Ok(RawTransaction { hash, data })
}