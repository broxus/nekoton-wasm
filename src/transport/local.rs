use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use nt::core::models::{NetworkCapabilities, ContractState};
use nt::transport::{Transport, TransportInfo};
use nt::transport::models::{RawContractState, RawTransaction};
use nt::utils::Clock;
use ton_block::{Block, MsgAddressInt, Serializable};
use wasm_bindgen::prelude::*;
use serde_json;

use crate::models::{OptionContractState};
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
    connection: Arc<ILocalConnection>
}

impl LocalTransport{
    pub fn new(connection: Arc<ILocalConnection>) -> Self {
        Self {
            connection
        }
    }
}


#[async_trait::async_trait]
impl Transport for LocalTransport {
    fn info(&self) -> TransportInfo {
        todo!()
    }

    async fn send_message(&self, message: &ton_block::Message) -> Result<()> {
        Ok(self.connection.send_message(&base64::encode(message.write_to_bytes().unwrap())))
    }

    async fn get_contract_state(&self, address: &MsgAddressInt) -> Result<RawContractState> {
        let str_state = self.connection.get_contract_state(&address.to_string());
        match str_state {
            Some(state) => {
                Ok(serde_json::from_str::<RawContractState>(&state).unwrap())
            },
            None => Ok(RawContractState::NotExists)
        }
    }

    async fn get_accounts_by_code_hash(
        &self,
        code_hash: &ton_types::UInt256,
        limit: u8,
        continuation: &Option<MsgAddressInt>,
    ) -> Result<Vec<MsgAddressInt>> {
        let addr = continuation.as_ref().map(|addr| addr.to_string());
        let accs_list: StringArray = self.connection.get_accounts_by_code_hash(&code_hash.to_string(), limit, addr);
        let arr: js_sys::Array = accs_list.unchecked_into();
        Ok(arr.iter().map(|addr| MsgAddressInt::from_str(&addr.as_string().unwrap()).unwrap()).collect())
    }

    async fn get_transactions(
        &self,
        address: &MsgAddressInt,
        from_lt: u64,
        count: u8,
    ) -> Result<Vec<RawTransaction>> {
        todo!()
    }

    async fn get_transaction(&self, id: &ton_types::UInt256) -> Result<Option<RawTransaction>> {
        todo!()
    }

    async fn get_dst_transaction(
        &self,
        message_hash: &ton_types::UInt256,
    ) -> Result<Option<RawTransaction>> {
        todo!()
    }

    async fn get_latest_key_block(&self) -> anyhow::Result<Block> {
        todo!()
    }

    async fn get_capabilities(&self, clock: &dyn Clock) -> anyhow::Result<NetworkCapabilities> { todo!() }

    async fn get_blockchain_config(
        &self,
        clock: &dyn Clock,
        force: bool,
    ) -> Result<ton_executor::BlockchainConfig> {
        todo!()
    }
}




