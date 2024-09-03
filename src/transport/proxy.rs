use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result};
use gloo_utils::errors::JsError;
use nt::core::models::NetworkCapabilities;
use nt::transport::models::{PollContractState, RawContractState, RawTransaction};
use nt::transport::{Transport, TransportInfo};
use nt::utils::Clock;
use ton_block::{Deserializable, MsgAddressInt, Serializable};
use wasm_bindgen::prelude::*;

use crate::external::IProxyConnector;

#[wasm_bindgen]
pub struct ProxyConnection {
    #[wasm_bindgen(skip)]
    pub inner: Arc<IProxyConnector>,
}

#[wasm_bindgen]
impl ProxyConnection {
    #[wasm_bindgen(constructor)]
    pub fn new(proxy_connector: IProxyConnector) -> Self {
        Self {
            inner: Arc::new(proxy_connector),
        }
    }
}

pub struct ProxyTransport {
    connection: Arc<IProxyConnector>,
}

impl ProxyTransport {
    pub fn new(connection: Arc<IProxyConnector>) -> Self {
        Self { connection }
    }
}

#[async_trait::async_trait(?Send)]
impl Transport for ProxyTransport {
    fn info(&self) -> TransportInfo {
        if let Ok(info) = self.connection.info() {
            if let Ok(info) = gloo_utils::format::JsValueSerdeExt::into_serde(&info) {
                return info;
            }
        }

        TransportInfo {
            has_key_blocks: true,
            max_transactions_per_fetch: 50,
            reliable_behavior: nt::core::models::ReliableBehavior::IntensivePolling,
        }
    }

    async fn send_message(&self, message: &ton_block::Message) -> Result<()> {
        self.connection
            .send_message(&base64::encode(message.write_to_bytes()?))
            .await
            .map_err(map_js_err)
    }

    async fn get_contract_state(&self, address: &MsgAddressInt) -> Result<RawContractState> {
        let account = self
            .connection
            .get_contract_state(&address.to_string())
            .await
            .map_err(map_js_err)?
            .as_string()
            .context("Expected a string with base64 encoded account state")?;

        Ok(match ton_block::Account::construct_from_base64(&account)? {
            ton_block::Account::AccountNone => RawContractState::NotExists {
                timings: nt::abi::GenTimings::Unknown,
            },
            ton_block::Account::Account(account) => {
                let last_transaction_id = nt::abi::LastTransactionId::Inexact {
                    latest_lt: account.storage.last_trans_lt,
                };

                RawContractState::Exists(nt::transport::models::ExistingContract {
                    account,
                    timings: nt::abi::GenTimings::Unknown,
                    last_transaction_id,
                })
            }
        })
    }

    async fn poll_contract_state(
        &self,
        address: &MsgAddressInt,
        _last_trans_lt: u64,
    ) -> Result<PollContractState> {
        let state = self.get_contract_state(address).await?;
        Ok(state.into())
    }

    async fn get_accounts_by_code_hash(
        &self,
        code_hash: &ton_types::UInt256,
        limit: u8,
        continuation: &Option<MsgAddressInt>,
    ) -> Result<Vec<MsgAddressInt>> {
        let addresses = self
            .connection
            .get_accounts_by_code_hash(
                &code_hash.to_string(),
                limit,
                continuation.as_ref().map(|addr| addr.to_string()),
            )
            .await
            .map_err(map_js_err)?;

        anyhow::ensure!(
            js_sys::Array::is_array(&addresses),
            "Expected an array of account addresses"
        );
        let addresses: js_sys::Array = addresses.unchecked_into();

        addresses
            .iter()
            .map(|value| {
                value
                    .as_string()
                    .as_deref()
                    .context("Expected a raw account address")
                    .and_then(ton_block::MsgAddressInt::from_str)
            })
            .collect()
    }

    async fn get_transactions(
        &self,
        address: &MsgAddressInt,
        from_lt: u64,
        count: u8,
    ) -> Result<Vec<RawTransaction>> {
        let transactions = self
            .connection
            .get_transactions(&address.to_string(), &from_lt.to_string(), count)
            .await
            .map_err(map_js_err)?;

        anyhow::ensure!(
            js_sys::Array::is_array(&transactions),
            "Expected an array of strings with base64 encoded transactions"
        );
        let transactions: js_sys::Array = transactions.unchecked_into();

        transactions
            .iter()
            .map(|value| {
                value
                    .as_string()
                    .context("Expected a string with base64 encoded transaction")
                    .and_then(parse_raw_transaction)
            })
            .collect()
    }

    async fn get_transaction(&self, id: &ton_types::UInt256) -> Result<Option<RawTransaction>> {
        self.connection
            .get_transaction(&id.as_hex_string())
            .await
            .map_err(map_js_err)?
            .as_string()
            .map(parse_raw_transaction)
            .transpose()
    }

    async fn get_dst_transaction(
        &self,
        message_hash: &ton_types::UInt256,
    ) -> Result<Option<RawTransaction>> {
        self.connection
            .get_dst_transaction(&message_hash.as_hex_string())
            .await
            .map_err(map_js_err)?
            .as_string()
            .map(parse_raw_transaction)
            .transpose()
    }

    async fn get_latest_key_block(&self) -> Result<Vec<u8>> {
        let latest_key_block = self
            .connection
            .get_latest_key_block()
            .await
            .map_err(map_js_err)?
            .as_string()
            .context("Expected a string with base64 encoded key block")?;

        Ok(base64::decode(latest_key_block)?)
    }

    async fn get_capabilities(&self, clock: &dyn Clock) -> Result<NetworkCapabilities> {
        let capabilities = self
            .connection
            .get_capabilities(&clock.now_ms_u64().to_string())
            .await
            .map_err(map_js_err)?;

        gloo_utils::format::JsValueSerdeExt::into_serde(&capabilities).map_err(From::from)
    }

    async fn get_blockchain_config(
        &self,
        clock: &dyn Clock,
        _: bool,
    ) -> Result<ton_executor::BlockchainConfig> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct BlockchainConfig {
            global_id: i32,
            #[serde(with = "nt::utils::serde_ton_block")]
            boc: ton_block::ConfigParams,
        }

        let config = self
            .connection
            .get_blockchain_config(&clock.now_ms_u64().to_string())
            .await
            .map_err(map_js_err)?;

        let BlockchainConfig { global_id, boc } =
            gloo_utils::format::JsValueSerdeExt::into_serde(&config)?;

        ton_executor::BlockchainConfig::with_config(boc, global_id)
    }
}

fn parse_raw_transaction(tx: String) -> Result<RawTransaction> {
    let tx = ton_types::deserialize_tree_of_cells(&mut base64::decode(tx)?.as_slice())?;
    Ok(RawTransaction {
        hash: tx.repr_hash(),
        data: ton_block::Transaction::construct_from_cell(tx)?,
    })
}

fn map_js_err(error: JsValue) -> anyhow::Error {
    #[derive(Debug)]
    struct SomeJsError;

    impl std::fmt::Display for SomeJsError {
        #[inline]
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::fmt::Debug::fmt(self, f)
        }
    }

    impl std::error::Error for SomeJsError {}

    if let Ok(error) = error.dyn_into::<js_sys::Error>() {
        JsError::from(error).into()
    } else {
        SomeJsError.into()
    }
}
