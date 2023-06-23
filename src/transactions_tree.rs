use std::sync::{Arc, Mutex};

use nt::core::transactions_tree::{StoredAccount, TransactionsTreeStream};
use nt::utils::TrustMe;
use ton_block::{Deserializable, Serializable};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::*;

use crate::models::*;
use crate::transport::*;
use crate::utils::*;

#[wasm_bindgen]
pub struct TransactionsTree {
    #[wasm_bindgen(skip)]
    pub clock: Arc<ClockWithOffset>,
    #[wasm_bindgen(skip)]
    pub inner: Arc<Mutex<TransactionsTreeStream>>,
}

#[wasm_bindgen]
impl TransactionsTree {
    #[wasm_bindgen(js_name = "new")]
    pub fn new(
        clock: ClockWithOffset,
        config: &str,
        message: &str,
        global_id: Option<i32>,
        transport: Transport,
    ) -> Result<TransactionsTree, JsValue> {
        let clock = Arc::new(clock);
        let transport = transport.handle.into();

        let message = ton_block::Message::construct_from_base64(message).handle_error()?;

        let global_id = global_id.unwrap_or(42);
        let config = ton_block::ConfigParams::construct_from_base64(config).handle_error()?;
        let config =
            ton_executor::BlockchainConfig::with_config(config, global_id).handle_error()?;

        let inner = Arc::new(Mutex::new(TransactionsTreeStream::new(
            message,
            config,
            transport,
            clock.clone_inner(),
        )));
        Ok(TransactionsTree { clock, inner })
    }

    #[wasm_bindgen(js_name = "setAccountState")]
    pub fn set_account_state(&mut self, address: &str, state: &str) -> Result<(), JsValue> {
        let account = ton_block::Account::construct_from_base64(state).unwrap();
        let stored_account = StoredAccount::new(account);
        let address = parse_address(address)?;
        let mut inner = self.inner.lock().trust_me();
        inner.set_account_state(address, stored_account);
        Ok(())
    }

    #[wasm_bindgen(js_name = "getAccountState")]
    pub fn get_account_state(&mut self, address: &str) -> Result<Option<String>, JsValue> {
        let address = parse_address(address)?;
        let inner = self.inner.lock().trust_me();
        let states = inner.get_account_states();
        Ok(states
            .get(&address)
            .map(|stored_account| stored_account.get_state()))
    }

    #[wasm_bindgen(js_name = "setBreakpoint")]
    pub fn set_breakpoint(&mut self, breakpoint: i32) -> Result<(), JsValue> {
        let mut inner = self.inner.lock().trust_me();
        inner.set_breakpoint(breakpoint);
        Ok(())
    }

    #[wasm_bindgen(js_name = "resumeBreakpoint")]
    pub fn resume_breakpoint(&mut self, breakpoint: i32) -> Result<(), JsValue> {
        let mut inner = self.inner.lock().trust_me();
        inner.resume_breakpoint(breakpoint);
        Ok(())
    }

    #[wasm_bindgen(js_name = "disableSignatureCheck")]
    pub fn disable_signature_check(&mut self) -> Result<(), JsValue> {
        let mut inner = self.inner.lock().trust_me();
        inner.disable_signature_check();
        Ok(())
    }

    #[wasm_bindgen(js_name = "unlimitedMessageBalance")]
    pub fn unlimited_message_balance(&mut self) -> Result<(), JsValue> {
        let mut inner = self.inner.lock().trust_me();
        inner.unlimited_message_balance();
        Ok(())
    }

    #[wasm_bindgen(js_name = "unlimitedAccountBalance")]
    pub fn unlimited_account_balance(&mut self) -> Result<(), JsValue> {
        let mut inner = self.inner.lock().trust_me();
        inner.unlimited_account_balance();
        Ok(())
    }

    #[wasm_bindgen(js_name = "next")]
    pub fn next(&self) -> Result<PromiseOptionTransaction, JsValue> {
        let inner = self.inner.clone();

        // NOTE: method must be called through the external mutex
        #[allow(clippy::await_holding_lock)]
        Ok(JsCast::unchecked_into(future_to_promise(async move {
            let mut inner = inner.lock().trust_me();

            let transaction = inner.next().await.handle_error()?;
            Ok(match transaction {
                Some(transaction) => nt::core::models::Transaction::try_from((
                    transaction.serialize().handle_error()?.repr_hash(),
                    transaction,
                ))
                .map(make_transaction)
                .handle_error()?
                .unchecked_into(),
                None => JsValue::undefined(),
            })
        })))
    }

    #[wasm_bindgen(js_name = "updateClockOffset")]
    pub fn update_clock_offset(&self, offset: f64) {
        self.clock.update_offset(offset);
    }
}
