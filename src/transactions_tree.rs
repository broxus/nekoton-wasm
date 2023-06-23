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
    pub inner: Arc<TransactionsTreeState>,
}

#[wasm_bindgen]
impl TransactionsTree {
    #[wasm_bindgen(js_name = "new")]
    pub fn new(
        clock: ClockWithOffset,
        message: &str,
        transport: Transport,
    ) -> Result<PromiseTransactionsTree, JsValue> {
        let clock = Arc::new(clock);
        let transport: Arc<dyn nt::transport::Transport> = transport.handle.into();
        let message = ton_block::Message::construct_from_base64(message).handle_error()?;

        Ok(JsCast::unchecked_into(future_to_promise(async move {
            let config = transport
                .as_ref()
                .get_blockchain_config(&*clock.clone_inner(), false)
                .await
                .handle_error()?;

            let stream = Mutex::new(TransactionsTreeStream::new(
                message,
                config,
                transport,
                clock.clone_inner(),
            ));
            Ok(JsValue::from(TransactionsTree {
                clock,
                inner: Arc::new(TransactionsTreeState { stream }),
            }))
        })))
    }

    #[wasm_bindgen(js_name = "setAccountState")]
    pub fn set_account_state(&mut self, address: &str, state: &str) -> Result<(), JsValue> {
        let account = ton_block::Account::construct_from_base64(state).unwrap();
        let stored_account = StoredAccount::new(account);
        let address = parse_address(address)?;
        let mut stream = self.inner.stream.lock().trust_me();
        stream.set_account_state(address, stored_account);
        Ok(())
    }

    #[wasm_bindgen(js_name = "getAccountState")]
    pub fn get_account_state(&mut self, address: &str) -> Result<Option<String>, JsValue> {
        let address = parse_address(address)?;
        let stream = self.inner.stream.lock().trust_me();
        let states = stream.get_account_states();
        Ok(states
            .get(&address)
            .map(|stored_account| stored_account.get_state()))
    }

    #[wasm_bindgen(js_name = "setBreakpoint")]
    pub fn set_breakpoint(&mut self, breakpoint: i32) -> Result<(), JsValue> {
        let mut stream = self.inner.stream.lock().trust_me();
        stream.set_breakpoint(breakpoint);
        Ok(())
    }

    #[wasm_bindgen(js_name = "resumeBreakpoint")]
    pub fn resume_breakpoint(&mut self, breakpoint: i32) -> Result<(), JsValue> {
        let mut stream = self.inner.stream.lock().trust_me();
        stream.resume_breakpoint(breakpoint);
        Ok(())
    }

    #[wasm_bindgen(js_name = "disableSignatureCheck")]
    pub fn disable_signature_check(&mut self) -> Result<(), JsValue> {
        let mut stream = self.inner.stream.lock().trust_me();
        stream.disable_signature_check();
        Ok(())
    }

    #[wasm_bindgen(js_name = "unlimitedMessageBalance")]
    pub fn unlimited_message_balance(&mut self) -> Result<(), JsValue> {
        let mut stream = self.inner.stream.lock().trust_me();
        stream.unlimited_message_balance();
        Ok(())
    }

    #[wasm_bindgen(js_name = "unlimitedAccountBalance")]
    pub fn unlimited_account_balance(&mut self) -> Result<(), JsValue> {
        let mut stream = self.inner.stream.lock().trust_me();
        stream.unlimited_account_balance();
        Ok(())
    }

    #[wasm_bindgen(js_name = "next")]
    pub fn next(&self) -> Result<PromiseOptionTransaction, JsValue> {
        let inner = self.inner.clone();

        // NOTE: method must be called through the external mutex
        #[allow(clippy::await_holding_lock)]
        Ok(JsCast::unchecked_into(future_to_promise(async move {
            let mut stream = inner.stream.lock().trust_me();

            let transaction = stream.next().await.handle_error()?;
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

pub struct TransactionsTreeState {
    pub stream: Mutex<TransactionsTreeStream>,
}
