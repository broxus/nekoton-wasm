use std::str::FromStr;
use std::sync::{Arc, Mutex};

use gloo_utils::format::JsValueSerdeExt;
use nt::utils::TrustMe;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::*;

use crate::models::*;
use crate::transport::*;
use crate::utils::*;

#[wasm_bindgen]
pub struct GenericContract {
    #[wasm_bindgen(skip)]
    pub address: String,
    #[wasm_bindgen(skip)]
    pub inner: Arc<GenericContractState>,
}

impl GenericContract {
    pub fn new(
        transport: TransportHandle,
        contract: nt::core::generic_contract::GenericContract,
    ) -> Self {
        Self {
            address: contract.address().to_string(),
            inner: Arc::new(GenericContractState {
                transport,
                contract: Mutex::new(contract),
            }),
        }
    }
}

#[wasm_bindgen]
impl GenericContract {
    #[wasm_bindgen(getter, js_name = "address")]
    pub fn address(&self) -> String {
        self.address.clone()
    }

    #[wasm_bindgen(js_name = "sendMessageLocally")]
    pub fn send_message_locally(
        &self,
        message: SignedMessage,
        params: OptionalExecutorParams,
    ) -> Result<PromiseTransaction, JsValue> {
        let inner = self.inner.clone();
        let message = parse_signed_message(message)?;
        let params = parse_executor_params(params)?;

        // NOTE: method must be called through the external mutex
        #[allow(clippy::await_holding_lock)]
        Ok(JsCast::unchecked_into(future_to_promise(async move {
            let mut contract = inner.contract.lock().trust_me();

            let transaction = contract
                .execute_transaction_locally(&message.message, params)
                .await
                .handle_error()?;
            Ok(make_transaction(transaction).unchecked_into())
        })))
    }

    #[wasm_bindgen(js_name = "sendMessage")]
    pub fn send_message(
        &self,
        message: SignedMessage,
    ) -> Result<PromisePendingTransaction, JsValue> {
        let inner = self.inner.clone();
        let message = parse_signed_message(message)?;

        // NOTE: method must be called through the external mutex
        #[allow(clippy::await_holding_lock)]
        Ok(JsCast::unchecked_into(future_to_promise(async move {
            let mut contract = inner.contract.lock().trust_me();

            let pending_transaction = contract
                .send(&message.message, message.expire_at)
                .await
                .handle_error()?;
            Ok(make_pending_transaction(pending_transaction).unchecked_into())
        })))
    }

    #[wasm_bindgen(js_name = "refresh")]
    pub fn refresh(&mut self) -> PromisePollingMethod {
        let inner = self.inner.clone();

        // NOTE: method must be called through the external mutex
        #[allow(clippy::await_holding_lock)]
        JsCast::unchecked_into(future_to_promise(async move {
            let mut contract = inner.contract.lock().trust_me();

            contract.refresh().await.handle_error()?;
            Ok(make_polling_method(contract.polling_method()).unchecked_into())
        }))
    }

    #[wasm_bindgen(js_name = "handleBlock")]
    pub fn handle_block(&mut self, block_id: String) -> PromisePollingMethod {
        let inner = self.inner.clone();

        // NOTE: method must be called through the external mutex
        #[allow(clippy::await_holding_lock)]
        JsCast::unchecked_into(future_to_promise(async move {
            let block = inner.transport.get_block(&block_id).await?;

            let mut contract = inner.contract.lock().trust_me();
            contract.handle_block(&block).await.handle_error()?;

            Ok(make_polling_method(contract.polling_method()).unchecked_into())
        }))
    }

    #[wasm_bindgen(js_name = "preloadTransactions")]
    pub fn preload_transactions(&mut self, lt: &str) -> Result<PromiseVoid, JsValue> {
        let from_lt = u64::from_str(lt).handle_error()?;

        let inner = self.inner.clone();

        // NOTE: method must be called through the external mutex
        #[allow(clippy::await_holding_lock)]
        Ok(JsCast::unchecked_into(future_to_promise(async move {
            let mut contract = inner.contract.lock().trust_me();

            contract
                .preload_transactions(from_lt)
                .await
                .handle_error()?;
            Ok(JsValue::undefined())
        })))
    }

    #[wasm_bindgen(getter, js_name = "pollingMethod")]
    pub fn polling_method(&self) -> PollingMethod {
        make_polling_method(self.inner.contract.lock().trust_me().polling_method())
    }
}

pub struct GenericContractState {
    transport: TransportHandle,
    contract: Mutex<nt::core::generic_contract::GenericContract>,
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = "GenericContractSubscriptionHandler")]
    pub type GenericContractSubscriptionHandlerImpl;

    #[wasm_bindgen(method, js_name = "onMessageSent")]
    pub fn on_message_sent(
        this: &GenericContractSubscriptionHandlerImpl,
        pending_transaction: PendingTransaction,
        transaction: Option<Transaction>,
    );

    #[wasm_bindgen(method, js_name = "onMessageExpired")]
    pub fn on_message_expired(
        this: &GenericContractSubscriptionHandlerImpl,
        pending_transaction: PendingTransaction,
    );

    #[wasm_bindgen(method, js_name = "onStateChanged")]
    pub fn on_state_changed(
        this: &GenericContractSubscriptionHandlerImpl,
        new_state: ContractState,
    );

    #[wasm_bindgen(method, js_name = "onTransactionsFound")]
    pub fn on_transactions_found(
        this: &GenericContractSubscriptionHandlerImpl,
        transactions: TransactionsList,
        batch_info: TransactionsBatchInfo,
    );
}

unsafe impl Send for GenericContractSubscriptionHandlerImpl {}
unsafe impl Sync for GenericContractSubscriptionHandlerImpl {}

pub struct GenericContractSubscriptionHandler {
    inner: GenericContractSubscriptionHandlerImpl,
}

impl From<GenericContractSubscriptionHandlerImpl> for GenericContractSubscriptionHandler {
    fn from(inner: GenericContractSubscriptionHandlerImpl) -> Self {
        Self { inner }
    }
}

impl nt::core::generic_contract::GenericContractSubscriptionHandler
    for GenericContractSubscriptionHandler
{
    fn on_message_sent(
        &self,
        pending_transaction: nt::core::models::PendingTransaction,
        transaction: Option<nt::core::models::Transaction>,
    ) {
        self.inner.on_message_sent(
            make_pending_transaction(pending_transaction),
            transaction.map(make_transaction),
        );
    }

    fn on_message_expired(&self, pending_transaction: nt::core::models::PendingTransaction) {
        self.inner
            .on_message_expired(make_pending_transaction(pending_transaction));
    }

    fn on_state_changed(&self, new_state: nt::core::models::ContractState) {
        self.inner.on_state_changed(make_contract_state(new_state));
    }

    fn on_transactions_found(
        &self,
        transactions: Vec<nt::core::models::Transaction>,
        batch_info: nt::core::models::TransactionsBatchInfo,
    ) {
        self.inner.on_transactions_found(
            transactions
                .into_iter()
                .map(make_transaction)
                .map(JsValue::from)
                .collect::<js_sys::Array>()
                .unchecked_into(),
            make_transactions_batch_info(batch_info),
        );
    }
}

#[wasm_bindgen(typescript_custom_section)]
const TRANSACTION_EXECUTION_OPTIONS: &str = r#"
export type ExecutorParams = {
    disableSignatureCheck?: bool,
    overrideBalance?: string | number,
};
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "ExecutorParams | undefined")]
    pub type OptionalExecutorParams;
}

fn parse_executor_params(
    params: OptionalExecutorParams,
) -> Result<nt::core::TransactionExecutionOptions, JsValue> {
    if params.is_null() || params.is_undefined() {
        Ok(Default::default())
    } else {
        <JsValue as JsValueSerdeExt>::into_serde::<nt::core::TransactionExecutionOptions>(&params)
            .handle_error()
    }
}
