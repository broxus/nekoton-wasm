use std::collections::HashMap;
use std::convert::TryFrom;

use nt::abi;
use nt::core::models;

use ton_block::{Deserializable, Serializable};
use ton_types::UInt256;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::tokens_object::*;
use crate::utils::*;
use crate::TransactionTree;

#[wasm_bindgen(typescript_custom_section)]
const MODELS: &str = r#"
export type NetworkCapabilities = {
    globalId: number,
    capabilities: string,
};

export type NetworkDescription = NetworkCapabilities & {
    signatureId: number | undefined,
};

export type BlockchainConfig = {
    globalId: number,
    boc: string,
}

export type TransactionId = {
    lt: string,
    hash: string,
};

export type GenTimings = {
    genLt: string,
    genUtime: number,
};

export type LastTransactionId = {
    isExact: boolean,
    lt: string,
    hash?: string,
};

export type ContractState = {
    balance: string,
    genTimings: GenTimings,
    lastTransactionId?: LastTransactionId,
    isDeployed: boolean,
    codeHash?: string,
};

export type AccountStatus = 'uninit' | 'frozen' | 'active' | 'nonexist';

export type Message = {
    hash: string,
    src?: string,
    dst?: string,
    value: string,
    bounce: boolean,
    bounced: boolean,
    body?: string,
    bodyHash?: string,
    boc: string,
};

export type PendingTransaction = {
    messageHash: string,
    src?: string,
    expireAt: number,
};

export type AccountsList = {
  accounts: string[];
  continuation: string | undefined;
};

export type TransactionsList = {
    transactions: Transaction[];
    continuation: TransactionId | undefined;
};

export type Transaction = {
    id: TransactionId,
    prevTransactionId?: TransactionId,
    createdAt: number,
    aborted: boolean,
    exitCode?: number,
    resultCode?: number,
    origStatus: AccountStatus,
    endStatus: AccountStatus,
    totalFees: string,
    inMessage: Message,
    outMessages: Message[],
    boc: string
};

export type TransactionsBatchType = 'old' | 'new';

export type TransactionsBatchInfo = {
    minLt: string,
    maxLt: string,
    batchType: TransactionsBatchType,
};

export type StateInit = {
    data: string | undefined;
    code: string | undefined;
};

export type ExpectedAddress = {
    stateInit: string;
    address: string;
    hash: string;
};

export type DecodedInput = {
    method: string,
    input: TokensObject,
};

export type DecodedEvent = {
    event: string,
    data: TokensObject,
};

export type DecodedOutput = {
    method: string,
    output: TokensObject,
};

export type DecodedTransaction = {
    method: string,
    input: TokensObject,
    output: TokensObject,
};

export type DecodedTransactionEvents = Array<DecodedEvent>;

export type TransactionExecutorOutput =
    | { exitCode: number }
    | { account: string, transaction: Transaction };

export type ExecutionOutput = {
    output?: TokensObject,
    code: number,
};

export type ReliableBehaviorType = 'BlockWalking' | 'IntensivePolling';

export type TransportInfo = {
    maxTransactionsPerFetch: number;
    reliableBehavior: ReliableBehaviorType;
    hasKeyBlocks: boolean;
};

export type MethodName = undefined | string | string[];

export type AbiToken =
    | null
    | boolean
    | string
    | number
    | { [K in string]: AbiToken }
    | AbiToken[]
    | (readonly [AbiToken, AbiToken])[];

type TokensObject = { [K in string]: AbiToken };

export type AbiParam = {
  name: string;
  type: string;
  components?: AbiParam[];
};

export type LatestBlock = {
    id: string,
    endLt: string,
    genUtime: number,
};

export type SignedMessage = {
    hash: string,
    expireAt: number,
    boc: string,
};

export type PollingMethod = 'manual' | 'reliable';

export type Ed25519KeyPair = {
    publicKey: string,
    secretKey: string,
};

export type ExtendedSignature = {
    signature: string,
    signatureHex: string,
    signatureParts: {
        high: string,
        low: string,
    }
};

export type FullContractState = {
    balance: string;
    genTimings: GenTimings;
    lastTransactionId: LastTransactionId;
    isDeployed: boolean;
    codeHash?: string;
    boc: string;
};

export type RawContractState = {
    account: string;
    lastTransactionId: LastTransactionId;
    timings: GenTimings;
    type: string;
};

export type TransactionTree = {
    root: Transaction,
    children: TransactionTree[]
};

export type StorageFeeInfo = {
    storageFee: string;
    storageFeeDebt?: string;
    accountStatus: AccountStatus;
    freezeDueLimit: string;
    deleteDueLimit: string;
};

export type VmGetterOutput = {
    output?: TokensObject,
    exitCode: number,
    isOk: boolean,
};

export type JettonWalletData = {
  balance: string;
  owner: string;
  root: string;
  code: string;
};
"#;

// TODO: add zerostate hash
pub fn make_network_description(capabilities: models::NetworkCapabilities) -> JsValue {
    ObjectBuilder::new()
        .set("globalId", capabilities.global_id)
        .set("capabilities", format!("0x{:x}", capabilities.raw))
        .set("signatureId", capabilities.signature_id())
        .build()
}

pub fn make_transaction_id(data: nt::abi::TransactionId) -> TransactionId {
    ObjectBuilder::new()
        .set("lt", data.lt.to_string())
        .set("hash", hex::encode(data.hash.as_slice()))
        .build()
        .unchecked_into()
}

pub fn make_gen_timings(data: nt::abi::GenTimings) -> GenTimings {
    let (gen_lt, gen_utime) = match data {
        nt::abi::GenTimings::Unknown => (0, 0),
        nt::abi::GenTimings::Known { gen_lt, gen_utime } => (gen_lt, gen_utime),
    };

    ObjectBuilder::new()
        .set("genLt", gen_lt.to_string())
        .set("genUtime", gen_utime)
        .build()
        .unchecked_into()
}

pub fn make_last_transaction_id(data: nt::abi::LastTransactionId) -> LastTransactionId {
    let (lt, hash) = match data {
        nt::abi::LastTransactionId::Exact(id) => (id.lt, Some(id.hash.to_hex_string())),
        nt::abi::LastTransactionId::Inexact { latest_lt } => (latest_lt, None),
    };

    ObjectBuilder::new()
        .set("isExact", data.is_exact())
        .set("lt", lt.to_string())
        .set("hash", hash)
        .build()
        .unchecked_into()
}

pub fn make_contract_state(data: models::ContractState) -> ContractState {
    ObjectBuilder::new()
        .set("balance", data.balance.to_string())
        .set("genTimings", make_gen_timings(data.gen_timings))
        .set(
            "lastTransactionId",
            data.last_transaction_id.map(make_last_transaction_id),
        )
        .set("isDeployed", data.is_deployed)
        .set(
            "codeHash",
            data.code_hash
                .as_ref()
                .map(ton_types::UInt256::to_hex_string),
        )
        .build()
        .unchecked_into()
}

fn make_account_status(data: nt::core::models::AccountStatus) -> AccountStatus {
    JsValue::from(match data {
        models::AccountStatus::Uninit => "uninit",
        models::AccountStatus::Frozen => "frozen",
        models::AccountStatus::Active => "active",
        models::AccountStatus::Nonexist => "nonexist",
    })
    .unchecked_into()
}

pub fn make_message(data: &models::Message) -> JsValue {
    let (body, body_hash) = if let Some(body) = &data.body {
        (
            Some(make_boc(&body.data).expect("Shouldn't fail")),
            Some(body.hash.to_hex_string()),
        )
    } else {
        (None, None)
    };

    ObjectBuilder::new()
        .set("hash", data.hash.to_hex_string())
        .set("src", data.src.as_ref().map(ToString::to_string))
        .set("dst", data.dst.as_ref().map(ToString::to_string))
        .set("value", data.value.to_string())
        .set("bounce", data.bounce)
        .set("bounced", data.bounced)
        .set("body", body)
        .set("bodyHash", body_hash)
        .set("boc", make_boc(&data.raw).expect("Shouldn't fail"))
        .build()
        .unchecked_into()
}

pub fn make_pending_transaction(data: models::PendingTransaction) -> PendingTransaction {
    ObjectBuilder::new()
        .set("messageHash", data.message_hash.to_hex_string())
        .set("src", data.src.as_ref().map(ToString::to_string))
        .set("expireAt", data.expire_at)
        .build()
        .unchecked_into()
}

pub fn make_accounts_list(
    accounts: Vec<ton_block::MsgAddressInt>,
    without_continuation: bool,
) -> AccountsList {
    let continuation = if without_continuation {
        None
    } else {
        accounts.last().map(ToString::to_string)
    };

    ObjectBuilder::new()
        .set("continuation", continuation)
        .set(
            "accounts",
            accounts
                .into_iter()
                .map(|account| JsValue::from(account.to_string()))
                .collect::<js_sys::Array>(),
        )
        .build()
        .unchecked_into()
}

pub fn make_transactions_list(
    raw_transactions: Vec<nt::transport::models::RawTransaction>,
) -> TransactionsList {
    let batch_info = match (raw_transactions.first(), raw_transactions.last()) {
        (Some(first), Some(last)) => Some(nt::core::models::TransactionsBatchInfo {
            min_lt: last.data.lt, // transactions in response are in descending order
            max_lt: first.data.lt,
            batch_type: nt::core::models::TransactionsBatchType::New,
        }),
        _ => None,
    };

    let continuation = raw_transactions.last().and_then(|transaction| {
        (transaction.data.prev_trans_lt != 0).then_some(nt::abi::TransactionId {
            lt: transaction.data.prev_trans_lt,
            hash: transaction.data.prev_trans_hash,
        })
    });
    ObjectBuilder::new()
        .set(
            "transactions",
            raw_transactions
                .into_iter()
                .filter_map(|transaction| {
                    nt::core::models::Transaction::try_from((transaction.hash, transaction.data))
                        .ok()
                })
                .map(make_transaction)
                .collect::<js_sys::Array>(),
        )
        .set("continuation", continuation.map(make_transaction_id))
        .set("info", batch_info.map(make_transactions_batch_info))
        .build()
        .unchecked_into()
}

pub fn make_transaction(data: models::Transaction) -> Transaction {
    make_transaction_ext(data, None)
}

pub fn make_transaction_ext(
    data: models::Transaction,
    mut message_map: Option<&mut HashMap<UInt256, JsValue>>,
) -> Transaction {
    let in_msg = 'msg: {
        if let Some(map) = &mut message_map {
            if let Some(msg) = map.remove(&data.in_msg.hash) {
                break 'msg msg;
            }
        }
        make_message(&data.in_msg)
    };

    let out_msgs = data
        .out_msgs
        .into_iter()
        .map(|msg| {
            let value = make_message(&msg);
            if let (true, Some(map)) = (msg.dst.is_some(), &mut message_map) {
                map.insert(msg.hash, value.clone());
            }
            value
        })
        .collect::<js_sys::Array>();

    ObjectBuilder::new()
        .set("id", make_transaction_id(data.id))
        .set(
            "prevTransactionId",
            data.prev_trans_id.map(make_transaction_id),
        )
        .set("createdAt", data.created_at)
        .set("aborted", data.aborted)
        .set("exitCode", data.exit_code)
        .set("resultCode", data.result_code)
        .set("origStatus", make_account_status(data.orig_status))
        .set("endStatus", make_account_status(data.end_status))
        .set("totalFees", data.total_fees.to_string())
        .set("inMessage", in_msg)
        .set("outMessages", out_msgs)
        .set("boc", make_boc(&data.raw).expect("Shouldn't fail"))
        .build()
        .unchecked_into()
}

pub fn make_transaction_tree(data: TransactionTree) -> JsTransactionTree {
    make_node(data, &mut HashMap::new())
}

fn make_node(
    data: TransactionTree,
    message_map: &mut HashMap<UInt256, JsValue>,
) -> JsTransactionTree {
    let mut children: Vec<JsValue> = Vec::new();
    for c in data.children {
        let child = make_node(c, message_map);
        children.push(child.obj);
    }

    ObjectBuilder::new()
        .set("root", make_transaction_ext(data.root, Some(message_map)))
        .set("children", js_sys::Array::from_iter(children.iter()))
        .build()
        .unchecked_into()
}

pub fn make_transactions_batch_info(data: models::TransactionsBatchInfo) -> TransactionsBatchInfo {
    ObjectBuilder::new()
        .set("minLt", data.min_lt.to_string())
        .set("maxLt", data.max_lt.to_string())
        .set(
            "batchType",
            match data.batch_type {
                models::TransactionsBatchType::Old => "old",
                models::TransactionsBatchType::New => "new",
            },
        )
        .build()
        .unchecked_into()
}

pub fn make_execution_output(data: nt::abi::ExecutionOutput) -> Result<ExecutionOutput, JsValue> {
    Ok(ObjectBuilder::new()
        .set("output", data.tokens.map(make_tokens_object).transpose()?)
        .set("code", data.result_code)
        .build()
        .unchecked_into())
}

pub fn parse_method_name(value: MethodName) -> Result<nt::abi::MethodName, JsValue> {
    let value: JsValue = value.unchecked_into();
    if value.is_null() || value.is_undefined() {
        Ok(nt::abi::MethodName::Guess)
    } else if let Some(value) = value.as_string() {
        Ok(nt::abi::MethodName::Known(value))
    } else if js_sys::Array::is_array(&value) {
        let value: js_sys::Array = value.unchecked_into();
        Ok(nt::abi::MethodName::GuessInRange(
            value
                .iter()
                .map(|value| match value.as_string() {
                    Some(value) => Ok(value),
                    None => Err("Expected string or array"),
                })
                .collect::<Result<Vec<_>, &'static str>>()
                .handle_error()?,
        ))
    } else {
        Err("Expected string or array").handle_error()
    }
}

pub fn make_latest_block(latest_block: nt::transport::gql::LatestBlock) -> JsValue {
    ObjectBuilder::new()
        .set("id", latest_block.id)
        .set("endLt", latest_block.end_lt.to_string())
        .set("genUtime", latest_block.gen_utime)
        .build()
}

#[wasm_bindgen]
pub struct UnsignedMessage {
    #[wasm_bindgen(skip)]
    pub inner: Box<dyn nt::crypto::UnsignedMessage>,
}

#[wasm_bindgen]
impl UnsignedMessage {
    #[wasm_bindgen(js_name = "refreshTimeout")]
    pub fn refresh_timeout(&mut self, clock: &ClockWithOffset) {
        self.inner.refresh_timeout(clock.inner.as_ref());
    }

    #[wasm_bindgen(js_name = "expireAt")]
    pub fn expire_at(&self) -> u32 {
        self.inner.expire_at()
    }

    #[wasm_bindgen(getter)]
    pub fn hash(&self) -> String {
        hex::encode(nt::crypto::UnsignedMessage::hash(self.inner.as_ref()))
    }

    #[wasm_bindgen]
    pub fn sign(&self, signature: &str) -> Result<SignedMessage, JsValue> {
        let signature = parse_signature(signature)?.to_bytes();
        self.inner
            .sign(&signature)
            .handle_error()
            .and_then(make_signed_message)
    }

    #[wasm_bindgen(js_name = "signFake")]
    pub fn sign_fake(&self) -> Result<SignedMessage, JsValue> {
        self.inner
            .sign(&[0; 64])
            .handle_error()
            .and_then(make_signed_message)
    }
}

pub fn make_signed_message(data: nt::crypto::SignedMessage) -> Result<SignedMessage, JsValue> {
    let (boc, hash) = {
        let cell = data
            .message
            .write_to_new_cell()
            .and_then(ton_types::BuilderData::into_cell)
            .handle_error()?;
        (make_boc(&cell)?, cell.repr_hash())
    };

    Ok(ObjectBuilder::new()
        .set("hash", hash.to_hex_string())
        .set("expireAt", data.expire_at)
        .set("boc", boc)
        .build()
        .unchecked_into())
}

pub fn parse_signed_message(data: SignedMessage) -> Result<nt::crypto::SignedMessage, JsValue> {
    if !data.is_object() {
        return Err(TokensJsonError::ObjectExpected).handle_error();
    }
    let message = match js_sys::Reflect::get(&data, &JsValue::from_str("boc"))
        .map_err(|_| TokensJsonError::ParameterNotFound("boc".to_owned()))
        .handle_error()?
        .as_string()
    {
        Some(boc) => ton_block::Message::construct_from_cell(parse_cell(&boc)?).handle_error()?,
        None => return Err(TokensJsonError::StringExpected).handle_error(),
    };

    let expire_at = match js_sys::Reflect::get(&data, &JsValue::from_str("expireAt"))
        .map_err(|_| TokensJsonError::ParameterNotFound("expireAt".to_owned()))
        .handle_error()?
        .as_f64()
    {
        Some(expire_at) => expire_at as u32,
        None => return Err(TokensJsonError::NumberExpected).handle_error(),
    };

    Ok(nt::crypto::SignedMessage { message, expire_at })
}

pub fn make_polling_method(s: models::PollingMethod) -> PollingMethod {
    JsValue::from(match s {
        models::PollingMethod::Manual => "manual",
        models::PollingMethod::Reliable => "reliable",
    })
    .unchecked_into()
}

pub fn make_ed25519_key_pair(data: ed25519_dalek::Keypair) -> Ed25519KeyPair {
    ObjectBuilder::new()
        .set("publicKey", hex::encode(data.public.as_bytes()))
        .set("secretKey", hex::encode(data.secret.as_bytes()))
        .build()
        .unchecked_into()
}

pub fn make_extended_signature(signature: [u8; 64]) -> ExtendedSignature {
    ObjectBuilder::new()
        .set("signature", base64::encode(signature))
        .set("signatureHex", hex::encode(signature))
        .set(
            "signatureParts",
            ObjectBuilder::new()
                .set("high", format!("0x{}", hex::encode(&signature[..32])))
                .set("low", format!("0x{}", hex::encode(&signature[32..])))
                .build(),
        )
        .build()
        .unchecked_into()
}

pub fn make_full_contract_state(
    contract_state: nt::transport::models::RawContractState,
) -> Result<JsValue, JsValue> {
    match contract_state {
        nt::transport::models::RawContractState::Exists(state) => {
            let code_hash = match &state.account.storage.state {
                ton_block::AccountState::AccountActive {
                    state_init:
                        ton_block::StateInit {
                            code: Some(code), ..
                        },
                } => Some(code.repr_hash().to_hex_string()),
                _ => None,
            };

            Ok(ObjectBuilder::new()
                .set(
                    "balance",
                    state.account.storage.balance.grams.as_u128().to_string(),
                )
                .set("genTimings", make_gen_timings(state.timings))
                .set(
                    "lastTransactionId",
                    make_last_transaction_id(state.last_transaction_id),
                )
                .set(
                    "isDeployed",
                    matches!(
                        &state.account.storage.state,
                        ton_block::AccountState::AccountActive { .. }
                    ),
                )
                .set("codeHash", code_hash)
                .set("boc", serialize_into_boc(&state.account)?)
                .build()
                .unchecked_into())
        }
        nt::transport::models::RawContractState::NotExists { .. } => Ok(JsValue::undefined()),
    }
}

pub fn make_storage_fee_info(
    storage_fee: &ton_block::Grams,
    storage_fee_debt: Option<&ton_block::Grams>,
    account_status: models::AccountStatus,
    freeze_due_limit: u64,
    delete_due_limit: u64,
) -> StorageFeeInfo {
    ObjectBuilder::new()
        .set("storageFee", storage_fee.to_string())
        .set(
            "storageFeeDebt",
            storage_fee_debt.map(|value| value.to_string()),
        )
        .set("accountStatus", make_account_status(account_status))
        .set("freezeDueLimit", freeze_due_limit.to_string())
        .set("deleteDueLimit", delete_due_limit.to_string())
        .build()
        .unchecked_into()
}

pub fn make_boc_with_hash(cell: ton_types::Cell) -> Result<BocWithHash, JsValue> {
    Ok(ObjectBuilder::new()
        .set("hash", cell.repr_hash().to_hex_string())
        .set("boc", make_boc(&cell)?)
        .build()
        .unchecked_into())
}

pub fn serialize_into_boc_with_hash(data: &dyn Serializable) -> Result<BocWithHash, JsValue> {
    let cell = data.serialize().handle_error()?;
    make_boc_with_hash(cell)
}

pub fn make_vm_getter_output(
    params: &[ton_abi::Param],
    data: abi::VmGetterOutput,
) -> Result<VmGetterOutput, JsValue> {
    let mut builder = ObjectBuilder::new()
        .set("exitCode", data.exit_code)
        .set("isOk", data.is_ok);

    if data.is_ok {
        if data.stack.len() != params.len() {
            return Err(TokensJsonError::ParameterCountMismatch).handle_error();
        }

        let tokens = data
            .stack
            .iter()
            .zip(params)
            .map(|(value, param)| {
                let value = map_stack_item(param, value)?;
                Ok(ton_abi::Token {
                    name: param.name.clone(),
                    value,
                })
            })
            .collect::<Result<Vec<_>, JsValue>>()?;

        builder = builder.set("output", make_tokens_object(tokens)?);
    }

    Ok(builder.build().unchecked_into())
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "TransactionId")]
    pub type TransactionId;

    #[wasm_bindgen(typescript_type = "TransportInfo")]
    pub type TransportInfo;

    #[wasm_bindgen(typescript_type = "GenTimings")]
    pub type GenTimings;

    #[wasm_bindgen(typescript_type = "LastTransactionId")]
    pub type LastTransactionId;

    #[wasm_bindgen(typescript_type = "ContractState")]
    pub type ContractState;

    #[wasm_bindgen(typescript_type = "RawContractState")]
    pub type RawContractState;

    #[wasm_bindgen(typescript_type = "StorageFeeInfo")]
    pub type StorageFeeInfo;

    #[wasm_bindgen(typescript_type = "AccountStatus")]
    pub type AccountStatus;

    #[wasm_bindgen(typescript_type = "Message")]
    pub type Message;

    #[wasm_bindgen(typescript_type = "PendingTransaction")]
    pub type PendingTransaction;

    #[wasm_bindgen(typescript_type = "Promise<PendingTransaction>")]
    pub type PromisePendingTransaction;

    #[wasm_bindgen(typescript_type = "Transaction")]
    pub type Transaction;

    #[wasm_bindgen(typescript_type = "TransactionsList")]
    pub type TransactionsList;

    #[wasm_bindgen(typescript_type = "Promise<TransactionsList>")]
    pub type PromiseTransactionsList;

    #[wasm_bindgen(typescript_type = "TransactionsBatchType")]
    pub type TransactionsBatchType;

    #[wasm_bindgen(typescript_type = "TransactionsBatchInfo")]
    pub type TransactionsBatchInfo;

    #[wasm_bindgen(typescript_type = "Promise<Transaction>")]
    pub type PromiseTransaction;

    #[wasm_bindgen(typescript_type = "Promise<Transaction | undefined>")]
    pub type PromiseOptionTransaction;

    #[wasm_bindgen(typescript_type = "AccountsList")]
    pub type AccountsList;

    #[wasm_bindgen(typescript_type = "Promise<AccountsList>")]
    pub type PromiseAccountsList;

    #[wasm_bindgen(typescript_type = "PollingMethod")]
    pub type PollingMethod;

    #[wasm_bindgen(typescript_type = "Promise<PollingMethod>")]
    pub type PromisePollingMethod;

    #[wasm_bindgen(typescript_type = "StateInit")]
    pub type StateInit;

    #[wasm_bindgen(typescript_type = "ExpectedAddress")]
    pub type ExpectedAddress;

    #[wasm_bindgen(typescript_type = "{ hash: string, boc: string, }")]
    pub type BocWithHash;

    #[wasm_bindgen(typescript_type = "{ publicKey?: string, data: TokensObject }")]
    pub type InitData;

    #[wasm_bindgen(typescript_type = "DecodedInput")]
    pub type DecodedInput;

    #[wasm_bindgen(typescript_type = "DecodedEvent")]
    pub type DecodedEvent;

    #[wasm_bindgen(typescript_type = "DecodedOutput")]
    pub type DecodedOutput;

    #[wasm_bindgen(typescript_type = "DecodedTransaction")]
    pub type DecodedTransaction;

    #[wasm_bindgen(typescript_type = "DecodedTransactionEvents")]
    pub type DecodedTransactionEvents;

    #[wasm_bindgen(typescript_type = "TransactionExecutorOutput")]
    pub type TransactionExecutorOutput;

    #[wasm_bindgen(typescript_type = "ExecutionOutput")]
    pub type ExecutionOutput;

    #[wasm_bindgen(typescript_type = "MethodName")]
    pub type MethodName;

    #[wasm_bindgen(typescript_type = "TokensObject")]
    pub type TokensObject;

    #[wasm_bindgen(typescript_type = "Array<AbiParam>")]
    pub type ParamsList;

    #[wasm_bindgen(typescript_type = "Promise<LatestBlock>")]
    pub type PromiseLatestBlock;

    #[wasm_bindgen(typescript_type = "SignedMessage")]
    pub type SignedMessage;

    #[wasm_bindgen(typescript_type = "FullContractState | undefined")]
    pub type OptionFullContractState;

    #[wasm_bindgen(typescript_type = "Promise<FullContractState | undefined>")]
    pub type PromiseOptionFullContractState;

    #[wasm_bindgen(typescript_type = "Promise<GenericContract>")]
    pub type PromiseGenericContract;

    #[wasm_bindgen(typescript_type = "Promise<NetworkDescription>")]
    pub type PromiseNetworkDescription;

    #[wasm_bindgen(typescript_type = "Promise<number | undefined>")]
    pub type PromiseOptionSignatureId;

    #[wasm_bindgen(typescript_type = "Ed25519KeyPair")]
    pub type Ed25519KeyPair;

    #[wasm_bindgen(typescript_type = "ExtendedSignature")]
    pub type ExtendedSignature;

    #[wasm_bindgen(typescript_type = "TransactionTree")]
    pub type JsTransactionTree;

    #[wasm_bindgen(typescript_type = "VmGetterOutput")]
    pub type VmGetterOutput;

    #[wasm_bindgen(typescript_type = "JettonWalletData")]
    pub type JettonWalletData;

    #[wasm_bindgen(typescript_type = "Promise<JettonWalletData>")]
    pub type PromiseJettonWalletData;
}
