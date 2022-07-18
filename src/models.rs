use std::convert::TryFrom;
use std::str::FromStr;

use nt::core::models;
use serde::Deserialize;
use ton_block::{Deserializable, Serializable};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::tokens_object::*;
use crate::utils::*;

#[wasm_bindgen(typescript_custom_section)]
const TRANSACTION_ID: &str = r#"
export type TransactionId = {
    lt: string,
    hash: string,
};
"#;

pub fn make_transaction_id(data: nt::abi::TransactionId) -> TransactionId {
    ObjectBuilder::new()
        .set("lt", data.lt.to_string())
        .set("hash", hex::encode(data.hash.as_slice()))
        .build()
        .unchecked_into()
}

#[wasm_bindgen(typescript_custom_section)]
const GEN_TIMINGS: &str = r#"
export type GenTimings = {
    genLt: string,
    genUtime: number,
};
"#;

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

#[wasm_bindgen(typescript_custom_section)]
const LAST_TRANSACTION_ID: &str = r#"
export type LastTransactionId = {
    isExact: boolean,
    lt: string,
    hash?: string,
};
"#;

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

#[wasm_bindgen(typescript_custom_section)]
const CONTRACT_STATE: &str = r#"
export type ContractState = {
    balance: string,
    genTimings: GenTimings,
    lastTransactionId?: LastTransactionId,
    isDeployed: boolean,
    codeHash?: string,
};
"#;

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

#[wasm_bindgen(typescript_custom_section)]
const ACCOUNT_STATUS: &str = r#"
export type AccountStatus = 'uninit' | 'frozen' | 'active' | 'nonexist';
"#;

fn make_account_status(data: nt::core::models::AccountStatus) -> AccountStatus {
    JsValue::from(match data {
        models::AccountStatus::Uninit => "uninit",
        models::AccountStatus::Frozen => "frozen",
        models::AccountStatus::Active => "active",
        models::AccountStatus::Nonexist => "nonexist",
    })
    .unchecked_into()
}

#[wasm_bindgen(typescript_custom_section)]
const MESSAGE: &str = r#"
export type Message = {
    hash: string,
    src?: string,
    dst?: string,
    value: string,
    bounce: boolean,
    bounced: boolean,
    body?: string,
    bodyHash?: string,
};
"#;

pub fn make_message(data: models::Message) -> Message {
    let (body, body_hash) = if let Some(body) = data.body {
        let data = ton_types::serialize_toc(&body.data).expect("Shouldn't fail");
        (Some(base64::encode(data)), Some(body.hash.to_hex_string()))
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
        .build()
        .unchecked_into()
}

#[wasm_bindgen(typescript_custom_section)]
const PENDING_TRANSACTION: &str = r#"
export type PendingTransaction = {
    messageHash: string,
    src?: string,
    expireAt: number,
};
"#;

pub fn make_pending_transaction(data: models::PendingTransaction) -> PendingTransaction {
    ObjectBuilder::new()
        .set("messageHash", data.message_hash.to_hex_string())
        .set("src", data.src.as_ref().map(ToString::to_string))
        .set("expireAt", data.expire_at)
        .build()
        .unchecked_into()
}

#[wasm_bindgen(typescript_custom_section)]
const ACCOUNTS_LIST: &'static str = r#"
export type AccountsList = {
  accounts: string[];
  continuation: string | undefined;
}
"#;

pub fn make_accounts_list(accounts: Vec<ton_block::MsgAddressInt>) -> AccountsList {
    ObjectBuilder::new()
        .set("continuation", accounts.last().map(ToString::to_string))
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

#[wasm_bindgen(typescript_custom_section)]
const TRANSACTIONS_LIST: &'static str = r#"
export type TransactionsList = {
    transactions: Transaction[];
    continuation: TransactionId | undefined;
};
"#;

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
        (transaction.data.prev_trans_lt != 0).then(|| nt::abi::TransactionId {
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

#[wasm_bindgen(typescript_custom_section)]
const TRANSACTION: &str = r#"
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
};
"#;

pub fn make_transaction(data: models::Transaction) -> Transaction {
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
        .set("inMessage", make_message(data.in_msg))
        .set(
            "outMessages",
            data.out_msgs
                .into_iter()
                .map(make_message)
                .map(JsValue::from)
                .collect::<js_sys::Array>(),
        )
        .build()
        .unchecked_into()
}

#[wasm_bindgen(typescript_custom_section)]
const TRANSACTIONS_BATCH_INFO: &str = r#"
export type TransactionsBatchType = 'old' | 'new';

export type TransactionsBatchInfo = {
    minLt: string,
    maxLt: string,
    batchType: TransactionsBatchType,
};
"#;

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

#[wasm_bindgen(typescript_custom_section)]
const STATE_INIT: &str = r#"
export type StateInit = {
    data: string | undefined;
    code: string | undefined;
};
"#;

#[wasm_bindgen(typescript_custom_section)]
const EXPECTED_ADDRESS: &str = r#"
export type ExpectedAddress = {
    stateInit: string;
    address: string;
};
"#;

#[wasm_bindgen(typescript_custom_section)]
const DECODED_INPUT: &str = r#"
export type DecodedInput = {
    method: string,
    input: TokensObject,
};
"#;

#[wasm_bindgen(typescript_custom_section)]
const DECODED_EVENT: &str = r#"
export type DecodedEvent = {
    event: string,
    data: TokensObject,
};
"#;

#[wasm_bindgen(typescript_custom_section)]
const DECODED_OUTPUT: &str = r#"
export type DecodedOutput = {
    method: string,
    output: TokensObject,
};
"#;

#[wasm_bindgen(typescript_custom_section)]
const DECODED_TRANSACTION: &str = r#"
export type DecodedTransaction = {
    method: string,
    input: TokensObject,
    output: TokensObject,
};
"#;

#[wasm_bindgen(typescript_custom_section)]
const DECODED_TRANSACTION_EVENTS: &str = r#"
export type DecodedTransactionEvents = Array<DecodedEvent>;
"#;

#[wasm_bindgen(typescript_custom_section)]
const EXECUTION_OUTPUT: &str = r#"
export type ExecutionOutput = {
    output?: TokensObject,
    code: number,
};
"#;

pub fn make_execution_output(data: nt::abi::ExecutionOutput) -> Result<ExecutionOutput, JsValue> {
    Ok(ObjectBuilder::new()
        .set("output", data.tokens.map(make_tokens_object).transpose()?)
        .set("code", data.result_code)
        .build()
        .unchecked_into())
}

#[wasm_bindgen(typescript_custom_section)]
const METHOD_NAME: &str = r#"
export type MethodName = undefined | string | string[]
"#;

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

#[wasm_bindgen(typescript_custom_section)]
const TOKEN: &str = r#"
export type AbiToken =
    | null
    | boolean
    | string
    | number
    | { [K in string]: AbiToken }
    | AbiToken[]
    | (readonly [AbiToken, AbiToken])[];

type TokensObject = { [K in string]: AbiToken };
"#;

#[wasm_bindgen(typescript_custom_section)]
const PARAM: &str = r#"
export type AbiParamKindUint = 'uint8' | 'uint16' | 'uint32' | 'uint64' | 'uint128' | 'uint160' | 'uint256';
export type AbiParamKindInt = 'int8' | 'int16' | 'int32' | 'int64' | 'int128' | 'int160' | 'int256';
export type AbiParamKindTuple = 'tuple';
export type AbiParamKindBool = 'bool';
export type AbiParamKindCell = 'cell';
export type AbiParamKindAddress = 'address';
export type AbiParamKindBytes = 'bytes';
export type AbiParamKindGram = 'gram';
export type AbiParamKindTime = 'time';
export type AbiParamKindExpire = 'expire';
export type AbiParamKindPublicKey = 'pubkey';
export type AbiParamKindString = 'string';
export type AbiParamKindArray = `${AbiParamKind}[]`;

export type AbiParamKindMap = `map(${AbiParamKindInt | AbiParamKindUint | AbiParamKindAddress},${AbiParamKind | `${AbiParamKind}[]`})`;

export type AbiParamOptional = `optional(${AbiParamKind})`

export type AbiParamKind =
  | AbiParamKindUint
  | AbiParamKindInt
  | AbiParamKindTuple
  | AbiParamKindBool
  | AbiParamKindCell
  | AbiParamKindAddress
  | AbiParamKindBytes
  | AbiParamKindGram
  | AbiParamKindTime
  | AbiParamKindExpire
  | AbiParamKindString
  | AbiParamKindPublicKey;

export type AbiParam = {
  name: string;
  type: AbiParamKind | AbiParamKindMap | AbiParamKindArray | AbiParamOptional;
  components?: AbiParam[];
};
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "Promise<GenericContract>")]
    pub type PromiseGenericContract;
}

#[wasm_bindgen(typescript_custom_section)]
const LATEST_BLOCK: &'static str = r#"
export type LatestBlock = {
    id: string,
    endLt: string,
    genUtime: number,
};
"#;

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

#[wasm_bindgen(typescript_custom_section)]
const SIGNED_MESSAGE: &str = r#"
export type SignedMessage = {
    hash: string,
    expireAt: number,
    boc: string,
};
"#;

pub fn make_signed_message(data: nt::crypto::SignedMessage) -> Result<SignedMessage, JsValue> {
    let (boc, hash) = {
        let cell = data.message.write_to_new_cell().handle_error()?.into();
        (
            base64::encode(ton_types::serialize_toc(&cell).handle_error()?),
            cell.repr_hash(),
        )
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
        Some(boc) => {
            let body = base64::decode(boc.trim()).handle_error()?;
            let cell = ton_types::deserialize_tree_of_cells(&mut body.as_slice()).handle_error()?;
            ton_block::Message::construct_from_cell(cell).handle_error()?
        }
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

#[wasm_bindgen(typescript_custom_section)]
const POLLING_METHOD: &str = r#"
export type PollingMethod = 'manual' | 'reliable';
"#;

pub fn make_polling_method(s: models::PollingMethod) -> PollingMethod {
    JsValue::from(match s {
        models::PollingMethod::Manual => "manual",
        models::PollingMethod::Reliable => "reliable",
    })
    .unchecked_into()
}

#[wasm_bindgen(typescript_custom_section)]
const ED25519_KEY_PAIR: &'static str = r#"
export type Ed25519KeyPair = {
    publicKey: string,
    secretKey: string,
};
"#;

pub fn make_ed25519_key_pair(data: ed25519_dalek::Keypair) -> Ed25519KeyPair {
    ObjectBuilder::new()
        .set("publicKey", hex::encode(data.public.as_bytes()))
        .set("secretKey", hex::encode(data.secret.as_bytes()))
        .build()
        .unchecked_into()
}

#[wasm_bindgen(typescript_custom_section)]
const EXTENDED_SIGNATURE: &str = r#"
export type ExtendedSignature = {
    signature: string,
    signatureHex: string,
    signatureParts: {
        high: string,
        low: string,
    }
};
"#;

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

#[wasm_bindgen(typescript_custom_section)]
const FULL_CONTRACT_STATE: &'static str = r#"
export type FullContractState = {
    balance: string;
    genTimings: GenTimings;
    lastTransactionId: LastTransactionId;
    isDeployed: boolean;
    codeHash?: string;
    boc: string;
};
"#;

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

            let account_cell = state.account.serialize().handle_error()?;
            let boc = ton_types::serialize_toc(&account_cell)
                .map(base64::encode)
                .handle_error()?;

            Ok(ObjectBuilder::new()
                .set("balance", state.account.storage.balance.grams.0.to_string())
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
                .set("boc", boc)
                .build()
                .unchecked_into())
        }
        nt::transport::models::RawContractState::NotExists => Ok(JsValue::undefined()),
    }
}

#[wasm_bindgen(typescript_custom_section)]
const WALLET_CONTRACT_TYPE: &'static str = r#"
export type WalletContractType =
    | 'SafeMultisigWallet'
    | 'SafeMultisigWallet24h'
    | 'SetcodeMultisigWallet'
    | 'SetcodeMultisigWallet24h'
    | 'BridgeMultisigWallet'
    | 'SurfWallet'
    | 'WalletV3'
    | 'HighloadWalletV2';
"#;

impl TryFrom<WalletContractType> for nt::core::ton_wallet::WalletType {
    type Error = JsValue;

    fn try_from(value: WalletContractType) -> Result<Self, Self::Error> {
        let contract_type = JsValue::from(value)
            .as_string()
            .ok_or_else(|| JsValue::from_str("String with wallet contract type name expected"))?;

        nt::core::ton_wallet::WalletType::from_str(&contract_type).handle_error()
    }
}

impl From<nt::core::ton_wallet::WalletType> for WalletContractType {
    fn from(c: nt::core::ton_wallet::WalletType) -> Self {
        JsValue::from(c.to_string()).unchecked_into()
    }
}

#[wasm_bindgen(typescript_custom_section)]
const GIFT: &'static str = r#"
export type Gift = {
    flags: number;
    bounce: boolean;
    destination: string;
    amount: string;
    body?: string;
    stateInit?: string;
};
"#;

pub fn parse_gift(gift: Gift) -> Result<nt::core::ton_wallet::Gift, JsValue> {
    #[derive(Deserialize)]
    struct ParsedGift {
        flags: u8,
        bounce: bool,
        #[serde(with = "nt::utils::serde_address")]
        destination: ton_block::MsgAddressInt,
        #[serde(with = "nt::utils::serde_u64")]
        amount: u64,
        body: Option<String>,
        #[serde(rename = "stateInit")]
        state_init: Option<String>,
    }

    let parsed: ParsedGift = gift.obj.into_serde().handle_error()?;
    let body = match &parsed.body {
        Some(body) => Some(parse_cell_slice(body)?),
        None => None,
    };
    let state_init = match &parsed.state_init {
        Some(tvc) => Some(ton_block::StateInit::construct_from_base64(tvc).handle_error()?),
        None => None,
    };

    Ok(nt::core::ton_wallet::Gift {
        flags: parsed.flags,
        bounce: parsed.bounce,
        destination: parsed.destination,
        amount: parsed.amount,
        body,
        state_init,
    })
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "TransactionId")]
    pub type TransactionId;

    #[wasm_bindgen(typescript_type = "GenTimings")]
    pub type GenTimings;

    #[wasm_bindgen(typescript_type = "LastTransactionId")]
    pub type LastTransactionId;

    #[wasm_bindgen(typescript_type = "ContractState")]
    pub type ContractState;

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

    #[wasm_bindgen(typescript_type = "StateInit")]
    pub type StateInit;

    #[wasm_bindgen(typescript_type = "ExpectedAddress")]
    pub type ExpectedAddress;

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

    #[wasm_bindgen(typescript_type = "Promise<FullContractState | undefined>")]
    pub type PromiseOptionFullContractState;

    #[wasm_bindgen(typescript_type = "Ed25519KeyPair")]
    pub type Ed25519KeyPair;

    #[wasm_bindgen(typescript_type = "ExtendedSignature")]
    pub type ExtendedSignature;

    #[wasm_bindgen(typescript_type = "WalletContractType")]
    pub type WalletContractType;

    #[wasm_bindgen(typescript_type = "Gift")]
    pub type Gift;

    #[wasm_bindgen(typescript_type = "Array<Gift>")]
    pub type GiftList;
}
