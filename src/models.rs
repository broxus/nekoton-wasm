use std::collections::HashMap;
use std::convert::TryFrom;

use nt::core::models;
use nt::core::models::TransactionError;
use ton_block::{
    Deserializable, GetRepresentationHash, MsgAddressExt, MsgAddressInt, Serializable,
    TrBouncePhase,
};
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
    raw: string,
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

export type MessageType = 'IntMsg' | 'ExtIn' | 'ExtOut';

export type JsRawMessage = {
  hash: string,
  src?: string,
  dst?: string,
  value: string,
  bounce: boolean,
  bounced: boolean,
  body?: string,
  bodyHash?: string,
  boc: string,
  init?: {
    codeHash: string
  },
  msgType: MessageType,
  lt?: number
};

export type TransactionComputeType = 'vm' | 'skipped';
export type TransactionBounceStatus = 'noFunds' | 'ok' | 'negFunds';
export type TransactionStorageStatusChange = 'Unchanged' | 'Frozen' | 'Deleted';
export type TrComputeSkippedReason = 'NoState' | 'BadState' | 'NoGas' | 'Suspended';

export type TrComputeSkipped = {
  status: 'skipped',
  reason: TrComputeSkippedReason
}
export type TrComputeVm = {
  status: 'vm',
  success: boolean,
  exitCode: number,
  msgStateUsed: boolean,
  accountActivated: boolean,
  gasFees: number,
  gasUsed: number,
  gasLimit: number,
  gasCredit: number,
  mode: number,
  exitArg: undefined | number,
  vmSteps: number
}
export type TrAction = {
  resultCode: number,
  success: boolean,
  valid: boolean,
  noFunds: boolean,
  totalFwdFees: number,
  totalActionFees: number,
  resultArg: number,
  totActions: number,
  specActions: number,
  skippedActions: number,
  msgsCreated: number
}

export type JsRawTransaction = {
  lt: bigint,
  hash: string,
  prevTransLt: bigint,
  prevTransHash: string,
  now: number,
  accountAddr: string,
  description: {
    compute: TrComputeVm | TrComputeSkipped,
    aborted: boolean,
    destroyed: boolean,
    bounce: undefined |
      {
        status: 'ok'
        msgFees: number,
        fwdFees: number
      } | {
        status: 'noFunds'
        reqFwdFees: number
      } | {
        status: 'negFunds'
      },
    storage: {
      storageFeesCollected: number,
      storageFeesDue: undefined | number,
      statusChange: TransactionStorageStatusChange
    },
    action: TrAction | undefined,
    creditFirst: boolean
  },
  origStatus: AccountStatus,
  endStatus: AccountStatus,
  totalFees: number,
  inMessage: JsRawMessage,
  outMessages: JsRawMessage[],
  boc: string,
}

export type TransactionsBatchType = 'old' | 'new';

export type TransactionsBatchInfo = {
    minLt: string,
    maxLt: string,
    batchType: TransactionsBatchType,
};

export type ReliableBehaviorType = 'BlockWalking' | 'IntensivePolling';

export type TransportInfo = {
    maxTransactionsPerFetch: number;
    reliableBehavior: ReliableBehaviorType;
    hasKeyBlocks: boolean;
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

export type TransactionExecutorExtendedOutput =
    | { exitCode: number }
    | { account: string, transaction: JsRawTransaction, trace: EngineTraceInfo[] };

export type EngineTraceInfo = {
  infoType: string,
  step: number,
  cmdStr: string,
  stack: string[],
  gasUsed: string,
  gasCmd: string,
  cmdCodeRemBits: string,
  cmdCodeHex: string,
  cmdCodeCellHash: string,
  cmdCodeOffset: string,
}

export type ExecutionOutput = {
    output?: TokensObject,
    code: number,
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

pub fn make_raw_message(raw: ton_types::Cell) -> JsRawMessage {
    let data = ton_block::Message::construct_from_cell(raw.clone()).expect("Shouldn't fail");
    let hash = data.hash().unwrap_or_default();

    #[derive(Default)]
    struct MessageCommon {
        pub src: Option<MsgAddressInt>,
        pub dst: Option<String>,
        pub value: u64,
        pub bounce: bool,
        pub bounced: bool,
        pub msg_type: String,
    }

    let common = match data.header() {
        ton_block::CommonMsgInfo::IntMsgInfo(header) => MessageCommon {
            src: match &header.src {
                ton_block::MsgAddressIntOrNone::Some(addr) => Some(addr.clone()),
                ton_block::MsgAddressIntOrNone::None => None,
            },
            dst: Some(header.dst.to_string()),
            value: header.value.grams.as_u128() as u64,
            bounce: header.bounce,
            bounced: header.bounced,
            msg_type: "IntMsg".to_string(),
        },
        ton_block::CommonMsgInfo::ExtInMsgInfo(header) => MessageCommon {
            src: None,
            dst: Some(header.dst.to_string()),
            msg_type: "ExtIn".to_string(),
            ..Default::default()
        },
        ton_block::CommonMsgInfo::ExtOutMsgInfo(header) => {
            let dst = match header.dst.clone() {
                MsgAddressExt::AddrNone => None,
                MsgAddressExt::AddrExtern(addr) => Some(addr.external_address.as_hex_string()),
            };
            MessageCommon {
                src: match &header.src {
                    ton_block::MsgAddressIntOrNone::Some(addr) => Some(addr.clone()),
                    ton_block::MsgAddressIntOrNone::None => None,
                },
                msg_type: "ExtOut".to_string(),
                dst,
                ..Default::default()
            }
        }
    };

    let (body, body_hash) = if let Some(body) = &data.body() {
        let data = body.clone().into_cell();
        (
            Some(make_boc(&data).expect("Shouldn't fail")),
            Some(data.repr_hash().to_hex_string()),
        )
    } else {
        (None, None)
    };

    let init = if let Some(init) = data.state_init() {
        let state_init_code_hash = init
            .code
            .as_ref()
            .map(|code| code.repr_hash().to_hex_string());
        Some(
            ObjectBuilder::new()
                .set("code_hash", state_init_code_hash)
                .build(),
        )
    } else {
        None
    };
    let lt = data.lt();

    ObjectBuilder::new()
        .set("hash", hash.to_hex_string())
        .set("src", common.src.as_ref().map(ToString::to_string))
        .set("dst", common.dst)
        .set("value", common.value.to_string())
        .set("bounce", common.bounce)
        .set("bounced", common.bounced)
        .set("body", body)
        .set("bodyHash", body_hash)
        .set("boc", make_boc(&raw).expect("Shouldn't fail"))
        .set("init", init)
        .set("msgType", common.msg_type)
        .set("lt", lt)
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

pub fn make_raw_transaction(
    raw_transaction: nt::transport::models::RawTransaction,
) -> JsRawTransaction {
    let nt::transport::models::RawTransaction { hash, data } = raw_transaction;

    let boc = data
        .write_to_new_cell()
        .map_err(|_| TransactionError::InvalidStructure)
        .unwrap();
    let boc = boc
        .into_cell()
        .map_err(|_| TransactionError::InvalidStructure)
        .unwrap();
    let boc = ton_types::serialize_toc(&boc)
        .map_err(|_| TransactionError::InvalidStructure)
        .unwrap();
    let boc = base64::encode(boc);

    let in_msg = {
        if let Some(msg) = &data.in_msg.map(|in_msg| in_msg.cell()) {
            Some(make_raw_message(msg.clone()))
        } else {
            None
        }
    };

    let mut out_messages = vec![];
    data.out_msgs
        .iterate_slices(|slice| {
            if let Ok(message) = slice.reference(0) {
                out_messages.push(message);
            }
            Ok(true)
        })
        .unwrap();

    let out_msgs = out_messages
        .into_iter()
        .map(|msg| make_raw_message(msg))
        .collect::<js_sys::Array>();

    let desc = if let Some(ton_block::TransactionDescr::Ordinary(desc)) =
        data.description.read_struct().ok()
    {
        Some(make_raw_description(desc))
    } else {
        None
    };

    ObjectBuilder::new()
        .set("lt", data.lt)
        .set("hash", hex::encode(hash.as_slice()))
        .set("prevTransLt", data.prev_trans_lt)
        .set(
            "prevTransHash",
            hex::encode(data.prev_trans_hash.as_slice()),
        )
        .set("now", data.now)
        .set("accountAddr", data.account_addr.as_hex_string())
        .set("description", desc)
        .set("origStatus", make_account_status(data.orig_status.into()))
        .set("endStatus", make_account_status(data.end_status.into()))
        .set("totalFees", data.total_fees.grams.as_u128().to_string())
        .set("inMessage", in_msg)
        .set("outMessages", out_msgs)
        .set("boc", boc)
        .build()
        .unchecked_into()
}

pub fn make_raw_description(desc: ton_block::TransactionDescrOrdinary) -> JsValue {
    let compute_ph = match &desc.compute_ph {
        ton_block::TrComputePhase::Vm(vm) => ObjectBuilder::new()
            .set("status", "vm")
            .set("success", vm.success)
            .set("exitCode", vm.exit_code)
            .set("msgStateUsed", vm.msg_state_used)
            .set("accountActivated", vm.account_activated)
            .set("gasFees", vm.gas_fees.as_u128().to_string())
            .set("gasUsed", vm.gas_used.to_string())
            .set("gasLimit", vm.gas_limit.to_string())
            .set("gasCredit", vm.gas_credit.unwrap_or_default().to_string())
            .set("mode", vm.mode)
            .set("exitArg", vm.exit_arg)
            .set("vmSteps", vm.vm_steps)
            .build(),
        ton_block::TrComputePhase::Skipped(s) => ObjectBuilder::new()
            .set("status", "skipped")
            .set("reason", format!("{:#?}", s.reason))
            .build(),
    };

    let aborted = desc.aborted;
    let bounce = if let Some(b) = desc.bounce {
        Some(match b {
            TrBouncePhase::Negfunds => ObjectBuilder::new().set("status", "negFunds").build(),
            TrBouncePhase::Nofunds(f) => ObjectBuilder::new()
                .set("status", "noFunds")
                .set("reqFwdFees", f.req_fwd_fees.as_u128().to_string())
                .build(),
            TrBouncePhase::Ok(f) => ObjectBuilder::new()
                .set("status", "ok")
                .set("msgFees", f.msg_fees.as_u128().to_string())
                .set("fwdFees", f.fwd_fees.as_u128().to_string())
                .build(),
        })
    } else {
        None
    };
    let storage = if let Some(b) = desc.storage_ph {
        Some(
            ObjectBuilder::new()
                .set("storageFeesCollected", b.storage_fees_collected.to_string())
                .set(
                    "storageFeesDue",
                    b.storage_fees_due.map(|v| v.as_u128().to_string()),
                )
                .set("statusChange", format!("{:#?}", b.status_change))
                .build(),
        )
    } else {
        None
    };
    let action = if let Some(b) = desc.action {
        Some(
            ObjectBuilder::new()
                .set("resultCode", b.result_code)
                .set("success", b.success)
                .set("valid", b.valid)
                .set("noFunds", b.no_funds)
                .set(
                    "totalFwdFees",
                    b.total_fwd_fees.unwrap_or_default().as_u128().to_string(),
                )
                .set(
                    "totalActionFees",
                    b.total_action_fees
                        .unwrap_or_default()
                        .as_u128()
                        .to_string(),
                )
                .set("resultArg", b.result_arg)
                .set("totActions", b.tot_actions)
                .set("specActions", b.spec_actions)
                .set("skippedActions", b.skipped_actions)
                .set("msgsCreated", b.msgs_created)
                .build(),
        )
    } else {
        None
    };
    ObjectBuilder::new()
        .set("compute", compute_ph)
        .set("aborted", aborted)
        .set("destroyed", desc.destroyed)
        .set("bounce", bounce)
        .set("storage", storage)
        .set("action", action)
        .set("creditFirst", desc.credit_first)
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
        nt::transport::models::RawContractState::NotExists => Ok(JsValue::undefined()),
    }
}

pub fn make_boc_with_hash(cell: ton_types::Cell) -> Result<BocWithHash, JsValue> {
    Ok(ObjectBuilder::new()
        .set("hash", cell.repr_hash().to_hex_string())
        .set("boc", make_boc(&cell)?)
        .build()
        .unchecked_into())
}

#[derive(Clone, Default)]
pub struct EngineTraceInfoData {
    pub info_type: String,
    pub step: u32, // number of executable command
    pub cmd_str: String,
    pub stack: Vec<String>,
    pub gas_used: i64,
    pub gas_cmd: i64,
    pub cmd_code_rem_bits: u32,
    pub cmd_code_hex: String,
    pub cmd_code_cell_hash: String,
    pub cmd_code_offset: u32,
}

impl EngineTraceInfoData {
    pub fn from(info: &ton_vm::executor::EngineTraceInfo) -> Self {
        let cmd_code_rem_bits = info.cmd_code.remaining_bits() as u32;
        let cmd_code_hex = info.cmd_code.to_hex_string();
        let cmd_code_cell_hash = info.cmd_code.cell().repr_hash().to_hex_string();
        let cmd_code_offset = info.cmd_code.pos() as u32;

        Self {
            info_type: format!("{:#?}", info.info_type),
            step: info.step,
            cmd_str: info.cmd_str.clone(),
            stack: info.stack.storage.iter().map(|s| s.to_string()).collect(),
            gas_used: info.gas_used,
            gas_cmd: info.gas_cmd,
            cmd_code_rem_bits,
            cmd_code_hex,
            cmd_code_cell_hash,
            cmd_code_offset,
        }
    }
}

pub fn make_engine_trace(engine_trace: &EngineTraceInfoData) -> Result<EngineTraceInfo, JsValue> {
    let stack = engine_trace
        .stack
        .iter()
        .map(|s| JsValue::from(s))
        .collect::<js_sys::Array>();
    Ok(ObjectBuilder::new()
        .set("infoType", engine_trace.info_type.clone())
        .set("step", engine_trace.step)
        .set("cmdStr", engine_trace.cmd_str.clone())
        .set("stack", stack)
        .set("gasUsed", engine_trace.gas_used.to_string())
        .set("gasCmd", engine_trace.gas_cmd.to_string())
        .set("cmdCodeRemBits", engine_trace.cmd_code_rem_bits.to_string())
        .set("cmdCodeHex", engine_trace.cmd_code_hex.clone())
        .set("cmdCodeCellHash", engine_trace.cmd_code_cell_hash.clone())
        .set("cmdCodeOffset", engine_trace.cmd_code_offset.to_string())
        .build()
        .unchecked_into())
}

pub fn serialize_into_boc_with_hash(data: &dyn Serializable) -> Result<BocWithHash, JsValue> {
    let cell = data.serialize().handle_error()?;
    make_boc_with_hash(cell)
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

    #[wasm_bindgen(typescript_type = "TransactionExecutorExtendedOutput")]
    pub type TransactionExecutorExtendedOutput;

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

    #[wasm_bindgen(typescript_type = "EngineTraceInfo")]
    pub type EngineTraceInfo;

    #[wasm_bindgen(typescript_type = "TransactionTree")]
    pub type JsTransactionTree;

    #[wasm_bindgen(typescript_type = "JsRawTransaction")]
    pub type JsRawTransaction;

    #[wasm_bindgen(typescript_type = "JsRawMessage")]
    pub type JsRawMessage;
}
