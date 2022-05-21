use std::str::FromStr;
use std::sync::Arc;

use ton_block::{Deserializable, MsgAddressInt};
use wasm_bindgen::prelude::*;
use wasm_bindgen::{JsCast, JsValue};

use nt_utils::TrustMe;

impl<T, E> HandleError for Result<T, E>
where
    E: ToString,
{
    type Output = T;

    fn handle_error(self) -> Result<Self::Output, JsValue> {
        self.map_err(|e| {
            let error = e.to_string();
            js_sys::Error::new(&error).unchecked_into()
        })
    }
}

pub trait HandleError {
    type Output;

    fn handle_error(self) -> Result<Self::Output, JsValue>;
}

pub struct ObjectBuilder {
    object: js_sys::Object,
}

impl ObjectBuilder {
    pub fn new() -> Self {
        Self {
            object: js_sys::Object::new(),
        }
    }

    pub fn set<T>(self, key: &str, value: T) -> Self
    where
        JsValue: From<T>,
    {
        let key = JsValue::from_str(key);
        let value = JsValue::from(value);
        js_sys::Reflect::set(&self.object, &key, &value).trust_me();
        self
    }

    pub fn build(self) -> JsValue {
        JsValue::from(self.object)
    }
}

impl Default for ObjectBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
#[derive(Default)]
pub struct ClockWithOffset {
    #[wasm_bindgen(skip)]
    pub inner: Arc<nt_utils::ClockWithOffset>,
}

#[wasm_bindgen]
impl ClockWithOffset {
    #[wasm_bindgen(constructor)]
    pub fn new() -> ClockWithOffset {
        Self::default()
    }

    #[wasm_bindgen(js_name = "updateOffset")]
    pub fn update_offset(&self, offset_ms: f64) {
        self.inner.update_offset(offset_ms as i64)
    }

    #[wasm_bindgen(js_name = "offsetMs")]
    pub fn offset_ms(&self) -> f64 {
        self.inner.offset_ms() as f64
    }
}

impl ClockWithOffset {
    pub fn clone_inner(&self) -> Arc<nt_utils::ClockWithOffset> {
        self.inner.clone()
    }
}

pub fn parse_hash(hash: &str) -> Result<ton_types::UInt256, JsValue> {
    ton_types::UInt256::from_str(hash).handle_error()
}

pub fn parse_public_key(public_key: &str) -> Result<ed25519_dalek::PublicKey, JsValue> {
    ed25519_dalek::PublicKey::from_bytes(&hex::decode(&public_key).handle_error()?).handle_error()
}

pub fn parse_address(address: &str) -> Result<MsgAddressInt, JsValue> {
    MsgAddressInt::from_str(address).handle_error()
}

pub fn parse_slice(boc: &str) -> Result<ton_types::SliceData, JsValue> {
    let body = base64::decode(boc).handle_error()?;
    let cell = ton_types::deserialize_tree_of_cells(&mut body.as_slice()).handle_error()?;
    Ok(cell.into())
}

pub fn parse_account_stuff(boc: &str) -> Result<ton_block::AccountStuff, JsValue> {
    use ton_block::MaybeDeserialize;

    let bytes = base64::decode(boc).handle_error()?;
    ton_types::deserialize_tree_of_cells(&mut bytes.as_slice())
        .and_then(|cell| {
            let slice = &mut cell.into();
            Ok(ton_block::AccountStuff {
                addr: Deserializable::construct_from(slice)?,
                storage_stat: Deserializable::construct_from(slice)?,
                storage: ton_block::AccountStorage {
                    last_trans_lt: Deserializable::construct_from(slice)?,
                    balance: Deserializable::construct_from(slice)?,
                    state: Deserializable::construct_from(slice)?,
                    init_code_hash: if slice.remaining_bits() > 0 {
                        ton_types::UInt256::read_maybe_from(slice)?
                    } else {
                        None
                    },
                },
            })
        })
        .handle_error()
}

pub fn parse_contract_abi(contract_abi: &str) -> Result<ton_abi::Contract, JsValue> {
    ton_abi::Contract::load(&mut contract_abi.as_bytes()).handle_error()
}

#[wasm_bindgen(typescript_custom_section)]
const GENERAL_STUFF: &str = r#"
export type EnumItem<T extends string, D> = { type: T, data: D };
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "Promise<void>")]
    pub type PromiseVoid;

    #[wasm_bindgen(typescript_type = "Promise<boolean>")]
    pub type PromiseBool;

    #[wasm_bindgen(typescript_type = "Promise<string>")]
    pub type PromiseString;

    #[wasm_bindgen(typescript_type = "Promise<string | undefined>")]
    pub type PromiseOptionString;

    #[wasm_bindgen(typescript_type = "Array<string>")]
    pub type StringArray;
}

#[derive(thiserror::Error, Debug)]
pub enum TokensJsonError {
    #[error("Parameter count mismatch")]
    ParameterCountMismatch,
    #[error("Object expected")]
    ObjectExpected,
    #[error("Message expected")]
    MessageExpected,
    #[error("Message body expected")]
    MessageBodyExpected,
    #[error("Array expected")]
    ArrayExpected,
    #[error("Parameter not found: {}", .0)]
    ParameterNotFound(String),
    #[error("Invalid number: {}", .0)]
    InvalidNumber(String),
    #[error("Expected integer value: {}", .0)]
    IntegerValueExpected(f64),
    #[error("Expected unsigned value: {}", .0)]
    UnsignedValueExpected(f64),
    #[error("Expected integer as string or number")]
    NumberExpected,
    #[error("Expected boolean")]
    BoolExpected,
    #[error("Invalid array length: {}", .0)]
    InvalidArrayLength(u32),
    #[error("Invalid cell")]
    InvalidCell,
    #[error("Expected string")]
    StringExpected,
    #[error("Expected map item as array of key and value")]
    MapItemExpected,
    #[error("Invalid address")]
    InvalidAddress,
    #[error("Invalid bytes")]
    InvalidBytes,
    #[error("Invalid bytes length")]
    InvalidBytesLength(usize),
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Expected param type")]
    ParamTypeExpected,
    #[error("Invalid components")]
    InvalidComponents,
}
