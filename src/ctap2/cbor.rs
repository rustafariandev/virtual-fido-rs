//! Small helpers over `ciborium::Value` for CTAP2's integer-keyed maps.

use ciborium::Value;

use super::Status;

pub type Map = Vec<(Value, Value)>;

pub fn int(i: i64) -> Value {
    Value::Integer(i.into())
}

pub fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

pub fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

/// Builds a map in CTAP2 canonical order: keys sorted by encoded length, then bytewise.
pub fn map(mut entries: Map) -> Value {
    entries.sort_by_cached_key(|(k, _)| {
        let enc = encode(k);
        (enc.len(), enc)
    });
    Value::Map(entries)
}

pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(v, &mut out).expect("writing CBOR to a Vec cannot fail");
    out
}

/// Decodes a request parameter map. Empty input is an empty map.
pub fn decode_map(data: &[u8]) -> Result<Map, Status> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    match ciborium::de::from_reader(data).map_err(|_| Status::INVALID_CBOR)? {
        Value::Map(m) => Ok(m),
        _ => Err(Status::CBOR_UNEXPECTED_TYPE),
    }
}

/// Value for integer key `key`.
pub fn get(map: &[(Value, Value)], key: i64) -> Option<&Value> {
    map.iter().find(|(k, _)| matches!(k, Value::Integer(i) if i128::from(*i) == key as i128)).map(|(_, v)| v)
}

/// Value for text key `key`.
pub fn get_text<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter().find(|(k, _)| matches!(k, Value::Text(t) if t == key)).map(|(_, v)| v)
}

pub fn require(v: Option<&Value>) -> Result<&Value, Status> {
    v.ok_or(Status::MISSING_PARAMETER)
}

pub fn as_bytes(v: &Value) -> Result<&[u8], Status> {
    v.as_bytes().map(Vec::as_slice).ok_or(Status::CBOR_UNEXPECTED_TYPE)
}

pub fn as_text(v: &Value) -> Result<&str, Status> {
    v.as_text().ok_or(Status::CBOR_UNEXPECTED_TYPE)
}

pub fn as_map(v: &Value) -> Result<&[(Value, Value)], Status> {
    v.as_map().map(Vec::as_slice).ok_or(Status::CBOR_UNEXPECTED_TYPE)
}

pub fn as_array(v: &Value) -> Result<&[Value], Status> {
    v.as_array().map(Vec::as_slice).ok_or(Status::CBOR_UNEXPECTED_TYPE)
}

pub fn as_bool(v: &Value) -> Result<bool, Status> {
    v.as_bool().ok_or(Status::CBOR_UNEXPECTED_TYPE)
}

pub fn as_int(v: &Value) -> Result<i128, Status> {
    v.as_integer().map(i128::from).ok_or(Status::CBOR_UNEXPECTED_TYPE)
}

/// Optional text field of a map, e.g. `user.name`.
pub fn opt_text(map: &[(Value, Value)], key: &str) -> Result<Option<String>, Status> {
    get_text(map, key).map(|v| as_text(v).map(str::to_owned)).transpose()
}
