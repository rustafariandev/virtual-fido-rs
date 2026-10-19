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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_uses_ctap2_canonical_order() {
        let m = map(vec![
            (text("rk"), int(0)),
            (int(-1), int(0)),
            (int(24), int(0)),
            (text("a"), int(0)),
            (int(1), int(0)),
            (text("up"), int(0)),
            (int(-25), int(0)),
        ]);
        let keys: Vec<Vec<u8>> = m.as_map().unwrap().iter().map(|(k, _)| encode(k)).collect();
        // Shorter encodings first, then bytewise: so ints before text, positive before negative.
        assert_eq!(
            keys,
            [
                vec![0x01],
                vec![0x20],
                vec![0x18, 24],
                vec![0x38, 24],
                vec![0x61, b'a'],
                encode(&text("rk")),
                encode(&text("up"))
            ]
        );
    }

    #[test]
    fn decode_map_errors() {
        assert_eq!(decode_map(&[]).unwrap(), Vec::new());
        assert_eq!(decode_map(&[0xA1, 0x01, 0x02]).unwrap(), vec![(int(1), int(2))]);
        assert_eq!(decode_map(&[0x80]).unwrap_err(), Status::CBOR_UNEXPECTED_TYPE);
        assert_eq!(decode_map(&[0xA1, 0x01]).unwrap_err(), Status::INVALID_CBOR);
    }

    #[test]
    fn getters_match_key_type_and_value_type() {
        let m = vec![(int(-1), bytes(b"x")), (text("name"), text("alice")), (int(3), Value::Bool(true))];
        assert_eq!(as_bytes(get(&m, -1).unwrap()).unwrap(), b"x");
        assert!(get(&m, 1).is_none());
        assert!(get_text(&m, "-1").is_none());
        assert_eq!(opt_text(&m, "name").unwrap().as_deref(), Some("alice"));
        assert_eq!(opt_text(&m, "missing").unwrap(), None);
        assert!(as_bool(get(&m, 3).unwrap()).unwrap());
        assert_eq!(as_int(get(&m, 3).unwrap()).unwrap_err(), Status::CBOR_UNEXPECTED_TYPE);
        assert_eq!(require(get(&m, 9)).unwrap_err(), Status::MISSING_PARAMETER);
    }
}
