use crate::error::{Error, Result};
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};

mod workflow_spec;

pub const OPENAPI: &str = include_str!("../../../docs/contracts/openapi.json");

pub fn openapi() -> &'static Value {
    static DOC: OnceLock<Value> = OnceLock::new();
    DOC.get_or_init(|| serde_json::from_str(OPENAPI).expect("checked-in OpenAPI must parse"))
}

pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

pub fn validate(name: &str, input: &Value) -> Result<()> {
    static CACHE: OnceLock<Mutex<HashMap<String, Arc<jsonschema::JSONSchema>>>> = OnceLock::new();
    let mut cache = CACHE
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| Error::unavailable("Validator unavailable"))?;
    let validator = if let Some(v) = cache.get(name) {
        v.clone()
    } else {
        if openapi()["components"]["schemas"].get(name).is_none() {
            return Err(Error::invalid("Unknown model"));
        }
        let doc = with_schema_dependencies(json!({
            "$ref": format!("#/components/schemas/{}", pointer_segment(name))
        }))?;
        let v = Arc::new(
            jsonschema::JSONSchema::options()
                .with_draft(jsonschema::Draft::Draft202012)
                .should_validate_formats(true)
                .compile(&doc)
                .map_err(|_| Error::invalid("Invalid contract"))?,
        );
        cache.insert(name.to_owned(), v.clone());
        v
    };
    drop(cache);
    if !validator.is_valid(input) {
        return Err(Error::invalid("Value does not match the existing contract"));
    }
    if name == "WorkflowSpec" {
        workflow_spec::validate_graph(input)?;
    }
    Ok(())
}

/// Attach only the checked-in models reachable from this schema. Each cached
/// validator owns its root document, so including the entire catalog in every
/// root needlessly retains hundreds of copies of unrelated model definitions.
/// References keep their original paths, including cycles and model subpaths.
pub(crate) fn with_schema_dependencies(schema: Value) -> Result<Value> {
    schema_dependencies(schema, &openapi()["components"]["schemas"])
}

fn pointer_segment(name: &str) -> String {
    name.replace('~', "~0").replace('/', "~1")
}

fn schema_dependencies(mut schema: Value, catalog: &Value) -> Result<Value> {
    let root = schema
        .as_object_mut()
        .ok_or_else(|| Error::invalid("Contract schema must be an object"))?;
    if root.contains_key("components") {
        return Err(Error::invalid(
            "Contract schema cannot replace the model catalog",
        ));
    }
    let mut pending = Vec::new();
    model_references(&schema, catalog, &mut pending)?;
    let mut models = Map::new();
    while let Some(name) = pending.pop() {
        if models.contains_key(&name) {
            continue;
        }
        let model = catalog
            .get(&name)
            .ok_or_else(|| Error::invalid("Unknown model reference"))?;
        model_references(model, catalog, &mut pending)?;
        // Record a model before visiting its dependencies so recursive schemas
        // terminate without flattening or weakening their reference semantics.
        models.insert(name, model.clone());
    }
    schema["components"] = json!({"schemas": models});
    Ok(schema)
}

fn model_references(value: &Value, catalog: &Value, pending: &mut Vec<String>) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                match key.as_str() {
                    "$ref" => {
                        let reference = value
                            .as_str()
                            .and_then(|s| s.strip_prefix("#/components/schemas/"))
                            .ok_or_else(|| {
                                Error::invalid("Only local model references are supported")
                            })?;
                        let raw_name = reference.split('/').next().unwrap_or_default();
                        let name = raw_name.replace("~1", "/").replace("~0", "~");
                        if name.is_empty()
                            || pointer_segment(&name) != raw_name
                            || catalog.pointer(&format!("/{reference}")).is_none()
                        {
                            return Err(Error::invalid("Invalid or missing model reference"));
                        }
                        pending.push(name);
                    }
                    "$id" | "$dynamicRef" | "$recursiveRef" => {
                        return Err(Error::invalid("Contract reference scopes are unsupported"));
                    }
                    _ => model_references(value, catalog, pending)?,
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                model_references(value, catalog, pending)?;
            }
        }
        _ => (),
    }
    Ok(())
}

pub fn compile_business(schema: &Value) -> Result<jsonschema::JSONSchema> {
    reject_refs(schema)?;
    let compiled = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .should_validate_formats(true)
        .compile(schema)
        .map_err(|_| Error::invalid("Invalid business schema"))?;
    Ok(compiled)
}

pub fn validate_business(schema: &Value, input: &Value) -> Result<()> {
    let compiled = compile_business(schema)?;
    if compiled.is_valid(input) {
        Ok(())
    } else {
        Err(Error::invalid("Business value does not match its schema"))
    }
}

/// PostgreSQL text and jsonb cannot represent U+0000.
pub(crate) fn reject_jsonb_nul(value: &Value) -> Result<()> {
    fn contains_nul(value: &Value) -> bool {
        match value {
            Value::String(value) => value.contains('\0'),
            Value::Array(values) => values.iter().any(contains_nul),
            Value::Object(values) => values
                .iter()
                .any(|(key, value)| key.contains('\0') || contains_nul(value)),
            _ => false,
        }
    }
    if contains_nul(value) {
        return Err(Error::invalid("Stored JSON cannot contain NUL characters"));
    }
    Ok(())
}

// M1 accepts self-contained schemas only. It never resolves network or host-file refs.
pub fn reject_refs(value: &Value) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if matches!(
                    key.as_str(),
                    "$ref" | "$dynamicRef" | "$recursiveRef" | "$id"
                ) {
                    return Err(Error::invalid(
                        "Referenced schemas are not supported by this M1 profile",
                    ));
                }
                reject_refs(value)?;
            }
        }
        Value::Array(a) => {
            for v in a {
                reject_refs(v)?;
            }
        }
        _ => (),
    }
    Ok(())
}

pub fn strict_json(bytes: &[u8], maximum: usize) -> Result<Value> {
    if bytes.len() > maximum {
        return Err(Error::new(
            "PAYLOAD_TOO_LARGE",
            "JSON exceeds its byte limit",
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
        ));
    }
    let mut d = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue::deserialize(&mut d)?;
    d.end()?;
    Ok(value.0)
}

/// Strict UTF-8 URL encoding shared by OAuth queries and forms. A lossy URL
/// decoder must not silently replace malformed security parameters or accept
/// two differently encoded spellings of the same parameter name.
pub(crate) fn strict_urlencoded(
    bytes: &[u8],
    maximum_bytes: usize,
    maximum_fields: usize,
) -> Result<Map<String, Value>> {
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(Error::invalid("URL encoded input size is invalid"));
    }
    fn hex(value: u8) -> Option<u8> {
        match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            b'A'..=b'F' => Some(value - b'A' + 10),
            _ => None,
        }
    }
    fn decode(input: &[u8]) -> Result<String> {
        let mut output = Vec::with_capacity(input.len());
        let mut offset = 0;
        while offset < input.len() {
            match input[offset] {
                b'+' => output.push(b' '),
                b'%' => {
                    let high = input.get(offset + 1).copied().and_then(hex);
                    let low = input.get(offset + 2).copied().and_then(hex);
                    let (Some(high), Some(low)) = (high, low) else {
                        return Err(Error::invalid("Malformed URL percent encoding"));
                    };
                    output.push((high << 4) | low);
                    offset += 2;
                }
                byte => output.push(byte),
            }
            offset += 1;
        }
        String::from_utf8(output).map_err(|_| Error::invalid("URL encoded input must be UTF-8"))
    }
    let mut fields = Map::new();
    for pair in bytes.split(|byte| *byte == b'&') {
        if fields.len() >= maximum_fields {
            return Err(Error::invalid("Too many URL encoded fields"));
        }
        let equal = pair
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or_else(|| Error::invalid("URL encoded field requires a value"))?;
        let name = decode(&pair[..equal])?;
        let value = decode(&pair[equal + 1..])?;
        if name.is_empty() || fields.insert(name, Value::String(value)).is_some() {
            return Err(Error::invalid("Ambiguous URL encoded parameter"));
        }
    }
    Ok(fields)
}

struct StrictValue(Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = StrictValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("strict JSON")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(json!(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(json!(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(json!(v)))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|x| StrictValue(Value::Number(x)))
                    .ok_or_else(|| E::custom("nonfinite number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(json!(v)))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(json!(v)))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                self.visit_unit()
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut a = Vec::new();
                while let Some(v) = seq.next_element::<StrictValue>()? {
                    a.push(v.0);
                }
                Ok(StrictValue(Value::Array(a)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut a = Map::new();
                while let Some(k) = map.next_key::<String>()? {
                    if a.contains_key(&k) {
                        return Err(de::Error::custom("duplicate JSON member"));
                    }
                    a.insert(k, map.next_value::<StrictValue>()?.0);
                }
                Ok(StrictValue(Value::Object(a)))
            }
        }
        d.deserialize_any(V)
    }
}

pub fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| Error::invalid("Required string is missing"))
}
/// JSON Schema integers include integral JSON numbers such as `1000.0`.
/// Convert bounded counters/deadlines without truncation or unchecked unwraps.
pub(crate) fn unsigned(value: &Value) -> Result<u64> {
    if let Some(integer) = value.as_u64() {
        return Ok(integer);
    }
    if let Some(number) = value.as_f64() {
        if number.is_finite()
            && (0.0..=9007199254740991.0).contains(&number)
            && number.fract() == 0.0
        {
            return Ok(number as u64);
        }
    }
    Err(Error::invalid("Expected an exact unsigned integer"))
}

pub fn id(v: &Value, key: &str) -> Result<uuid::Uuid> {
    string(v, key)?
        .parse()
        .map_err(|_| Error::invalid("Invalid resource UUID"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_dependency_closure_preserves_cycles_and_subpaths() {
        let catalog = json!({
            "Node": {
                "type": "object",
                "additionalProperties": false,
                "required": ["value"],
                "properties": {
                    "value": {"$ref": "#/components/schemas/Scalar/$defs/value"},
                    "next": {"$ref": "#/components/schemas/Node"}
                }
            },
            "Scalar": {"$defs": {"value": {"type": "integer", "minimum": 0}}},
            "Unrelated": {"$ref": "https://invalid.example/schema"}
        });
        let document =
            schema_dependencies(json!({"$ref": "#/components/schemas/Node"}), &catalog).unwrap();
        assert_eq!(
            document["components"]["schemas"].as_object().unwrap().len(),
            2
        );
        assert!(document["components"]["schemas"].get("Unrelated").is_none());
        let compiled = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&document)
            .unwrap();
        assert!(compiled.is_valid(&json!({"value": 1, "next": {"value": 2}})));
        assert!(!compiled.is_valid(&json!({"value": 1, "next": {"value": -1}})));
        assert!(!compiled.is_valid(&json!({"value": 1, "extra": true})));
    }

    #[test]
    fn model_dependencies_reject_unresolvable_or_external_references() {
        let catalog = json!({"Known": {"type": "string"}});
        for reference in [
            "https://invalid.example/schema",
            "file:///etc/passwd",
            "other.json#/components/schemas/Known",
            "#/components/schemas/Missing",
            "#/components/schemas/Known/$defs/missing",
            "#/components/schemas/Kn~2own",
            "#/components/schemas/",
            "#",
        ] {
            assert!(schema_dependencies(json!({"$ref": reference}), &catalog).is_err());
        }
        assert!(schema_dependencies(json!({"$ref": 42}), &catalog).is_err());
        for keyword in ["$id", "$dynamicRef", "$recursiveRef"] {
            let mut schema = json!({"type": "object"});
            schema[keyword] = json!("https://invalid.example/schema");
            assert!(schema_dependencies(schema, &catalog).is_err());
        }
        assert!(schema_dependencies(json!({"components": {}}), &catalog).is_err());
        let catalog = json!({"Known": {"properties": {"nested": {"$ref": "file:///etc/passwd"}}}});
        assert!(
            schema_dependencies(json!({"$ref": "#/components/schemas/Known"}), &catalog).is_err()
        );
    }

    #[test]
    fn model_dependency_names_use_json_pointer_escaping() {
        let catalog = json!({"path/~value": {"type": "integer"}});
        let document = schema_dependencies(
            json!({"$ref": "#/components/schemas/path~1~0value"}),
            &catalog,
        )
        .unwrap();
        assert_eq!(document["components"]["schemas"], catalog);
    }

    #[test]
    fn every_model_compiles_with_a_compact_dependency_document() {
        let catalog = &openapi()["components"]["schemas"];
        let models = catalog.as_object().unwrap();
        let full_bytes = serde_json::to_vec(catalog).unwrap().len() * models.len();
        let mut retained_bytes = 0;
        for name in models.keys() {
            let document = with_schema_dependencies(json!({
                "$ref": format!("#/components/schemas/{}", pointer_segment(name))
            }))
            .unwrap_or_else(|error| panic!("{name}: {error}"));
            retained_bytes += serde_json::to_vec(&document).unwrap().len();
            jsonschema::JSONSchema::options()
                .with_draft(jsonschema::Draft::Draft202012)
                .should_validate_formats(true)
                .compile(&document)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
        }
        assert!(
            retained_bytes < full_bytes / 10,
            "model documents retain {retained_bytes} bytes versus {full_bytes} with the full catalog"
        );
        assert!(validate(
            "HealthStatus",
            &json!({"status": "ok", "spec_version": "2.8.0"})
        )
        .is_ok());
    }

    #[test]
    fn duplicate_and_trailing_json_are_rejected() {
        for input in [
            br#"{"a":1,"a":2}"#.as_slice(),
            br#"{"a":{"x":0,"x":1}}"#,
            b"{} {}",
            b"NaN",
        ] {
            assert!(strict_json(input, 1024).is_err());
        }
    }
    #[test]
    fn schemas_are_offline_and_strict() {
        assert!(validate("NodeConfig",&json!({"kernel_cpu_millis":3999,"kernel_memory_bytes":17179869184u64,"system_cpu_millis":1000,"system_memory_bytes":1048576,"shutdown_grace_ms":30000})).is_err());
        assert!(
            reject_refs(&json!({"properties":{"secret":{"$ref":"file:///etc/passwd"}}})).is_err()
        );
        assert!(validate(
            "HealthStatus",
            &json!({"status":"ok","spec_version":"2.8.0","extra":true})
        )
        .is_err());
    }
}
