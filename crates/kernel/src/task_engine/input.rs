use crate::error::{Error, Result};
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, HashMap},
    io::{self, Write},
};

/// Materialize a validated WorkflowStep from the task input and the successful
/// outputs of its direct and transitive dependencies.
pub(super) fn materialize(
    step: &Value,
    task_input: &Value,
    upstream: &HashMap<String, Value>,
    maximum_bytes: usize,
) -> Result<Value> {
    let mapping = step["input_mapping"]
        .as_object()
        .ok_or_else(|| Error::invalid("Workflow step input mapping must be an object"))?;
    let mut input = BTreeMap::new();
    for (field, leaf) in mapping {
        let leaf = leaf
            .as_object()
            .filter(|leaf| leaf.len() == 1)
            .ok_or_else(|| {
                Error::invalid("Workflow input mapping must have one source per field")
            })?;
        let value = if let Some(literal) = leaf.get("literal") {
            literal
        } else if let Some(pointer) = leaf.get("task_input") {
            resolve_pointer(task_input, pointer)?
        } else if let Some(output) = leaf.get("step_output") {
            let source = output["step"]
                .as_str()
                .and_then(|id| upstream.get(id))
                .ok_or_else(|| Error::invalid("Workflow step output source is unavailable"))?;
            resolve_pointer(source, &output["pointer"])?
        } else {
            return Err(Error::invalid("Workflow input mapping source is invalid"));
        };
        input.insert(field.as_str(), value);
    }
    // Count the actual wire representation while values are still borrowed.
    // Several fields can reference the same large value without cloning it.
    let mut limit = ByteLimit {
        remaining: maximum_bytes,
        exceeded: false,
    };
    if let Err(error) = serde_json::to_writer(&mut limit, &input) {
        return Err(if limit.exceeded {
            Error::invalid("Workflow step input exceeds its byte limit")
        } else {
            error.into()
        });
    }
    let input: Map<String, Value> = input
        .into_iter()
        .map(|(field, value)| (field.to_owned(), value.clone()))
        .collect();
    Ok(Value::Object(input))
}

struct ByteLimit {
    remaining: usize,
    exceeded: bool,
}

impl Write for ByteLimit {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(remaining) = self.remaining.checked_sub(bytes.len()) else {
            self.exceeded = true;
            return Err(io::Error::other(
                "Workflow step input exceeds its byte limit",
            ));
        };
        self.remaining = remaining;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn resolve_pointer<'a>(value: &'a Value, pointer: &Value) -> Result<&'a Value> {
    let pointer = pointer
        .as_str()
        .filter(|pointer| {
            pointer
                .split('~')
                .skip(1)
                .all(|suffix| matches!(suffix.as_bytes().first(), Some(b'0' | b'1')))
        })
        .ok_or_else(|| {
            Error::invalid("Workflow input mapping requires an RFC 6901 JSON Pointer")
        })?;
    value
        .pointer(pointer)
        .ok_or_else(|| Error::invalid("Workflow input mapping path does not exist"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn materializes_literals_and_references_without_transforming_values() {
        let task_input = json!({"rows":[{"a/b": {"~1": {"中文": "selected"}}}], "": null});
        let upstream = HashMap::from([("parse".into(), json!({"values":[false, null]}))]);
        let literal = json!({"task_input":"/rows", "step_output":null});
        let step = json!({"input_mapping": {
            "literal": {"literal": literal},
            "all_input": {"task_input":""},
            "escaped": {"task_input":"/rows/0/a~1b/~01/中文"},
            "empty_field": {"task_input":"/"},
            "all_output": {"step_output":{"step":"parse","pointer":""}},
            "null_output": {"step_output":{"step":"parse","pointer":"/values/1"}}
        }});
        assert_eq!(
            materialize(&step, &task_input, &upstream, 4096).unwrap(),
            json!({
                "literal":literal, "all_input":task_input, "escaped":"selected",
                "empty_field":null, "all_output":upstream["parse"], "null_output":null
            })
        );
    }

    #[test]
    fn rejects_invalid_indices_and_malformed_or_missing_pointers() {
        let task_input = json!({"array":["zero"], "~2":"invalid escape", "~":"dangling escape"});
        for pointer in [
            "array",
            "/array/00",
            "/array/+0",
            "/array/-",
            "/array/1",
            "/~2",
            "/~",
            "/missing",
        ] {
            let step = json!({"input_mapping":{"field":{"task_input":pointer}}});
            let error = materialize(&step, &task_input, &HashMap::new(), 4096).unwrap_err();
            assert_eq!(error.code, "INVALID_ARGUMENT", "{pointer}");
        }
    }

    #[test]
    fn distinguishes_an_unavailable_step_from_a_successful_null_output() {
        let step = json!({"input_mapping":{"field":{"step_output":{"step":"parse","pointer":""}}}});
        let error = materialize(&step, &Value::Null, &HashMap::new(), 4096).unwrap_err();
        assert_eq!(error.code, "INVALID_ARGUMENT");
        let upstream = HashMap::from([("parse".into(), Value::Null)]);
        assert_eq!(
            materialize(&step, &Value::Null, &upstream, 4096).unwrap(),
            json!({"field":null})
        );
    }

    #[test]
    fn caps_repeated_values_by_exact_serialized_size() {
        let task_input = json!({"text":"x".repeat(16 * 1024)});
        let step = json!({"input_mapping": {
            "α": {"task_input":""}, "quoted\"field": {"task_input":""}, "c": {"task_input":""}
        }});
        let expected = json!({"α":task_input, "quoted\"field":task_input, "c":task_input});
        let size = serde_json::to_vec(&expected).unwrap().len();
        let error = materialize(&step, &task_input, &HashMap::new(), size - 1).unwrap_err();
        assert_eq!(error.code, "INVALID_ARGUMENT");
        assert_eq!(error.message, "Workflow step input exceeds its byte limit");
        assert_eq!(
            materialize(&step, &task_input, &HashMap::new(), size).unwrap(),
            expected
        );
    }
}
