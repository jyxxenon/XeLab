use crate::error::{Error, Result};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

// Called after the WorkflowSpec schema has validated the shape of each step.
pub(super) fn validate_graph(spec: &Value) -> Result<()> {
    let steps = spec["steps"].as_array().unwrap();
    let mut step_indexes = HashMap::with_capacity(steps.len());
    for (index, step) in steps.iter().enumerate() {
        let id = step["id"].as_str().unwrap();
        if step_indexes.insert(id, index).is_some() {
            return Err(Error::invalid("Workflow step IDs must be unique"));
        }
    }

    let mut dependents = vec![Vec::new(); steps.len()];
    let mut remaining = vec![0; steps.len()];
    let mut ready = Vec::new();
    for (index, step) in steps.iter().enumerate() {
        let dependencies = step["depends_on"].as_array().unwrap();
        remaining[index] = dependencies.len();
        if dependencies.is_empty() {
            ready.push(index);
        }
        for dependency in dependencies {
            let dependency_id = dependency.as_str().unwrap();
            let upstream = step_indexes
                .get(dependency_id)
                .ok_or_else(|| Error::invalid("Workflow step has an unknown dependency"))?;
            dependents[*upstream].push(index);
        }
    }

    let mut ancestors = vec![HashSet::new(); steps.len()];
    let mut visited = 0;
    while let Some(index) = ready.pop() {
        let mut upstream = std::mem::take(&mut ancestors[index]);
        validate_mapping(&steps[index], &step_indexes, &upstream)?;
        upstream.insert(index);
        for &dependent in &dependents[index] {
            ancestors[dependent].extend(upstream.iter().copied());
            remaining[dependent] -= 1;
            if remaining[dependent] == 0 {
                ready.push(dependent);
            }
        }
        visited += 1;
    }
    if visited != steps.len() {
        return Err(Error::invalid("Workflow dependencies contain a cycle"));
    }
    Ok(())
}

fn validate_mapping(
    step: &Value,
    step_indexes: &HashMap<&str, usize>,
    ancestors: &HashSet<usize>,
) -> Result<()> {
    for leaf in step["input_mapping"].as_object().unwrap().values() {
        if let Some(pointer) = leaf.get("task_input") {
            validate_pointer(pointer.as_str().unwrap())?;
        }
        if let Some(output) = leaf.get("step_output") {
            let source = output["step"].as_str().unwrap();
            if !step_indexes
                .get(source)
                .is_some_and(|index| ancestors.contains(index))
            {
                return Err(Error::invalid(
                    "Workflow step output must reference a direct or transitive dependency",
                ));
            }
            validate_pointer(output["pointer"].as_str().unwrap())?;
        }
    }
    Ok(())
}

fn validate_pointer(pointer: &str) -> Result<()> {
    const INVALID_POINTER: &str = "Workflow input mapping requires an RFC 6901 JSON Pointer";
    if !pointer.is_empty() && !pointer.starts_with('/') {
        return Err(Error::invalid(INVALID_POINTER));
    }
    let mut bytes = pointer.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'~' && !matches!(bytes.next(), Some(b'0' | b'1')) {
            return Err(Error::invalid(INVALID_POINTER));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::contracts::validate;
    use serde_json::{json, Value};

    fn step(id: &str, depends_on: &[&str], mapping: Value) -> Value {
        json!({
            "id": id,
            "depends_on": depends_on,
            "input_mapping": mapping,
            "skill_id": "00000000-0000-4000-8000-000000000001",
            "timeout_ms": 100,
        })
    }

    fn spec(steps: Vec<Value>) -> Value {
        json!({ "name": "workflow", "input_schema": {}, "steps": steps })
    }

    fn assert_invalid(workflow: &Value, message: &str) {
        let error = validate("WorkflowSpec", workflow).unwrap_err();
        assert_eq!(error.status.as_u16(), 400);
        assert_eq!(error.code, "INVALID_ARGUMENT");
        assert_eq!(error.message, message);
    }

    #[test]
    fn accepts_forward_dependencies_and_mappings_from_all_upstream_branches() {
        let workflow = spec(vec![
            step(
                "join",
                &["middle", "other"],
                json!({
                    "direct": {"step_output": {"step": "middle", "pointer": ""}},
                    "transitive": {"step_output": {"step": "first", "pointer": "/a~1b/~0/中文//"}},
                    "other_branch": {"step_output": {"step": "other", "pointer": "/value"}},
                    "input": {"task_input": ""},
                    "literal": {"literal": {"task_input": "opaque", "step_output": null}},
                }),
            ),
            step("middle", &["first", "first"], json!({})),
            step("other", &[], json!({})),
            step("first", &[], json!({})),
        ]);
        validate("WorkflowSpec", &workflow).unwrap();
    }

    #[test]
    fn rejects_duplicate_ids_and_unknown_dependencies() {
        assert_invalid(
            &spec(vec![step("a", &[], json!({})), step("a", &[], json!({}))]),
            "Workflow step IDs must be unique",
        );
        assert_invalid(
            &spec(vec![step("a", &["missing"], json!({}))]),
            "Workflow step has an unknown dependency",
        );
    }

    #[test]
    fn rejects_self_cycles_and_cycles_disconnected_from_roots() {
        for steps in [
            vec![step("a", &["a"], json!({}))],
            vec![
                step("root", &[], json!({})),
                step("a", &["b"], json!({})),
                step("b", &["a"], json!({})),
            ],
        ] {
            assert_invalid(&spec(steps), "Workflow dependencies contain a cycle");
        }
    }

    #[test]
    fn rejects_step_outputs_from_outside_the_dependency_chain() {
        for source in ["missing", "current", "sibling", "downstream"] {
            let workflow = spec(vec![
                step("upstream", &[], json!({})),
                step("sibling", &["upstream"], json!({})),
                step("downstream", &["current"], json!({})),
                step(
                    "current",
                    &["upstream"],
                    json!({"value": {"step_output": {"step": source, "pointer": "/value"}}}),
                ),
            ]);
            assert_invalid(
                &workflow,
                "Workflow step output must reference a direct or transitive dependency",
            );
        }
    }

    #[test]
    fn rejects_malformed_pointers_in_both_mapping_branches() {
        for pointer in ["value", "#/value", "/value~", "/bad~2value", "/bad~~0"] {
            for leaf in [
                json!({"task_input": pointer}),
                json!({"step_output": {"step": "root", "pointer": pointer}}),
            ] {
                let workflow = spec(vec![
                    step("root", &[], json!({})),
                    step("child", &["root"], json!({"value": leaf})),
                ]);
                assert_invalid(
                    &workflow,
                    "Workflow input mapping requires an RFC 6901 JSON Pointer",
                );
            }
        }
    }

    #[test]
    fn validates_graphs_up_to_the_existing_step_limit() {
        let mut steps = vec![step("root", &[], json!({}))];
        let mut upstream = "root".to_owned();
        for index in 1..64 {
            let id = format!("step{index}");
            steps.push(step(
                &id,
                &[&upstream],
                json!({"value": {"step_output": {"step": "root", "pointer": "/value"}}}),
            ));
            upstream = id;
        }
        validate("WorkflowSpec", &spec(steps.clone())).unwrap();
        steps.push(step("extra", &[&upstream], json!({})));
        for steps in [steps, vec![]] {
            assert_invalid(&spec(steps), "Value does not match the existing contract");
        }
    }
}
