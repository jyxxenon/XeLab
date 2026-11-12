//! Exercised by the real signed OCI HTTP test, never a standalone metadata mock.
use super::*;

mod task_cancel;
pub(super) use task_cancel::cancel_hold_task;

async fn register(
    router: &Router,
    token: &str,
    manifest: &Value,
    installed: &Value,
    index: usize,
) -> String {
    let registered=api(router,"registerSkill",&[],Some(token),
        json!({"installation_id":installed["installation_id"],"definition":manifest["skills"][index]}),
        &format!("http-profile-register-{index}"),None).await;
    assert_eq!(registered.0, 201, "{}", registered.1);
    let id = registered.1["id"].as_str().unwrap().to_owned();
    let enabled = api(
        router,
        "setSkillEnabled",
        &[("skill_id", id.clone())],
        Some(token),
        json!({"enabled":true}),
        &format!("http-profile-enable-{index}"),
        Some(1),
    )
    .await;
    assert_eq!(enabled.0, 200, "{}", enabled.1);
    id
}
async fn stream(
    router: &Router,
    token: &str,
    skill: &str,
    deployment: &str,
    key: &str,
    items: u64,
    interval: u64,
) -> Response {
    request(router,"POST",CORE_HOST,&format!("/api/platform/v1/skills/{skill}/calls:stream"),Some(token),
        serde_json::to_vec(&json!({"input":{"message":"actual signed HTTP Skill stream","items":items,"interval_ms":interval},"timeout_ms":10000,"idempotency_key":key,"provider_deployment_id":deployment})).unwrap(),
        &[("content-type","application/json".into()),("idempotency-key",key.into())]).await
}
fn frames(bytes: &[u8]) -> Vec<Value> {
    let text = std::str::from_utf8(bytes).unwrap();
    let values: Vec<Value> = text
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .map(|data| serde_json::from_str(data).unwrap())
        .collect();
    for (index, value) in values.iter().enumerate() {
        contracts::validate("SkillStreamEvent", value).unwrap();
        assert_eq!(value["event"]["sequence"], index + 1);
    }
    values
}
async fn completed(
    router: &Router,
    token: &str,
    skill: &str,
    deployment: &str,
    key: &str,
) -> Value {
    let response = stream(router, token, skill, deployment, key, 2, 10).await;
    assert_eq!(response.status(), StatusCode::OK);
    let values = frames(&to_bytes(response.into_body(), 4194304).await.unwrap());
    assert_eq!(values.len(), 4);
    assert_eq!(values[0]["event"]["kind"], "accepted");
    assert_eq!(values[1]["event"]["kind"], "item");
    assert_eq!(values[3]["event"]["kind"], "completed");
    assert_eq!(values[3]["skill_id"], skill);
    assert_eq!(values[3]["event"]["payload"]["skill_id"], skill);
    assert_eq!(
        values[3]["event"]["payload"]["skill_definition_digest"],
        values[3]["definition_digest"]
    );
    assert_eq!(
        values[3]["event"]["payload"]["contract"]["schema_digest"],
        values[3]["definition_digest"]
    );
    values[3]["event"]["payload"].clone()
}
pub(super) async fn fixed_methods_and_stream(
    router: &Router,
    app: &App,
    token: &str,
    manifest: &Value,
    installed: &Value,
    deployment: &str,
) -> String {
    for (index, input, output) in [
        (2, Value::Null, json!({"message":"HTTP fixed read"})),
        (
            3,
            json!({"message":"OCI PUT201"}),
            json!({"message":"OCI PUT201"}),
        ),
        (
            4,
            json!({"message":"OCI PATCH"}),
            json!({"message":"OCI PATCH"}),
        ),
        (5, Value::Null, Value::Null),
        (6, Value::Null, Value::Null),
    ] {
        let skill = register(router, token, manifest, installed, index).await;
        let called = api(
            router,
            "invokeSkill",
            &[("skill_id", skill.clone())],
            Some(token),
            json!({"input":input,"provider_deployment_id":deployment}),
            &format!("http-profile-call-{index}"),
            None,
        )
        .await;
        assert_eq!(called.0, 200, "{}", called.1);
        assert_eq!(called.1["call"]["output"], output);
        let (mapping, task_input, task_output, suffix, method, path) = match index {
            3 => {
                let message = json!({"message":"OCI Task PUT201"});
                (
                    json!({"message":{"task_input":"/message"}}),
                    message.clone(),
                    message,
                    "http-put",
                    "PUT",
                    "/plugins/org.xelab.http-echo/created",
                )
            }
            5 => (
                json!({}),
                json!({}),
                Value::Null,
                "http-delete",
                "DELETE",
                "/plugins/org.xelab.http-echo/discard",
            ),
            _ => continue,
        };
        let instance = contracts::id(&called.1["call"], "provider_instance_id").unwrap();
        let input_digest = if method == "DELETE" {
            contracts::digest(b"")
        } else {
            contracts::digest(&serde_json::to_vec(&task_input).unwrap())
        };
        let call = super::oci_task::run(
            app,
            router,
            token,
            super::oci_task::TaskCase {
                skill: skill.parse().unwrap(),
                expected_instance: instance,
                reference_call: contracts::id(&called.1["call"], "call_id").unwrap(),
                input_mapping: mapping,
                input: task_input,
                expected_output: task_output,
                suffix,
            },
        )
        .await;
        let c = app.db.connect().await.unwrap();
        let row = c
            .query_one(
                "SELECT c.http_binding,c.input_digest,i.generation FROM calls c
                 JOIN instances i ON i.id=c.provider_instance_id WHERE c.id=$1",
                &[&call],
            )
            .await
            .unwrap();
        let target = &manifest["skills"][index]["target"];
        assert_eq!(
            row.get::<_, Value>("http_binding"),
            json!({
                "installation_id":installed["installation_id"], "deployment_id":deployment,
                "generation":row.get::<_,i64>("generation"), "required_action":"plugin.http.invoke",
                "http_contract_digest":target["http_contract_digest"], "operation_id":target["http_operation_id"],
                "method":method, "path":path,
            })
        );
        assert_eq!(row.get::<_, String>("input_digest"), input_digest);
    }
    let skill = register(router, token, manifest, installed, 1).await;
    let result = completed(router, token, &skill, deployment, "http-oci-stream-skill").await;
    assert_eq!(result["contract"]["name"], manifest["skills"][1]["name"]);
    let c = app.db.connect().await.unwrap();
    let call = contracts::id(&result, "call_id").unwrap();
    let row = c
        .query_one(
            "SELECT state,result,http_binding FROM calls WHERE id=$1",
            &[&call],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>("state"), "succeeded");
    assert_eq!(row.get::<_, Value>("result"), result);
    assert_eq!(
        row.get::<_, Value>("http_binding")["installation_id"],
        installed["installation_id"]
    );
    let before = c
        .query_one("SELECT count(*) FROM calls", &[])
        .await
        .unwrap()
        .get::<_, i64>(0);
    assert_eq!(
        stream(
            router,
            token,
            &skill,
            deployment,
            "http-oci-stream-skill",
            2,
            10
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        c.query_one("SELECT count(*) FROM calls", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        before
    );
    wait_active(&app.db, 0).await;
    skill
}
pub(super) async fn after_restart_and_live_revoke(
    router: &Router,
    db: &Db,
    token: &str,
    owner: Uuid,
    skill: &str,
    deployment: &str,
) {
    completed(
        router,
        token,
        skill,
        deployment,
        "http-stream-skill-after-controller-restart",
    )
    .await;
    let key=api(router,"createApiKey",&[("account_id",owner.to_string())],Some(token),
        json!({"name":"HTTP Skill streaming original authority","inheritance":{"mode":"selected","rules":[
            {"action":"skill.invoke","resource":{"kind":"skill","match":"ids","ids":[skill]}},
            {"action":"plugin.http.invoke","resource":{"kind":"plugin","match":"ids","ids":["org.xelab.http-echo"]}}
        ]},"conditions":{"expires_at":chrono::Utc::now()+chrono::Duration::days(1)}}),"http-stream-skill-revoke-key",None).await;
    assert_eq!(key.0, 201, "{}", key.1);
    let response = stream(
        router,
        key.1["secret"].as_str().unwrap(),
        skill,
        deployment,
        "http-skill-live-revoke",
        64,
        100,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body().into_data_stream();
    let first = tokio::time::timeout(Duration::from_secs(5), body.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let accepted = frames(&first);
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0]["event"]["kind"], "accepted");
    let call = contracts::id(&accepted[0]["event"], "call_id").unwrap();
    let revoked = api(
        router,
        "revokeApiKey",
        &[(
            "credential_id",
            key.1["credential"]["id"].as_str().unwrap().into(),
        )],
        Some(token),
        Value::Null,
        "http-skill-live-revoke-credential",
        key.1["credential"]["revision"].as_i64(),
    )
    .await;
    assert_eq!(revoked.0, 204, "{}", revoked.1);
    let mut bytes = first.to_vec();
    tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(chunk) = body.next().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
    })
    .await
    .unwrap();
    let values = frames(&bytes);
    assert_eq!(
        values.len(),
        2,
        "No queued item may survive original-credential withdrawal"
    );
    assert_eq!(values[1]["event"]["kind"], "failed");
    assert_eq!(values[1]["event"]["payload"]["code"], "INVALID_CREDENTIAL");
    wait_active(db, 0).await;
    wait_ready(db, deployment).await;
    let c = db.connect().await.unwrap();
    let row = c
        .query_one("SELECT state,result FROM calls WHERE id=$1", &[&call])
        .await
        .unwrap();
    assert_eq!(
        row.get::<_, String>("state"),
        "unknown",
        "A physically fenced non-idempotent HTTP stream must retain its unknown business outcome"
    );
    assert!(row.get::<_, Option<Value>>("result").is_none());
}
