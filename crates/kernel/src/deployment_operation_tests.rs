//! Actual HTTP/PostgreSQL contract checks. Installation/observations here are
//! metadata fixtures, not OCI health or runtime stop proofs.
use super::*;
use crate::{backups::tests::Fixture, contracts::validate};
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::Request,
};
use tower::ServiceExt;

#[tokio::test]
async fn inactive_sweep_selects_historical_runtime_markers_until_stop_is_confirmed() {
    let Some(mut f) = Fixture::new().await else {
        return;
    };
    let app = Arc::get_mut(&mut f.app).unwrap();
    let mut config = app.config.value.clone();
    config["runtime"]["socket"] = json!(app.config.root().join("missing-fixture-containerd.sock"));
    app.config = crate::config::Config::from_value(config).unwrap();
    app.runtime = crate::runtime::Runtime::new(app.config.clone());
    let c = app.db.connect().await.unwrap();
    let deployment: Uuid = c
        .query_one("SELECT id FROM deployments", &[])
        .await
        .unwrap()
        .get(0);
    c.execute(
        "DELETE FROM deployment_storage_holds WHERE deployment_id=$1",
        &[&deployment],
    )
    .await
    .unwrap();
    let instance = Uuid::new_v4();
    c.execute("INSERT INTO instances(id,deployment_id,generation,ordinal,phase,health,limits,runtime_id,created_at,updated_at) VALUES($1,$2,1,0,'stopped','unknown','{}',$3,now(),now())", &[&instance,&deployment,&instance.to_string()]).await.unwrap();
    let rows = deployment_page(&c, &mut Sweep::default(), false)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<_, Uuid>("id"), deployment);

    // The fixture has no containerd on its private socket, so no physical
    // stop proof can be obtained. The old marker must survive that failure.
    let error = reconcile(app, deployment, &mut BTreeMap::new())
        .await
        .unwrap_err();
    assert_eq!(error.code, "NOT_READY");
    let retained: Option<String> = c
        .query_one("SELECT runtime_id FROM instances WHERE id=$1", &[&instance])
        .await
        .unwrap()
        .get(0);
    assert_eq!(retained, Some(instance.to_string()));
    assert_eq!(
        deployment_page(&c, &mut Sweep::default(), false)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn actual_postgres_deployment_operations_return_complete_objects_and_respect_intent() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let c = f.app.db.connect().await.unwrap();
    let installed = c
        .query_one("SELECT id,publisher_id FROM installations LIMIT 1", &[])
        .await
        .unwrap();
    let installation: Uuid = installed.get(0);
    let mut manifest: Value =
        serde_json::from_str(include_str!("../tests/fixtures/secret-manifest.json")).unwrap();
    manifest["publisher_id"] = json!(installed.get::<_, Uuid>(1));
    manifest["requested_rules"] = json!([]);
    c.execute(
        "UPDATE installations SET plugin_id='org.xelab.echo-python',manifest=$2 WHERE id=$1",
        &[&installation, &manifest],
    )
    .await
    .unwrap();
    let spec = json!({"installation_id":installation,"display_name":"operation result contract","enabled":false,"limits":manifest["minimum_resources"],"config":{},"volume_ids":[]});
    let request = Request::builder()
        .header(
            "host",
            crate::plugin_http_gateway::core_authority(&f.app.config).unwrap(),
        )
        .method("POST")
        .uri("/api/platform/v1/deployments")
        .header("authorization", format!("Bearer {}", f.token))
        .header("content-type", "application/json")
        .header("idempotency-key", "complete-deployment-operation");
    let mut request = request
        .body(Body::from(serde_json::to_vec(&spec).unwrap()))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:30000".parse::<std::net::SocketAddr>().unwrap(),
    ));
    let response = crate::api::router(f.app.clone())
        .oneshot(request)
        .await
        .unwrap();
    assert_eq!(response.status(), 202);
    let created: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4194304).await.unwrap()).unwrap();
    assert_eq!(created["state"], "succeeded");
    validate("Deployment", &created["result"]).unwrap();
    assert_eq!(created["result"]["id"], created["resource_id"]);
    assert_eq!(created["result"]["spec"]["replicas"], 1);
    assert_eq!(created["result"]["phase"], "disabled");
    let deployment: Uuid = created["resource_id"].as_str().unwrap().parse().unwrap();
    let owner: Uuid = c
        .query_one(
            "SELECT owner_id FROM deployments WHERE id=$1",
            &[&deployment],
        )
        .await
        .unwrap()
        .get(0);
    for enabled in [true, false] {
        let operation = db::operation(
            &c,
            owner,
            "setDeploymentEnabled",
            Some(deployment.to_string()),
        )
        .await
        .unwrap();
        // The previous opposite intent must not complete this observation.
        finish_deployment_operations(&c, deployment, enabled)
            .await
            .unwrap();
        assert_eq!(
            db::operation_value(&c, operation).await.unwrap()["state"],
            "pending"
        );
        let phase = if enabled { "ready" } else { "disabled" };
        c.execute("UPDATE deployments SET spec=jsonb_set(spec,'{enabled}',$2),phase=$3,observed_generation=3,revision=revision+1,updated_at=now() WHERE id=$1", &[&deployment,&json!(enabled),&phase]).await.unwrap();
        finish_deployment_operations(&c, deployment, enabled)
            .await
            .unwrap();
        let completed = db::operation_value(&c, operation).await.unwrap();
        assert_eq!(completed["state"], "succeeded");
        validate("Deployment", &completed["result"]).unwrap();
        assert_eq!(
            completed["result"],
            crate::api::read_object(&c, "deployments", deployment, "Deployment")
                .await
                .unwrap()
        );
        assert_eq!(completed["result"]["spec"]["enabled"], enabled);
        assert_eq!(completed["result"]["observed_generation"], 3);
        assert_eq!(completed["result"]["phase"], phase);
        finish_deployment_operations(&c, deployment, !enabled)
            .await
            .unwrap();
        assert_eq!(
            db::operation_value(&c, operation).await.unwrap(),
            completed,
            "late observations cannot rewrite a terminal result"
        );
    }
}
