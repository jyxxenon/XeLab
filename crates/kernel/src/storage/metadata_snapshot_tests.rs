//! These round trips use real PostgreSQL COPY, target constraints and policy.
//! They are metadata components, not a whole-platform/off-site acceptance.
use super::*;
use crate::{auth, backups::tests::Fixture, db::Db};

const PASSWORD: &str = "fresh offline metadata restore password";

#[tokio::test]
async fn actual_postgres_oauth_copy_round_trip_resets_families_clients_and_browser_intents() {
    use crate::oauth::{
        authorization, clients,
        tokens::{self, ExchangeOutcome},
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde_json::json;
    use std::collections::HashMap;
    let Some(f) = Fixture::new().await else {
        return;
    };
    let mut source = f.app.db.connect().await.unwrap();
    let ctx = f
        .app
        .auth
        .authenticate(
            &source,
            &f.token,
            "127.0.0.1".parse().unwrap(),
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    let spec = json!({"name":"Snapshot browser client","plugin_id":"org.xelab.webui","redirect_uris":["https://snapshot-ui.example/callback"],"allowed_origins":["https://snapshot-ui.example"],"maximum_rules":[{"action":"account.read","resource":{"kind":"account","match":"ids","ids":[ctx.subject]}}]});
    let (client, _) = clients::execute(
        &source,
        &f.app.auth,
        &ctx,
        "createClient",
        &HashMap::new(),
        &spec,
        &axum::http::HeaderMap::new(),
        "",
    )
    .await
    .unwrap();
    let verifier = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let input = authorization::AuthorizationInput {
        client_id: client["client_id"].as_str().unwrap().into(),
        redirect_uri: "https://snapshot-ui.example/callback".into(),
        state: "snapshot-browser-state".into(),
        code_challenge: URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
        scope: format!("client:{}", client["client_id"].as_str().unwrap()),
    };
    let tx = source.transaction().await.unwrap();
    db::auth_lock(&tx, true).await.unwrap();
    let consent = authorization::begin_authorization(&tx, &f.app.auth, &ctx, &input)
        .await
        .unwrap();
    let authorization::ConsentOutcome::Approved { location } = authorization::decide_consent(
        &tx,
        &f.app.auth,
        &ctx,
        consent.authorization_request_id,
        true,
        &consent.csrf_token,
    )
    .await
    .unwrap() else {
        panic!("approved consent required");
    };
    tx.commit().await.unwrap();
    let code = url::Url::parse(&location)
        .unwrap()
        .query_pairs()
        .find(|(name, _)| name == "code")
        .unwrap()
        .1
        .into_owned();
    let ExchangeOutcome::Token(issued)=tokens::exchange(&f.app.db,&f.app.auth,ctx.peer,Uuid::new_v4(),&json!({"grant_type":"authorization_code","client_id":input.client_id,"redirect_uri":input.redirect_uri,"code":code,"code_verifier":verifier}),Some("https://snapshot-ui.example")).await.unwrap() else { panic!("real OAuth exchange required"); };
    let tx = source.transaction().await.unwrap();
    db::auth_lock(&tx, true).await.unwrap();
    authorization::begin_authorization(&tx, &f.app.auth, &ctx, &input)
        .await
        .unwrap();
    authorization::prepare_login(&tx, &f.app.auth, &input, ctx.peer)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    // Current registration can change after historical authorization. Restore
    // validates the saved binding, and never resurrects that old authority.
    source.execute("UPDATE clients SET spec=jsonb_set(spec,'{redirect_uris}','[\"https://snapshot-ui.example/new-callback\"]'),revision=revision+1",&[]).await.unwrap();
    let mut bytes = Vec::new();
    let summary = export_inner(&mut source, &mut bytes).await.unwrap();
    assert!(db::snapshot_tables().contains(&"oauth_families"));
    assert!(db::snapshot_tables().contains(&"oauth_login_intents"));
    let (target_db, mut destination, recovery) = target(f.backup).await;
    assert!(
        !destination
            .query_one("SELECT EXISTS(SELECT 1 FROM default_ui)", &[])
            .await
            .unwrap()
            .get::<_, bool>(0),
        "migrations must leave an empty restore target empty"
    );
    import_inner(
        &mut destination,
        &mut bytes.as_slice(),
        &summary,
        recovery,
        ctx.subject,
        PASSWORD,
    )
    .await
    .unwrap();
    crate::oauth::snapshot::ensure_authority_reset(&destination)
        .await
        .unwrap();
    assert_eq!(
        destination
            .query_one(
                "SELECT count(*) FROM oauth_families WHERE status='revoked'",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        destination
            .query_one(
                "SELECT count(*) FROM authorization_requests WHERE status='denied'",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert!(f
        .app
        .auth
        .authenticate(
            &destination,
            issued["access_token"].as_str().unwrap(),
            ctx.peer,
            Uuid::new_v4()
        )
        .await
        .is_err());
    target_db.migrate().await.unwrap();
    crate::oauth::snapshot::ensure_authority_reset(&destination)
        .await
        .unwrap();
    assert!(
        target_db.check().await.is_err(),
        "COPY success is not physical recovery readiness"
    );
    // Publication independently refuses each surviving browser trust root.
    destination
        .execute("UPDATE oauth_families SET status='active'", &[])
        .await
        .unwrap();
    assert!(crate::oauth::snapshot::ensure_authority_reset(&destination)
        .await
        .is_err());
    destination
        .execute("UPDATE oauth_families SET status='revoked'", &[])
        .await
        .unwrap();
    destination
        .execute("UPDATE clients SET status='active'", &[])
        .await
        .unwrap();
    assert!(crate::oauth::snapshot::ensure_authority_reset(&destination)
        .await
        .is_err());
    // Invalid frozen source metadata is rejected before a new snapshot exists.
    source
        .execute("UPDATE oauth_families SET fixed_paths='[]'", &[])
        .await
        .unwrap();
    assert!(export_inner(&mut source, &mut Vec::new()).await.is_err());
}

pub(super) async fn target(backup: Uuid) -> (Db, Client, Uuid) {
    let base = std::env::var("XELAB_TEST_DATABASE_URL").unwrap();
    let admin = Db::new(base.clone()).unwrap().connect().await.unwrap();
    let name = format!("metadata_restore_{}", Uuid::new_v4().simple());
    admin
        .batch_execute(&format!("CREATE DATABASE {name}"))
        .await
        .unwrap();
    let db = Db::new(format!("{base} dbname={name}")).unwrap();
    db.migrate().await.unwrap();
    let c = db.connect().await.unwrap();
    let recovery = Uuid::new_v4();
    c.execute("INSERT INTO platform_recovery_state(recovery_id,backup_id,phase) VALUES($1,$2,'importing')",&[&recovery,&backup]).await.unwrap();
    (db, c, recovery)
}
async fn empty(c: &mut Client) {
    let tx = c.transaction().await.unwrap();
    for table in db::snapshot_tables() {
        assert!(
            !tx.query_one(
                &format!("SELECT EXISTS(SELECT 1 FROM {})", relation(table)),
                &[]
            )
            .await
            .unwrap()
            .get::<_, bool>(0),
            "{table} survived a failed import"
        );
    }
    assert!(tx
        .query_one(
            "SELECT phase='importing' AND metadata_summary IS NULL FROM platform_recovery_state",
            &[]
        )
        .await
        .unwrap()
        .get::<_, bool>(0));
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn actual_postgres_snapshot_preserves_bounded_http_contract_but_resets_live_approval() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let mut source = f.app.db.connect().await.unwrap();
    let owner: Uuid = source
        .query_one("SELECT created_by FROM backups WHERE id=$1", &[&f.backup])
        .await
        .unwrap()
        .get(0);
    let publisher = Uuid::new_v4();
    let (_directory, mut manifest, mut raw) =
        crate::http_contracts::tests::fixture_manifest(publisher);
    // Exercise the supported maximum bytea payload. Binary COPY can carry this
    // bounded member without confusing its doubled JSON hex projection for an
    // oversized row; unrelated tables retain their existing row-size checks.
    raw.resize(crate::plugin_http::MAXIMUM_CONTRACT_BYTES, b' ');
    let hash = crate::contracts::digest(&raw);
    for route in manifest["routes"].as_array_mut().unwrap() {
        if route["kind"] == "http" {
            route["http_contract_digest"] = serde_json::json!(hash);
        }
    }
    for skill in manifest["skills"].as_array_mut().unwrap() {
        if skill["target"]["kind"] == "http" {
            skill["target"]["http_contract_digest"] = serde_json::json!(hash);
        }
    }
    let installation = Uuid::new_v4();
    let deployment = Uuid::new_v4();
    source.execute("INSERT INTO publishers(id,name,key_id,public_key_pem,status,created_at,updated_at) VALUES($1,'snapshot HTTP publisher',$2,'component-only','trusted',now(),now())",&[&publisher,&format!("http-{publisher}")]).await.unwrap();
    source.execute("INSERT INTO installations(id,plugin_id,version,publisher_id,image_digest,manifest_digest,manifest,state,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,'installed',now(),now())",&[&installation,&manifest["plugin_id"].as_str().unwrap(),&manifest["version"].as_str().unwrap(),&publisher,&crate::contracts::digest(b"component-only image"),&crate::contracts::digest(&serde_json::to_vec(&manifest).unwrap()),&manifest]).await.unwrap();
    crate::http_contracts::store(&source, installation, &manifest, Some(&raw))
        .await
        .unwrap();
    source.execute("INSERT INTO deployments(id,owner_id,installation_id,spec,phase,created_at,updated_at) VALUES($1,$2,$3,'{\"enabled\":false}','disabled',now(),now())",&[&deployment,&owner,&installation]).await.unwrap();
    let credential: Uuid = source
        .query_one(
            "SELECT id FROM credentials WHERE owner_id=$1 LIMIT 1",
            &[&owner],
        )
        .await
        .unwrap()
        .get(0);
    source.execute("INSERT INTO plugin_http_approvals(deployment_id,credential_id,peer,approval_digest,source_paths) VALUES($1,$2,'127.0.0.1',$3,'[]')",&[&deployment,&credential,&crate::contracts::digest(b"component-only approval")]).await.unwrap();
    let mut bytes = Vec::new();
    let summary = export_inner(&mut source, &mut bytes).await.unwrap();
    let (_, mut destination, recovery) = target(f.backup).await;
    import_inner(
        &mut destination,
        &mut bytes.as_slice(),
        &summary,
        recovery,
        owner,
        PASSWORD,
    )
    .await
    .unwrap();
    let restored = destination
        .query_one(
            "SELECT digest,raw FROM plugin_http_contracts WHERE installation_id=$1",
            &[&installation],
        )
        .await
        .unwrap();
    assert_eq!(restored.get::<_, String>("digest"), hash);
    assert_eq!(restored.get::<_, Vec<u8>>("raw"), raw);
    assert!(crate::http_contracts::load(&destination, installation)
        .await
        .is_ok());
    assert!(!destination
        .query_one("SELECT EXISTS(SELECT 1 FROM plugin_http_approvals)", &[])
        .await
        .unwrap()
        .get::<_, bool>(0));
    assert_eq!(
        destination
            .query_one("SELECT status FROM publishers WHERE id=$1", &[&publisher])
            .await
            .unwrap()
            .get::<_, String>(0),
        "revoked"
    );
    assert_eq!(
        destination
            .query_one(
                "SELECT spec->>'enabled' FROM deployments WHERE id=$1",
                &[&deployment]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        "false"
    );
    assert!(destination
        .execute(
            "DELETE FROM plugin_http_contracts WHERE installation_id=$1",
            &[&installation]
        )
        .await
        .is_err());
}

#[tokio::test]
async fn actual_postgres_snapshot_round_trip_and_late_failure_rollback() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let mut source = f.app.db.connect().await.unwrap();
    let owner: Uuid = source
        .query_one("SELECT created_by FROM backups WHERE id=$1", &[&f.backup])
        .await
        .unwrap()
        .get(0);
    let literal = "snapshot text: '); DROP TABLE accounts; --\n恢复";
    source
        .execute(
            "UPDATE accounts SET display_name=$2 WHERE id=$1",
            &[&owner, &literal],
        )
        .await
        .unwrap();
    // Nontransactional sequence high water exceeds all live project rows and
    // must survive the restore too; it cannot be inferred only from allocations.
    source
        .query_one("SELECT setval('volume_project_ids',9000,true)", &[])
        .await
        .unwrap();
    let mut bytes = Vec::new();
    let summary = export_inner(&mut source, &mut bytes).await.unwrap();
    assert_eq!(summary.bytes, bytes.len() as u64);
    assert!(summary.rows > 0);
    let (db, mut destination, recovery) = target(f.backup).await;
    assert!(db.check().await.is_err());
    let before = foreign_keys(&destination.transaction().await.unwrap())
        .await
        .unwrap();
    let mut corrupt = bytes.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(import_inner(
        &mut destination,
        &mut corrupt.as_slice(),
        &summary,
        recovery,
        owner,
        PASSWORD
    )
    .await
    .is_err());
    empty(&mut destination).await;
    let after = foreign_keys(&destination.transaction().await.unwrap())
        .await
        .unwrap();
    assert_eq!(before, after, "failed import must restore every target FK");
    let mut mismatch = summary.clone();
    mismatch.sha256 = "0".repeat(64);
    assert!(import_inner(
        &mut destination,
        &mut bytes.as_slice(),
        &mismatch,
        recovery,
        owner,
        PASSWORD
    )
    .await
    .is_err());
    empty(&mut destination).await;
    assert!(import_inner(
        &mut destination,
        &mut &bytes[..bytes.len() - 10],
        &summary,
        recovery,
        owner,
        PASSWORD
    )
    .await
    .is_err());
    empty(&mut destination).await;
    let restored = import_inner(
        &mut destination,
        &mut bytes.as_slice(),
        &summary,
        recovery,
        owner,
        PASSWORD,
    )
    .await
    .unwrap();
    assert_eq!(restored, summary);
    assert_eq!(
        destination
            .query_one("SELECT display_name FROM accounts WHERE id=$1", &[&owner])
            .await
            .unwrap()
            .get::<_, String>(0),
        literal
    );
    assert!(
        db.check().await.is_err(),
        "filesystem rebuilding is still outstanding"
    );
    let row = destination
        .query_one(
            "SELECT phase,metadata_summary,recovery_owner_id FROM platform_recovery_state",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "rebuilding");
    assert_eq!(
        row.get::<_, serde_json::Value>(1),
        serde_json::to_value(&summary).unwrap()
    );
    assert_eq!(row.get::<_, Uuid>(2), owner);
    let peer = "127.0.0.1".parse().unwrap();
    assert!(f
        .app
        .auth
        .authenticate(&destination, &f.token, peer, Uuid::new_v4())
        .await
        .is_err());
    let issued = f
        .app
        .auth
        .login(&destination, owner, PASSWORD.into(), peer, Uuid::new_v4())
        .await
        .unwrap();
    let ctx = f
        .app
        .auth
        .authenticate(
            &destination,
            issued["access_token"].as_str().unwrap(),
            peer,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    auth::authorize(
        &destination,
        &ctx,
        "publisher.trust",
        &auth::Resource::new("publisher", Uuid::new_v4(), None),
    )
    .await
    .unwrap();
    let high: i64 = destination
        .query_one("SELECT nextval('volume_project_ids')", &[])
        .await
        .unwrap()
        .get(0);
    assert!(high > 9000);
    assert_eq!(
        foreign_keys(&destination.transaction().await.unwrap())
            .await
            .unwrap(),
        before
    );
    // A completed metadata import cannot be replayed into its nonempty target.
    assert!(import_inner(
        &mut destination,
        &mut bytes.as_slice(),
        &summary,
        recovery,
        owner,
        PASSWORD
    )
    .await
    .is_err());
}

#[tokio::test]
async fn actual_postgres_rejects_incompatible_headers_and_toasted_oversize_rows() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let mut source = f.app.db.connect().await.unwrap();
    let owner: Uuid = source
        .query_one("SELECT created_by FROM backups WHERE id=$1", &[&f.backup])
        .await
        .unwrap()
        .get(0);
    let mut bytes = Vec::new();
    let summary = export_inner(&mut source, &mut bytes).await.unwrap();
    let (_, mut destination, recovery) = target(f.backup).await;
    let size = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
    for change in 0..3 {
        let mut header: Header = serde_json::from_slice(&bytes[12..12 + size]).unwrap();
        match change {
            0 => header.postgres_major += 1,
            1 => header.tables[0].name = "accounts; DROP TABLE accounts; --".into(),
            _ => header.tables[0].columns[0].data_type = "unsupported source type".into(),
        }
        let json = serde_json::to_vec(&header).unwrap();
        let mut altered = Vec::new();
        altered.extend(MAGIC);
        altered.extend((json.len() as u32).to_be_bytes());
        altered.extend(json);
        altered.extend(&bytes[12 + size..]);
        let error = import_inner(
            &mut destination,
            &mut altered.as_slice(),
            &summary,
            recovery,
            owner,
            PASSWORD,
        )
        .await
        .unwrap_err();
        assert_eq!(error.status.as_u16(), 409);
        empty(&mut destination).await;
    }
    let mut oversized_frame = bytes.clone();
    oversized_frame[12 + size..16 + size].copy_from_slice(&((CHUNK + 1) as u32).to_be_bytes());
    assert!(import_inner(
        &mut destination,
        &mut oversized_frame.as_slice(),
        &summary,
        recovery,
        owner,
        PASSWORD
    )
    .await
    .is_err());
    empty(&mut destination).await;
    // pg_column_size alone would accept a huge compressed/toasted value. Bound
    // its expanded representation before the COPY protocol can queue that row.
    source.batch_execute("UPDATE installations SET manifest=jsonb_build_object('oversized',repeat('x',9*1024*1024))").await.unwrap();
    let mut rejected = Vec::new();
    assert!(export_inner(&mut source, &mut rejected).await.is_err());
    assert!(rejected.is_empty());
}

#[tokio::test]
async fn actual_postgres_import_validates_target_foreign_keys_before_commit() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let mut source = f.app.db.connect().await.unwrap();
    let owner: Uuid = source
        .query_one("SELECT created_by FROM backups WHERE id=$1", &[&f.backup])
        .await
        .unwrap()
        .get(0);
    // A structurally valid COPY stream with a broken reference must not commit.
    // The source constraint change never enters the snapshot or the target DDL.
    source
        .batch_execute("ALTER TABLE backups DROP CONSTRAINT backups_created_by_fkey")
        .await
        .unwrap();
    source
        .execute(
            "UPDATE backups SET created_by=$1 WHERE id=$2",
            &[&Uuid::new_v4(), &f.backup],
        )
        .await
        .unwrap();
    let mut bytes = Vec::new();
    let summary = export_inner(&mut source, &mut bytes).await.unwrap();
    let (_, mut destination, recovery) = target(f.backup).await;
    let before = foreign_keys(&destination.transaction().await.unwrap())
        .await
        .unwrap();
    assert!(import_inner(
        &mut destination,
        &mut bytes.as_slice(),
        &summary,
        recovery,
        owner,
        PASSWORD
    )
    .await
    .is_err());
    empty(&mut destination).await;
    assert_eq!(
        foreign_keys(&destination.transaction().await.unwrap())
            .await
            .unwrap(),
        before
    );
}

/// Real COPY of the existing host_rpc_contexts shape with a raw effectful Call
/// (skill_id/http_binding NULL), including its empty-authority query lease.
/// Runtime dispatch deliberately fails here; this is not OCI/off-host evidence.
#[tokio::test]
async fn actual_postgres_raw_effect_proof_and_query_lease_copy_preserves_history_not_authority() {
    use serde_json::{json, Value};
    let Some(f) = Fixture::new().await else {
        return;
    };
    let mut source = f.app.db.connect().await.unwrap();
    let mut ctx = f
        .app
        .auth
        .authenticate(
            &source,
            &f.token,
            "127.0.0.1".parse().unwrap(),
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    let origin = f.app.config.text("server", "public_origin").to_owned();
    ctx.browser_origin = Some(origin.clone());
    let publisher: Uuid = source
        .query_one("SELECT id FROM publishers LIMIT 1", &[])
        .await
        .unwrap()
        .get(0);
    let installation = Uuid::new_v4();
    let deployment = Uuid::new_v4();
    let instance = Uuid::new_v4();
    let mut manifest: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/secret-manifest.json")).unwrap();
    manifest["publisher_id"] = json!(publisher);
    manifest["requested_rules"] = json!([]);
    manifest["capabilities"][0]["side_effect"] = json!("queryable");
    crate::artifact::validate_profile(&manifest).unwrap();
    let cap = &manifest["capabilities"][0];
    let hash = crate::contracts::digest(&serde_json::to_vec(&manifest).unwrap());
    source.execute("INSERT INTO installations(id,plugin_id,version,publisher_id,image_digest,manifest_digest,manifest,state,created_at,updated_at) VALUES($1,$2,'1.0.0',$3,$4,$4,$5,'installed',now(),now())", &[&installation,&manifest["plugin_id"].as_str().unwrap(),&publisher,&hash,&manifest]).await.unwrap();
    let spec = json!({"installation_id":installation,"display_name":"Raw effects COPY metadata","enabled":true,"replicas":1,"limits":manifest["minimum_resources"],"config":{},"volume_ids":[]});
    source.execute("INSERT INTO deployments(id,owner_id,installation_id,spec,phase,created_at,updated_at) VALUES($1,$2,$3,$4,'ready',now(),now())", &[&deployment,&ctx.subject,&installation,&spec]).await.unwrap();
    source.execute("INSERT INTO instances(id,deployment_id,generation,ordinal,phase,health,limits,created_at,updated_at) VALUES($1,$2,1,0,'ready','alive',$3,now(),now())", &[&instance,&deployment,&spec["limits"]]).await.unwrap();
    source
        .execute(
            "INSERT INTO capability_contracts(name,version,schema_digest,spec) VALUES($1,$2,$3,$4)",
            &[
                &cap["contract"]["name"].as_str().unwrap(),
                &cap["contract"]["version"].as_str().unwrap(),
                &cap["contract"]["schema_digest"].as_str().unwrap(),
                cap,
            ],
        )
        .await
        .unwrap();
    source.execute("INSERT INTO provider_records(instance_id,name,version,availability,features,observed_generation,observed_at) VALUES($1,$2,$3,'ready','[]',1,now())", &[&instance,&cap["contract"]["name"].as_str().unwrap(),&cap["contract"]["version"].as_str().unwrap()]).await.unwrap();
    let request = json!({"contract":cap["contract"],"input":{"message":"frozen raw effect"},"provider_deployment_id":deployment,"timeout_ms":10000});
    let failed = crate::broker::invoke_from_http(
        &f.app,
        &f.token,
        ctx.peer,
        Uuid::new_v4(),
        &request,
        "raw-effect-copy",
        None,
        Some(&origin),
    )
    .await
    .unwrap_err();
    let call: Uuid = failed
        .resource_id
        .as_ref()
        .expect("Actual Broker admission required")
        .parse()
        .unwrap();
    let original = source.query_one("SELECT c.skill_id,c.http_binding,c.delegation_id,x.source_paths,x.read_blob_ids,x.browser_origin FROM calls c JOIN host_rpc_contexts x ON x.call_id=c.id WHERE c.id=$1", &[&call]).await.unwrap();
    assert!(original.get::<_, Option<Uuid>>("skill_id").is_none());
    assert!(original.get::<_, Option<Value>>("http_binding").is_none());
    let proof: Value = original.get("source_paths");
    assert!(!proof.as_array().unwrap().is_empty());
    assert_eq!(original.get::<_, Value>("read_blob_ids"), json!([]));
    assert_eq!(
        original.get::<_, Option<String>>("browser_origin"),
        Some(origin.clone())
    );
    let proof_digest = crate::contracts::digest(&serde_jcs::to_vec(&proof).unwrap());
    let delegation: Uuid = original.get::<_, Option<Uuid>>("delegation_id").unwrap();
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "authorization",
        format!("Bearer {}", f.token).parse().unwrap(),
    );
    headers.insert("origin", origin.parse().unwrap());
    let queried = crate::broker_query::get_call(
        &f.app,
        &headers,
        "127.0.0.1:50000".parse().unwrap(),
        Uuid::new_v4(),
        call,
    )
    .await
    .unwrap();
    assert_eq!(queried["state"], "unknown");
    let query_leases:i64=source.query_one("SELECT count(*) FROM rpc_delegations r JOIN execution_delegations e ON e.id=r.execution_delegation_id WHERE r.call_id=$1 AND r.execution_delegation_id<>$2 AND e.maximum_rules='[]'::jsonb AND r.status='revoked' AND e.status='revoked'", &[&call,&delegation]).await.unwrap().get(0);
    assert_eq!(
        query_leases, 1,
        "The real query path must persist and retire its separate empty-authority lease"
    );
    let mut bytes = Vec::new();
    let summary = export_inner(&mut source, &mut bytes).await.unwrap();
    let (target_db, mut destination, recovery) = target(f.backup).await;
    import_inner(
        &mut destination,
        &mut bytes.as_slice(),
        &summary,
        recovery,
        ctx.subject,
        PASSWORD,
    )
    .await
    .unwrap();
    let saved = destination.query_one("SELECT c.state,c.skill_id,c.http_binding,c.delegation_id,x.source_paths,x.read_blob_ids,x.browser_origin FROM calls c JOIN host_rpc_contexts x ON x.call_id=c.id WHERE c.id=$1", &[&call]).await.unwrap();
    assert_eq!(saved.get::<_, String>("state"), "unknown");
    assert!(saved.get::<_, Option<Uuid>>("skill_id").is_none());
    assert!(saved.get::<_, Option<Value>>("http_binding").is_none());
    assert_eq!(
        saved.get::<_, Option<Uuid>>("delegation_id"),
        Some(delegation)
    );
    let saved_proof: Value = saved.get("source_paths");
    assert_eq!(saved_proof, proof);
    assert_eq!(
        crate::contracts::digest(&serde_jcs::to_vec(&saved_proof).unwrap()),
        proof_digest
    );
    assert_eq!(saved.get::<_, Value>("read_blob_ids"), json!([]));
    assert_eq!(
        saved.get::<_, Option<String>>("browser_origin"),
        ctx.browser_origin
    );
    assert_eq!(
        destination
            .query_one(
                "SELECT count(*) FROM rpc_delegations WHERE call_id=$1 AND status='active'",
                &[&call]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert!(f
        .app
        .auth
        .authenticate(&destination, &f.token, ctx.peer, Uuid::new_v4())
        .await
        .is_err());
    assert!(
        crate::host_blobs::check_call_sources(&destination, &ctx, call)
            .await
            .is_err(),
        "Historical proof cannot revive revoked original credentials after restore"
    );
    target_db.migrate().await.unwrap();
    assert!(
        target_db.check().await.is_err(),
        "Metadata COPY is not physical recovery readiness"
    );
}

#[tokio::test]
async fn actual_postgres_schedule_plugin_and_batch_history_copy_resets_execution_authority() {
    use serde_json::{json, Value};
    use std::collections::HashMap;

    // A created schedule fire points to a Task admitted through the normal
    // Workflow and Task handlers. The Task journal has its own round-trip test.
    let Some(f) = Fixture::new().await else {
        return;
    };
    let mut source = f.app.db.connect().await.unwrap();
    let ctx = f
        .app
        .auth
        .authenticate(
            &source,
            &f.token,
            "127.0.0.1".parse().unwrap(),
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    let owner = ctx.subject;
    let delegation = Uuid::new_v4();
    let schedule = Uuid::new_v4();
    let micro = Uuid::new_v4();
    let extension = Uuid::new_v4();
    let installation = Uuid::new_v4();
    let skill = Uuid::new_v4();
    let batch = Uuid::new_v4();
    source
        .execute(
            "INSERT INTO execution_delegations(id,subject_id,issuer_credential_id,maximum_rules,run_as,expires_at,status,created_at)
             VALUES($1,$2,$3,'[]','user',now()+interval '1 hour','active',now())",
            &[&delegation, &owner, &ctx.credential],
        )
        .await
        .unwrap();
    source
        .execute("INSERT INTO micro_plugins(id,owner_id,name,display_name,status,created_at,updated_at) VALUES($1,$2,'snapshot-micro','snapshot micro','active',now(),now())",&[&micro,&owner])
        .await
        .unwrap();
    source
        .execute("INSERT INTO extension_plugins(id,owner_id,name,display_name,status,created_at,updated_at) VALUES($1,$2,'snapshot-extension','snapshot extension','active',now(),now())",&[&extension,&owner])
        .await
        .unwrap();
    let mut manifest: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/secret-manifest.json")).unwrap();
    let publisher: Uuid = source
        .query_one("SELECT id FROM publishers ORDER BY id LIMIT 1", &[])
        .await
        .unwrap()
        .get(0);
    manifest["publisher_id"] = serde_json::json!(publisher);
    let cap = manifest["capabilities"][0].clone();
    let definition = serde_json::json!({"name":"org.xelab.echo-python.echo","version":"1.0.0","description":"Echo a bounded message","input_schema":cap["input_schema"],"output_schema":cap["output_schema"],"stream_item_schema":cap["stream_item_schema"],"target":{"kind":"capability","plugin_id":manifest["plugin_id"],"contract":cap["contract"]},"mapping":"identity","maximum_timeout_ms":30000,"input_blobs":false,"tags":[]});
    manifest["skills"] = serde_json::json!([definition]);
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let hash = crate::contracts::digest(&manifest_bytes);
    let plugin_id = manifest["plugin_id"].as_str().unwrap().to_owned();
    let plugin_version = manifest["version"].as_str().unwrap().to_owned();
    source
        .execute("INSERT INTO installations(id,plugin_id,version,publisher_id,image_digest,manifest_digest,manifest,state,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$5,$6,'installed',now(),now())", &[&installation,&plugin_id,&plugin_version,&publisher,&hash,&manifest])
        .await
        .unwrap();
    let contract = &cap["contract"];
    let contract_name = contract["name"].as_str().unwrap().to_owned();
    let contract_version = contract["version"].as_str().unwrap().to_owned();
    let contract_digest = contract["schema_digest"].as_str().unwrap().to_owned();
    source
        .execute(
            "INSERT INTO capability_contracts(name,version,schema_digest,spec) VALUES($1,$2,$3,$4)",
            &[&contract_name, &contract_version, &contract_digest, &cap],
        )
        .await
        .unwrap();
    let definition_hash = crate::skills::definition_digest(&definition).unwrap();
    let definition_name = definition["name"].as_str().unwrap().to_owned();
    source
        .execute("INSERT INTO skills(id,name,version,installation_id,created_by,definition,definition_digest,enabled,created_at,updated_at) VALUES($1,$2,'1.0.0',$3,$4,$5,$6,true,now(),now())", &[&skill,&definition_name,&installation,&owner,&definition,&definition_hash])
        .await
        .unwrap();

    let tx = source.transaction().await.unwrap();
    db::auth_lock(&tx, false).await.unwrap();
    let params = HashMap::new();
    let (workflow, status) = crate::workflows::execute(
        &tx,
        &f.app.auth,
        &ctx,
        "createWorkflow",
        &params,
        &json!({"name":"snapshot-scheduled-workflow","input_schema":{"type":"object"},"steps":[{
            "id":"echo","contract":contract,"depends_on":[],"timeout_ms":30000,
            "input_mapping":{"message":{"task_input":"/message"}}
        }]}),
        &axum::http::HeaderMap::new(),
        "",
    )
    .await
    .unwrap();
    assert_eq!(status, 201);
    let workflow = crate::contracts::id(&workflow, "id").unwrap();
    let input = json!({"message":"scheduled snapshot input"});
    let (task, status) = crate::tasks::execute(
        &tx,
        &f.app.auth,
        &ctx,
        "createTask",
        &params,
        &json!({"workflow_id":workflow,"input":input}),
        "",
    )
    .await
    .unwrap();
    assert_eq!(status, 201);
    let task = crate::contracts::id(&task, "id").unwrap();
    tx.commit().await.unwrap();

    let schedule_spec = json!({"name":"snapshot schedule","workflow_id":workflow,
        "cron":"0 0 * * *","timezone":"Etc/UTC","input":input});
    crate::contracts::validate("ScheduleSpec", &schedule_spec).unwrap();
    source
        .execute(
            "INSERT INTO schedules(id,owner_id,spec,delegation_id,next_fire_at,created_at,updated_at)
             VALUES($1,$2,$3,$4,date_trunc('day',now(),'UTC')+interval '24 hours',now(),now())",
            &[&schedule, &owner, &schedule_spec, &delegation],
        )
        .await
        .unwrap();
    source
        .execute(
            "INSERT INTO schedule_fires(schedule_id,scheduled_at,task_id,outcome)
             SELECT id,next_fire_at-interval '24 hours',$2,'created' FROM schedules WHERE id=$1",
            &[&schedule, &task],
        )
        .await
        .unwrap();
    source
        .execute("INSERT INTO skill_batches(id,owner_id,subject_id,delegation_id,skill_id,installation_id,definition_digest,state,request_spec,counts,total_items,max_parallel,failure_policy,run_as,deadline_at,created_at,updated_at) VALUES($1,$2,$2,$3,$4,$5,$6,'queued','{}','{\"queued\":1}'::jsonb,1,1,'stop','user',now()+interval '1 hour',now(),now())",&[&batch,&owner,&delegation,&skill,&installation,&definition_hash])
        .await
        .unwrap();
    let input_bytes = serde_json::to_vec(&input).unwrap();
    let input_digest = crate::contracts::digest(&input_bytes);
    source
        .execute(
            "INSERT INTO skill_batch_items(batch_id,item_id,item_index,input,input_digest,input_bytes,idempotency_key,state)
             VALUES($1,'1',0,$2,$3,$4,'snapshot-item-key','queued')",
            &[&batch, &input, &input_digest, &(input_bytes.len() as i64)],
        )
        .await
        .unwrap();
    let mut bytes = Vec::new();
    let summary = export_inner(&mut source, &mut bytes).await.unwrap();
    let (db, mut destination, recovery) = target(f.backup).await;
    assert!(db.check().await.is_err());
    let restored = import_inner(
        &mut destination,
        &mut bytes.as_slice(),
        &summary,
        recovery,
        owner,
        PASSWORD,
    )
    .await
    .unwrap();
    assert_eq!(restored, summary);
    let saved_schedule = destination
        .query_one(
            "SELECT s.spec,f.task_id,f.outcome,e.status
             FROM schedules s JOIN schedule_fires f ON f.schedule_id=s.id
             JOIN execution_delegations e ON e.id=s.delegation_id WHERE s.id=$1",
            &[&schedule],
        )
        .await
        .unwrap();
    assert_eq!(saved_schedule.get::<_, Value>(0), schedule_spec);
    assert_eq!(saved_schedule.get::<_, Uuid>(1), task);
    assert_eq!(saved_schedule.get::<_, &str>(2), "created");
    assert_eq!(saved_schedule.get::<_, &str>(3), "revoked");
    for (table, id, name) in [
        ("micro_plugins", micro, "snapshot-micro"),
        ("extension_plugins", extension, "snapshot-extension"),
    ] {
        let row = destination
            .query_one(
                &format!("SELECT name,status FROM {table} WHERE id=$1"),
                &[&id],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, &str>(0), name);
        assert_eq!(row.get::<_, &str>(1), "active");
    }
    let saved_batch = destination
        .query_one(
            "SELECT b.state,b.skill_id,b.definition_digest,i.state,i.input,i.input_digest,e.status
             FROM skill_batches b JOIN skill_batch_items i ON i.batch_id=b.id
             JOIN execution_delegations e ON e.id=b.delegation_id
             WHERE b.id=$1 AND i.item_id='1'",
            &[&batch],
        )
        .await
        .unwrap();
    assert_eq!(saved_batch.get::<_, &str>(0), "queued");
    assert_eq!(saved_batch.get::<_, Uuid>(1), skill);
    assert_eq!(saved_batch.get::<_, String>(2), definition_hash);
    assert_eq!(saved_batch.get::<_, &str>(3), "queued");
    assert_eq!(saved_batch.get::<_, Value>(4), input);
    assert_eq!(saved_batch.get::<_, String>(5), input_digest);
    assert_eq!(saved_batch.get::<_, &str>(6), "revoked");
}
