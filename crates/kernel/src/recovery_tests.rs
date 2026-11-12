//! Real metadata/authorization checks. These do not prove filesystem recovery or
//! an independent off-host restore.
use super::*;
use crate::{auth::Resource, backups::tests::Fixture, policy::Policy};
use std::net::IpAddr;

const OLD_PASSWORD: &str = "correct horse backup fixture password";
const NEW_PASSWORD: &str = "fresh independent recovery password";

async fn owner(c: &tokio_postgres::Client, backup: Uuid) -> Uuid {
    c.query_one("SELECT created_by FROM backups WHERE id=$1", &[&backup])
        .await
        .unwrap()
        .get(0)
}
async fn gate(c: &tokio_postgres::Client, backup: Uuid) -> Uuid {
    let recovery = Uuid::new_v4();
    c.execute("INSERT INTO platform_recovery_state(recovery_id,backup_id,phase) VALUES($1,$2,'importing')", &[&recovery,&backup]).await.unwrap();
    recovery
}

#[tokio::test]
async fn actual_postgres_reset_rejects_old_authority_and_anchors_only_fresh_owner() {
    use ed25519_dalek::{pkcs8::EncodePublicKey, SigningKey};
    let Some(f) = Fixture::new().await else {
        return;
    };
    let mut c = f.app.db.connect().await.unwrap();
    let owner = owner(&c, f.backup).await;
    let publisher: Uuid = c
        .query_one("SELECT publisher_id FROM installations LIMIT 1", &[])
        .await
        .unwrap()
        .get(0);
    let pem = SigningKey::from_bytes(&[7; 32])
        .verifying_key()
        .to_public_key_pem(Default::default())
        .unwrap();
    c.execute(
        "UPDATE publishers SET public_key_pem=$2 WHERE id=$1",
        &[&publisher, &pem],
    )
    .await
    .unwrap();
    let peer: IpAddr = "127.0.0.1".parse().unwrap();
    let old = f
        .app
        .auth
        .authenticate(&c, &f.token, peer, Uuid::new_v4())
        .await
        .unwrap();
    let child = Uuid::new_v4();
    let archived = Uuid::new_v4();
    let hash = auth::password_hash(OLD_PASSWORD).unwrap();
    c.execute("INSERT INTO accounts(id,parent_id,kind,status,display_name,password_hash,created_at,updated_at) VALUES($1,$2,'user','active','old child',$3,now(),now())", &[&child,&owner,&hash]).await.unwrap();
    c.execute("INSERT INTO accounts(id,kind,status,display_name,independent_owner,password_hash,created_at,updated_at) VALUES($1,'user','archived','archived root',true,$2,now(),now())", &[&archived,&hash]).await.unwrap();
    c.execute("INSERT INTO account_closure(ancestor_id,descendant_id,depth) VALUES($1,$1,0),($2,$1,1),($3,$3,0)", &[&child,&owner,&archived]).await.unwrap();
    c.execute("INSERT INTO inheritance_grants(account_id,parent_id,mode,issuer_credential_id,created_at,updated_at) VALUES($1,$2,'follow_parent',$3,now(),now())", &[&child,&owner,&old.credential]).await.unwrap();
    c.execute("INSERT INTO quotas(account_id,spec,daily_bucket,created_at,updated_at) SELECT $1,spec,current_date,now(),now() FROM quotas WHERE account_id=$2", &[&child,&owner]).await.unwrap();
    c.execute(
        "UPDATE quotas SET daily_calls_used=7,concurrent_calls_used=1",
        &[],
    )
    .await
    .unwrap();
    let child_issued = f
        .app
        .auth
        .login(&c, child, OLD_PASSWORD.into(), peer, Uuid::new_v4())
        .await
        .unwrap();
    let old_child_token = child_issued["access_token"].as_str().unwrap();
    let child_context = f
        .app
        .auth
        .authenticate(&c, old_child_token, peer, Uuid::new_v4())
        .await
        .unwrap();
    let resource = Resource::new("publisher", Uuid::new_v4(), None);
    auth::authorize(&c, &child_context, "publisher.trust", &resource)
        .await
        .unwrap();
    // Stale definitions must not turn a future/removed action into self service.
    c.execute("INSERT INTO permission_definitions(action,resource_kinds,description,self_service) VALUES('retired.unsafe.action','[\"publisher\"]','old definition',true)", &[]).await.unwrap();
    c.execute(
        "UPDATE permission_definitions SET self_service=true WHERE action='publisher.trust'",
        &[],
    )
    .await
    .unwrap();
    c.execute(
        "UPDATE role_definitions SET definition='{\"actions\":[]}' WHERE id='Owner'",
        &[],
    )
    .await
    .unwrap();
    let secret = Uuid::new_v4();
    c.execute("INSERT INTO secrets(id,owner_id,name,encrypted_value,encryption_key_id,status,created_at,updated_at) VALUES($1,$2,'old secret',$3,'snapshot-key','active',now(),now())", &[&secret,&owner,&vec![1u8,2,3]]).await.unwrap();
    c.execute("INSERT INTO secret_bindings(id,deployment_id,secret_id,maximum_lease_seconds,status,created_at,updated_at) SELECT $1,deployment_id,$2,60,'active',now(),now() FROM backups WHERE id=$3", &[&Uuid::new_v4(),&secret,&f.backup]).await.unwrap();
    let workflow = Uuid::new_v4();
    c.execute(
        "INSERT INTO workflows(id,owner_id,name,version,spec,status,created_at,updated_at)
         VALUES($1,$2,'restored schedule workflow',1,'{}','active',now(),now())",
        &[&workflow, &owner],
    )
    .await
    .unwrap();
    let schedule = Uuid::new_v4();
    let legacy_schedule = Uuid::new_v4();
    let deleted_schedule = Uuid::new_v4();
    let proof = Some(json!({"version":1}));
    let schedule_spec = json!({
        "name":"restored schedule","workflow_id":workflow,"cron":"0 12 * * *","input":{}
    });
    let next_fire: chrono::DateTime<chrono::Utc> = c
        .query_one("SELECT now()+interval '1 day'", &[])
        .await
        .unwrap()
        .get(0);
    let task_delegation = Uuid::new_v4();
    for id in [schedule, legacy_schedule, deleted_schedule, task_delegation] {
        c.execute(
            "INSERT INTO execution_delegations
                (id,subject_id,issuer_credential_id,maximum_rules,run_as,expires_at,status,created_at)
             VALUES($1,$2,$3,'[]','user',$4,'active',now())",
            &[&id, &owner, &old.credential, &next_fire],
        )
        .await
        .unwrap();
    }
    for (id, admission, deleted) in [
        (schedule, proof.clone(), false),
        (legacy_schedule, None, false),
        (deleted_schedule, proof.clone(), true),
    ] {
        c.execute(
            "INSERT INTO schedules
                (id,owner_id,spec,delegation_id,admission,next_fire_at,deleted_at,created_at,updated_at)
             VALUES($1,$2,$3,$1,$4,$5,CASE WHEN $6 THEN now() END,now(),now())",
            &[&id, &owner, &schedule_spec, &admission, &next_fire, &deleted],
        )
        .await
        .unwrap();
    }
    let linked_task = Uuid::new_v4();
    c.execute(
        "INSERT INTO tasks(id,owner_id,workflow_id,delegation_id,input,deadline_at,state,created_at,updated_at)
         VALUES($1,$2,$3,$4,'{}',$5,'succeeded',now(),now())",
        &[&linked_task, &owner, &workflow, &task_delegation, &next_fire],
    )
    .await
    .unwrap();
    c.execute(
        "INSERT INTO schedule_fires(schedule_id,scheduled_at,task_id,outcome) VALUES
             ($1,$4::timestamptz-interval '2 hours',$5,'pending'),
             ($1,$4::timestamptz-interval '1 hour',NULL,'skipped'),
             ($1,$4,NULL,'pending'),($2,$4,NULL,'pending'),($3,$4,NULL,'pending')",
        &[
            &schedule,
            &legacy_schedule,
            &deleted_schedule,
            &next_fire,
            &linked_task,
        ],
    )
    .await
    .unwrap();
    assert!(f.app.db.check().await.is_ok());
    let recovery = gate(&c, f.backup).await;
    assert!(f.app.db.check().await.is_err());
    let tx = c.transaction().await.unwrap();
    reset_rows(&tx, owner, NEW_PASSWORD, recovery)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(
        f.app.db.check().await.is_err(),
        "rebuilding must still block startup"
    );
    for (id, expected_fire, expected_revision, expected_admission, pending_outcome) in [
        (schedule, None, 2, proof.clone(), "paused"),
        (legacy_schedule, Some(next_fire), 1, None, "pending"),
        (deleted_schedule, Some(next_fire), 1, proof, "pending"),
    ] {
        let row = c
            .query_one(
                "SELECT s.next_fire_at,s.revision,s.admission,s.spec,e.status,f.outcome
                 FROM schedules s JOIN execution_delegations e ON e.id=s.delegation_id
                 JOIN schedule_fires f ON f.schedule_id=s.id AND f.scheduled_at=$2 WHERE s.id=$1",
                &[&id, &next_fire],
            )
            .await
            .unwrap();
        assert_eq!(
            row.get::<_, Option<chrono::DateTime<chrono::Utc>>>(0),
            expected_fire
        );
        assert_eq!(row.get::<_, i64>(1), expected_revision);
        assert_eq!(row.get::<_, Option<Value>>(2), expected_admission);
        assert_eq!(row.get::<_, Value>(3), schedule_spec);
        assert_eq!(row.get::<_, &str>(4), "revoked");
        assert_eq!(row.get::<_, &str>(5), pending_outcome);
    }
    let history = c
        .query(
            "SELECT task_id,outcome FROM schedule_fires
             WHERE schedule_id=$1 AND scheduled_at<$2 ORDER BY scheduled_at",
            &[&schedule, &next_fire],
        )
        .await
        .unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].get::<_, Option<Uuid>>(0), Some(linked_task));
    assert_eq!(history[0].get::<_, &str>(1), "pending");
    assert_eq!(history[1].get::<_, Option<Uuid>>(0), None);
    assert_eq!(history[1].get::<_, &str>(1), "skipped");
    for token in [&f.token, old_child_token] {
        assert!(f
            .app
            .auth
            .authenticate(&c, token, peer, Uuid::new_v4())
            .await
            .is_err());
    }
    for account in [owner, child] {
        assert!(f
            .app
            .auth
            .login(&c, account, OLD_PASSWORD.into(), peer, Uuid::new_v4())
            .await
            .is_err());
    }
    let row = c
        .query_one(
            "SELECT status,password_hash FROM accounts WHERE id=$1",
            &[&child],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "disabled");
    assert!(row.get::<_, Option<String>>(1).is_none());
    c.execute("UPDATE accounts SET status='active' WHERE id=$1", &[&child])
        .await
        .unwrap();
    assert!(f
        .app
        .auth
        .login(&c, child, OLD_PASSWORD.into(), peer, Uuid::new_v4())
        .await
        .is_err());
    assert_eq!(
        c.query_one("SELECT status FROM accounts WHERE id=$1", &[&archived])
            .await
            .unwrap()
            .get::<_, String>(0),
        "archived"
    );
    let inherited: Value = c.query_one("SELECT maximum_rules FROM inheritance_grants WHERE account_id=$1 AND mode='all_snapshot' AND issuer_credential_id IS NULL", &[&child]).await.unwrap().get(0);
    assert_eq!(inherited, json!([]));
    crate::contracts::validate(
        "Account",
        &identity::account_value(&c, child).await.unwrap(),
    )
    .unwrap();
    assert!(!Policy::new(&c, peer)
        .account(child, 0)
        .await
        .unwrap()
        .iter()
        .any(|path| path.rule["action"] == "publisher.trust"));
    let counts = c.query_one("SELECT count(*) FILTER (WHERE daily_calls_used<>7),count(*) FILTER (WHERE concurrent_calls_used<>0 OR api_keys_used<>0) FROM quotas", &[]).await.unwrap();
    assert_eq!(counts.get::<_, i64>(0), 0);
    assert_eq!(counts.get::<_, i64>(1), 0);
    let reset = c.query_one("SELECT NOT EXISTS(SELECT 1 FROM credentials WHERE status<>'revoked'),NOT EXISTS(SELECT 1 FROM secrets WHERE status<>'revoked'),NOT EXISTS(SELECT 1 FROM secret_bindings WHERE status<>'revoked'),NOT EXISTS(SELECT 1 FROM publishers WHERE status<>'revoked'),NOT EXISTS(SELECT 1 FROM deployment_storage_holds),NOT EXISTS(SELECT 1 FROM permission_definitions WHERE action='retired.unsafe.action'),NOT EXISTS(SELECT 1 FROM deployments WHERE spec->>'enabled'<>'false')", &[]).await.unwrap();
    for i in 0..7 {
        assert!(reset.get::<_, bool>(i));
    }
    let issued = f
        .app
        .auth
        .login(&c, owner, NEW_PASSWORD.into(), peer, Uuid::new_v4())
        .await
        .unwrap();
    let new = f
        .app
        .auth
        .authenticate(
            &c,
            issued["access_token"].as_str().unwrap(),
            peer,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    auth::authorize(&c, &new, "publisher.trust", &resource)
        .await
        .unwrap();
    auth::authorize(
        &c,
        &new,
        "volume.create",
        &Resource::new("volume", Uuid::new_v4(), Some(owner)),
    )
    .await
    .unwrap();
    let fresh: bool = c.query_one("SELECT count(*)>0 AND bool_and(g.created_at>a.created_at AND g.status='active' AND r.recovery_id=$2) FROM recovery_owner_anchors r JOIN grants g ON g.id=r.grant_id JOIN accounts a ON a.id=r.account_id WHERE r.account_id=$1", &[&owner,&recovery]).await.unwrap().get(0);
    assert!(
        fresh,
        "fresh grants must not forge historical creation times"
    );
    // Self-issued grants cannot prove their own authority if the host anchors
    // are absent. The account remains active and its fresh session still works.
    let tx = c.transaction().await.unwrap();
    tx.execute("DELETE FROM recovery_owner_anchors", &[])
        .await
        .unwrap();
    assert!(auth::authorize(&tx, &new, "publisher.trust", &resource)
        .await
        .is_err());
    tx.rollback().await.unwrap();
    auth::authorize(&c, &new, "publisher.trust", &resource)
        .await
        .unwrap();
    // Handler/metadata proof only: this test never promotes the incomplete
    // physical recovery gate to Ready or claims an actual recovered daemon.
    use axum::{
        body::{to_bytes, Body},
        extract::ConnectInfo,
        http::Request,
    };
    use tower::ServiceExt;
    let router = crate::api::router(f.app.clone());
    let body = serde_json::json!({"name":"fixture","key_id":"backup-fixture","public_key_pem":pem});
    for (token, expected) in [
        (&f.token[..], 401u16),
        (issued["access_token"].as_str().unwrap(), 200),
    ] {
        let mut request = Request::builder()
            .header(
                "host",
                crate::plugin_http_gateway::core_authority(&f.app.config).unwrap(),
            )
            .method("POST")
            .uri("/api/platform/v1/publishers")
            .header("authorization", format!("Bearer {token}"))
            .header("idempotency-key", "explicit-recovery-retrust")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:30000".parse::<std::net::SocketAddr>().unwrap(),
        ));
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status().as_u16(), expected);
        if expected == 200 {
            let value: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap())
                    .unwrap();
            assert_eq!(value["id"], serde_json::json!(publisher));
            assert_eq!(value["status"], "trusted");
        }
    }
    assert_eq!(
        c.query_one(
            "SELECT count(*) FROM installations WHERE publisher_id=$1",
            &[&publisher]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    assert_eq!(
        c.query_one(
            "SELECT count(*) FROM deployments WHERE spec->>'enabled'='true'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
}

#[tokio::test]
async fn actual_postgres_reset_requires_importing_gate_fresh_password_and_live_root() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let mut c = f.app.db.connect().await.unwrap();
    let owner = owner(&c, f.backup).await;
    let tx = c.transaction().await.unwrap();
    assert!(reset_rows(&tx, owner, NEW_PASSWORD, Uuid::new_v4())
        .await
        .is_err());
    tx.rollback().await.unwrap();
    let recovery = gate(&c, f.backup).await;
    let tx = c.transaction().await.unwrap();
    assert!(reset_rows(&tx, owner, OLD_PASSWORD, recovery)
        .await
        .is_err());
    tx.rollback().await.unwrap();
    c.execute(
        "UPDATE accounts SET status='archived' WHERE id=$1",
        &[&owner],
    )
    .await
    .unwrap();
    let tx = c.transaction().await.unwrap();
    assert!(reset_rows(&tx, owner, NEW_PASSWORD, recovery)
        .await
        .is_err());
    tx.rollback().await.unwrap();
    c.execute("UPDATE accounts SET status='active' WHERE id=$1", &[&owner])
        .await
        .unwrap();
    let ctx = f
        .app
        .auth
        .authenticate(&c, &f.token, "127.0.0.1".parse().unwrap(), Uuid::new_v4())
        .await
        .unwrap();
    auth::authorize(
        &c,
        &ctx,
        "publisher.trust",
        &Resource::new("publisher", Uuid::new_v4(), None),
    )
    .await
    .unwrap();
    let phase: String = c
        .query_one("SELECT phase FROM platform_recovery_state", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(phase, "importing");
}
