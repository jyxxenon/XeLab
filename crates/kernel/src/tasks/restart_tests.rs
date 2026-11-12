//! PostgreSQL migration and recovery authority regression.
use super::{create, revoke_transient_delegations};
use crate::{auth, contracts, db, recovery};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use std::{fs, path::Path};
use tokio_postgres::Client;
use uuid::Uuid;

const LAST_PRE_TASK_ADMISSION: i64 = 19;
const OLD_PASSWORD: &str = "correct horse task fixture password";
const NEW_PASSWORD: &str = "fresh independent task recovery password";

async fn install_v19(c: &Client) {
    let mut sql = vec![(1, db::BASELINE.to_owned())];
    let migrations = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    for entry in fs::read_dir(migrations).unwrap() {
        let file = entry.unwrap().path();
        let Some(version) = file
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.split_once('_'))
            .and_then(|(version, _)| version.parse::<i64>().ok())
            .filter(|version| *version <= LAST_PRE_TASK_ADMISSION)
        else {
            continue;
        };
        sql.push((version, fs::read_to_string(file).unwrap()));
    }
    sql.sort_unstable_by_key(|(version, _)| *version);
    assert_eq!(
        sql.iter().map(|(version, _)| *version).collect::<Vec<_>>(),
        (1..=LAST_PRE_TASK_ADMISSION).collect::<Vec<_>>()
    );
    for (version, sql) in sql {
        c.batch_execute(&sql).await.unwrap();
        c.execute(
            "INSERT INTO schema_migrations(version,checksum,applied_at) VALUES($1,$2,now())",
            &[&version, &contracts::digest(sql.as_bytes())],
        )
        .await
        .unwrap();
    }
}

async fn migration_history(c: &Client) -> Vec<(i64, String, DateTime<Utc>)> {
    c.query(
        "SELECT version,checksum,applied_at FROM schema_migrations ORDER BY version",
        &[],
    )
    .await
    .unwrap()
    .iter()
    .map(|row| (row.get(0), row.get(1), row.get(2)))
    .collect()
}

async fn delegation_status(c: &Client, delegation: Uuid) -> String {
    c.query_one(
        "SELECT status FROM execution_delegations WHERE id=$1",
        &[&delegation],
    )
    .await
    .unwrap()
    .get(0)
}

#[tokio::test]
async fn actual_postgres_task_migration_preserves_history_and_restart_distinguishes_authority() {
    let Ok(base) = std::env::var("XELAB_TEST_DATABASE_URL") else {
        eprintln!("SKIPPED: Task restart and migration require PostgreSQL");
        return;
    };
    let name = format!("task_restart_{}", Uuid::new_v4().simple());
    let admin = db::Db::new(base.clone()).unwrap().connect().await.unwrap();
    admin
        .batch_execute(&format!("CREATE DATABASE {name}"))
        .await
        .unwrap();
    let database = db::Db::new(format!("{base} dbname={name}")).unwrap();
    let mut c = database.connect().await.unwrap();
    install_v19(&c).await;
    let before = migration_history(&c).await;
    assert_eq!(before.len(), LAST_PRE_TASK_ADMISSION as usize);
    assert!(database.check().await.is_err());

    let quota = json!({"maximum_depth":4,"maximum_descendants":20,"maximum_api_keys":50,"maximum_concurrent_calls":16,"daily_calls":10000});
    let tx = c.transaction().await.unwrap();
    let owner = auth::bootstrap(&tx, "Task restart owner", OLD_PASSWORD, &quota)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let contract = json!({
        "name":"tool.echo", "version":"1.0.0",
        "schema_digest":contracts::digest(b"Task restart fixture contract")
    });
    let workflow = Uuid::new_v4();
    let spec = json!({"name":"restart-test","input_schema":{"type":"object"},"steps":[{
        "id":"echo", "depends_on":[], "timeout_ms":100, "input_mapping":{}, "contract":contract
    }]});
    c.execute("INSERT INTO workflows(id,owner_id,name,version,spec,status,created_at,updated_at) VALUES($1,$2,'restart-test',1,$3,'active',now(),now())", &[&workflow,&owner,&spec]).await.unwrap();
    let historical_delegation = Uuid::new_v4();
    let transient_delegation = Uuid::new_v4();
    c.execute("INSERT INTO execution_delegations(id,subject_id,maximum_rules,run_as,expires_at,status,created_at) VALUES($1,$3,'[]','user',now()+interval '1 hour','active',now()),($2,$3,'[]','user',now()+interval '1 hour','active',now())", &[&historical_delegation,&transient_delegation,&owner]).await.unwrap();
    let historical_task = Uuid::new_v4();
    c.execute("INSERT INTO tasks(id,owner_id,workflow_id,delegation_id,input,deadline_at,state,created_at,updated_at) VALUES($1,$2,$3,$4,'{\"legacy\":true}',now()+interval '1 hour','queued',now(),now())", &[&historical_task,&owner,&workflow,&historical_delegation]).await.unwrap();
    let historical_step = Uuid::new_v4();
    c.execute("INSERT INTO task_steps(id,task_id,step_key,state,created_at,updated_at) VALUES($1,$2,'echo','ready',now(),now())", &[&historical_step,&historical_task]).await.unwrap();
    let old_task: Value = c
        .query_one(
            "SELECT to_jsonb(t) FROM tasks t WHERE id=$1",
            &[&historical_task],
        )
        .await
        .unwrap()
        .get(0);
    let old_step: Value = c
        .query_one(
            "SELECT to_jsonb(t) FROM task_steps t WHERE id=$1",
            &[&historical_step],
        )
        .await
        .unwrap()
        .get(0);

    database.migrate().await.unwrap();
    database.migrate().await.unwrap();
    database.check().await.unwrap();
    let after = migration_history(&c).await;
    assert_eq!(&after[..before.len()], &before);
    assert_eq!(after.len(), db::SCHEMA_VERSION as usize);
    assert_eq!(after[before.len()].0, LAST_PRE_TASK_ADMISSION + 1);
    let migrated = c
        .query_one(
            "SELECT to_jsonb(t)-'admission',admission IS NULL FROM tasks t WHERE id=$1",
            &[&historical_task],
        )
        .await
        .unwrap();
    assert_eq!(migrated.get::<_, Value>(0), old_task);
    assert!(migrated.get::<_, bool>(1));
    assert_eq!(
        c.query_one(
            "SELECT to_jsonb(t) FROM task_steps t WHERE id=$1",
            &[&historical_step]
        )
        .await
        .unwrap()
        .get::<_, Value>(0),
        old_step
    );

    // Admit a new stateless capability Task without invoking a provider.
    let publisher = Uuid::new_v4();
    c.execute("INSERT INTO publishers(id,name,key_id,public_key_pem,status,created_at,updated_at) VALUES($1,'Task fixture','task-fixture','metadata fixture','trusted',now(),now())", &[&publisher]).await.unwrap();
    let manifest = json!({"data_schema_version":"none","capabilities":[{"contract":contract}]});
    c.execute("INSERT INTO installations(id,plugin_id,version,publisher_id,image_digest,manifest_digest,manifest,state,created_at,updated_at) VALUES($1,'org.xelab.task-fixture','1.0.0',$2,'fixture','fixture',$3,'installed',now(),now())", &[&Uuid::new_v4(),&publisher,&manifest]).await.unwrap();
    c.execute("INSERT INTO capability_contracts(name,version,schema_digest,spec) VALUES('tool.echo','1.0.0',$1,$2)", &[&contract["schema_digest"].as_str().unwrap(),&json!({"contract":contract})]).await.unwrap();
    let auth = auth::Auth::new(vec![72; 32]).unwrap();
    let peer = "127.0.0.1".parse().unwrap();
    let tx = c.transaction().await.unwrap();
    let issued = auth
        .login(&tx, owner, OLD_PASSWORD.into(), peer, Uuid::new_v4())
        .await
        .unwrap();
    let ctx = auth
        .authenticate(
            &tx,
            issued["access_token"].as_str().unwrap(),
            peer,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    let new = create(&tx, &ctx, &json!({"workflow_id":workflow,"input":{}}))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let task = contracts::id(&new, "id").unwrap();
    let delegation = contracts::id(&new, "delegation_id").unwrap();
    let proof: Value = c
        .query_one("SELECT admission FROM tasks WHERE id=$1", &[&task])
        .await
        .unwrap()
        .get(0);
    assert_eq!(proof["version"], 1);
    assert!(!proof["steps"][0]["targets"][0]["paths"][0]["sources"].is_null());

    drop(c);
    let mut c = database.connect().await.unwrap();
    let tx = c.transaction().await.unwrap();
    db::call_lock(&tx).await.unwrap();
    revoke_transient_delegations(&tx).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        delegation_status(&c, historical_delegation).await,
        "revoked"
    );
    assert_eq!(delegation_status(&c, transient_delegation).await, "revoked");
    assert_eq!(delegation_status(&c, delegation).await, "active");
    assert_eq!(
        c.query_one("SELECT admission FROM tasks WHERE id=$1", &[&task])
            .await
            .unwrap()
            .get::<_, Value>(0),
        proof
    );

    // The offline metadata reset revokes even the new durable authority.
    let recovery = Uuid::new_v4();
    c.execute("INSERT INTO platform_recovery_state(recovery_id,backup_id,phase) VALUES($1,$2,'importing')", &[&recovery,&Uuid::new_v4()]).await.unwrap();
    let tx = c.transaction().await.unwrap();
    recovery::reset_rows(&tx, owner, NEW_PASSWORD, recovery)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(delegation_status(&c, delegation).await, "revoked");
    assert_eq!(
        c.query_one("SELECT admission FROM tasks WHERE id=$1", &[&task])
            .await
            .unwrap()
            .get::<_, Value>(0),
        proof
    );
}
