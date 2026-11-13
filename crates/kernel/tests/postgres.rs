use serde_json::json;
use std::time::Duration;
use uuid::Uuid;
use xelab_kernel::{
    admission,
    auth::{self, Auth, Resource},
    db::Db,
};

#[tokio::test]
async fn real_postgres_enforces_authentication_and_atomic_admission() {
    let Ok(dsn) = std::env::var("XELAB_TEST_DATABASE_URL") else {
        eprintln!("Set XELAB_TEST_DATABASE_URL to run PostgreSQL integration tests");
        return;
    };
    let admin = Db::new(dsn.clone()).unwrap().connect().await.unwrap();
    let name = format!("admission_{}", Uuid::new_v4().simple());
    admin
        .batch_execute(&format!("CREATE DATABASE {name}"))
        .await
        .unwrap();
    let db = Db::new(format!("{dsn} dbname={name}")).unwrap();
    db.migrate().await.unwrap();
    db.migrate().await.unwrap();
    db.check().await.unwrap();
    let mut c = db.connect().await.unwrap();
    let tx = c.transaction().await.unwrap();
    let quotas = json!({"maximum_depth":4,"maximum_descendants":20,"maximum_api_keys":50,"maximum_concurrent_calls":16,"daily_calls":10000});
    let owner = auth::bootstrap(
        &tx,
        "integration owner",
        "correct horse test password",
        &quotas,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let auth = Auth::new(vec![42; 32]).unwrap();
    let tx = c.transaction().await.unwrap();
    let issued = auth
        .login(
            &tx,
            owner,
            "correct horse test password".into(),
            "127.0.0.1".parse().unwrap(),
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    let token = issued["access_token"].as_str().unwrap();
    let credential: Uuid = issued["session"]["id"].as_str().unwrap().parse().unwrap();
    let ctx = auth
        .authenticate(&tx, token, "127.0.0.1".parse().unwrap(), Uuid::new_v4())
        .await
        .unwrap();
    auth::authorize(
        &tx,
        &ctx,
        "plugin.deploy",
        &Resource::new("deployment", "new", Some(owner)),
    )
    .await
    .unwrap();
    assert!(auth::authorize(
        &tx,
        &ctx,
        "unknown.action",
        &Resource::new("deployment", "new", Some(owner))
    )
    .await
    .is_err());
    assert!(auth
        .authenticate(
            &tx,
            "a fabricated bearer token of sufficient length",
            "127.0.0.1".parse().unwrap(),
            Uuid::new_v4()
        )
        .await
        .is_err());
    tx.commit().await.unwrap();
    c.execute(
        "UPDATE credentials SET status='revoked' WHERE id=$1",
        &[&credential],
    )
    .await
    .unwrap();
    assert!(auth
        .authenticate(&c, token, "127.0.0.1".parse().unwrap(), Uuid::new_v4())
        .await
        .is_err());
    let config = json!({"kernel_cpu_millis":4000,"kernel_memory_bytes":17179869184u64,"system_cpu_millis":1000,"system_memory_bytes":1073741824u64,"shutdown_grace_ms":30000});
    let tx = c.transaction().await.unwrap();
    admission::initialize(&tx, &config, 7000, 34359738368)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    c.execute("UPDATE node_budget SET admission_enabled=true", &[])
        .await
        .unwrap();
    let publisher = Uuid::new_v4();
    let installation = Uuid::new_v4();
    let deployment = Uuid::new_v4();
    let limits =
        json!({"cpu_millis":1500,"memory_bytes":134217728,"ephemeral_bytes":1048576,"pids":32});
    c.execute("INSERT INTO publishers(id,name,key_id,public_key_pem,status,created_at,updated_at) VALUES($1,'fixture','fixture','not used in admission test','trusted',now(),now())",&[&publisher]).await.unwrap();
    c.execute("INSERT INTO installations(id,plugin_id,version,publisher_id,image_digest,manifest_digest,manifest,state,created_at,updated_at) VALUES($1,'org.xelab.fixture','1.0.0',$2,'test','test','{}','installed',now(),now())",&[&installation,&publisher]).await.unwrap();
    c.execute("INSERT INTO deployments(id,owner_id,installation_id,spec,phase,created_at,updated_at) VALUES($1,$2,$3,$4,'reconciling',now(),now())",&[&deployment,&owner,&installation,&json!({"enabled":true,"limits":limits})]).await.unwrap();
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    for (i, id) in [a, b].iter().enumerate() {
        c.execute("INSERT INTO instances(id,deployment_id,generation,ordinal,phase,health,limits,created_at,updated_at) VALUES($1,$2,1,$3,'pending','unknown',$4,now(),now())",&[&id,&deployment,&(i as i32),&limits]).await.unwrap();
    }
    let mut handles = Vec::new();
    for id in [a, b] {
        let db = db.clone();
        handles.push(tokio::spawn(async move {
            let mut c = db.connect().await.unwrap();
            let tx = c.transaction().await.unwrap();
            match admission::reserve(&tx, id).await {
                Ok(()) => {
                    tx.commit().await.unwrap();
                    Some(id)
                }
                Err(_) => None,
            }
        }));
    }
    let mut winners = Vec::new();
    for h in handles {
        if let Some(id) = h.await.unwrap() {
            winners.push(id);
        }
    }
    assert_eq!(
        winners.len(),
        1,
        "concurrent reservations must not oversell"
    );
    reserve_waits_for_deployment_before_locking_instance(&db, deployment, winners[0]).await;
    let r = c
        .query_one("SELECT reserved_cpu_millis FROM node_budget", &[])
        .await
        .unwrap();
    assert_eq!(r.get::<_, i64>(0), 1500, "replayed reserve is idempotent");
    let tx = c.transaction().await.unwrap();
    assert!(admission::release_stopped(&tx, winners[0]).await.is_err());
    tx.rollback().await.unwrap();
    c.execute(
        "UPDATE instances SET phase='stopped' WHERE id=$1",
        &[&winners[0]],
    )
    .await
    .unwrap();
    let tx = c.transaction().await.unwrap();
    admission::release_stopped(&tx, winners[0]).await.unwrap();
    admission::release_stopped(&tx, winners[0]).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        c.query_one("SELECT reserved_cpu_millis FROM node_budget", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
}

async fn reserve_waits_for_deployment_before_locking_instance(
    db: &Db,
    deployment: Uuid,
    instance: Uuid,
) {
    let mut holder = db.connect().await.unwrap();
    let mut reserver = db.connect().await.unwrap();
    let holder_pid: i32 = holder
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let reserver_pid: i32 = reserver
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let hold = holder.transaction().await.unwrap();
    hold.query_one(
        "SELECT id FROM deployments WHERE id=$1 FOR UPDATE",
        &[&deployment],
    )
    .await
    .unwrap();
    let reserve = tokio::spawn(async move {
        let tx = reserver.transaction().await.unwrap();
        admission::reserve(&tx, instance).await.unwrap();
        tx.commit().await.unwrap();
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let blocked: bool = hold
                .query_one(
                    "SELECT $1 = ANY(pg_blocking_pids($2))",
                    &[&holder_pid, &reserver_pid],
                )
                .await
                .unwrap()
                .get(0);
            if blocked {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("Reservation did not wait for the deployment lock");
    hold.query_one(
        "SELECT id FROM instances WHERE id=$1 FOR UPDATE NOWAIT",
        &[&instance],
    )
    .await
    .expect("Reservation locked the instance before acquiring the deployment lock");
    hold.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), reserve)
        .await
        .expect("Reservation did not finish after the deployment lock was released")
        .unwrap();
}

#[tokio::test]
async fn call_charges_migrate_from_v1_without_rewriting_baseline() {
    let Ok(base) = std::env::var("XELAB_TEST_DATABASE_URL") else {
        return;
    };
    let admin = Db::new(base.clone()).unwrap().connect().await.unwrap();
    let name = format!("upgrade_{}", Uuid::new_v4().simple());
    admin
        .batch_execute(&format!("CREATE DATABASE {name}"))
        .await
        .unwrap();
    let db = Db::new(format!("{base} dbname={name}")).unwrap();
    let c = db.connect().await.unwrap();
    c.batch_execute(xelab_kernel::db::BASELINE).await.unwrap();
    let checksum = xelab_kernel::contracts::digest(xelab_kernel::db::BASELINE.as_bytes());
    c.execute(
        "INSERT INTO schema_migrations VALUES(1,$1,now())",
        &[&checksum],
    )
    .await
    .unwrap();
    assert!(
        db.check().await.is_err(),
        "unmigrated daemon must fail closed"
    );
    db.migrate().await.unwrap();
    db.migrate().await.unwrap();
    db.check().await.unwrap();
    assert_eq!(
        c.query_one(
            "SELECT checksum FROM schema_migrations WHERE version=1",
            &[]
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        checksum
    );
    assert_eq!(
        c.query_one("SELECT count(*) FROM schema_migrations", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        xelab_kernel::db::SCHEMA_VERSION as i64
    );
    c.query("SELECT * FROM call_credential_charges", &[])
        .await
        .unwrap();
}
