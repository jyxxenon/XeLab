//! Actual PostgreSQL post-admission waits, using workload/dependency metadata
//! fixtures. These backend tests deliberately wait beyond the public RPC's
//! unchanged two-second limit to make clock-boundary assertions deterministic;
//! they do not claim OCI or production transport acceptance.
use super::*;

async fn wait_for_binding_insert(observer: &tokio_postgres::Client, blocker: i32) {
    let bound = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let waiting: bool = observer
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE 'INSERT INTO dependency_bindings(%')",
                &[&blocker],
            )
            .await
            .unwrap()
            .get(0);
        if waiting {
            return;
        }
        assert!(
            tokio::time::Instant::now() < bound,
            "Resolve must reach the actual child-binding INSERT/FK wait after its initial authority check"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn postgres_host_resolve_rechecks_parent_clock_after_binding_insert_wait() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (consumer, instance) = f.workload().await;
    proxy(&f, consumer, proxy_rules()).await;
    let (provider, provider_instance) = f.workload().await;
    let contract = capability_target(&f, provider, provider_instance).await;
    dependency(&f, consumer, &contract).await;
    let source = f.source(b"Resolve post-wait authority".to_vec()).await;
    let observer = f.app.db.connect().await.unwrap();
    let mut blocking = f.app.db.connect().await.unwrap();
    let blocker: i32 = blocking
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);

    // The first attempt is a positive control: the same real FK wait releases
    // while the original parent remains valid and publishes exactly one pin.
    for expire_parent in [false, true] {
        let (parent, mut context) = f.delegation(consumer, instance, source).await;
        let expires: Option<chrono::DateTime<chrono::Utc>> = if expire_parent {
            Some(
                observer
                    .query_one(
                        "UPDATE calls SET deadline_at=clock_timestamp()+interval '20 seconds' WHERE id=$1 RETURNING deadline_at",
                        &[&parent],
                    )
                    .await
                    .unwrap()
                    .get(0),
            )
        } else {
            None
        };
        // A workload-supplied later deadline does not extend its actual parent.
        context.deadline_unix_ms =
            (chrono::Utc::now() + chrono::Duration::seconds(60)).timestamp_millis();
        let locked = blocking.transaction().await.unwrap();
        locked
            .query_one(
                "SELECT id FROM dependency_bindings WHERE consumer_deployment_id=$1 AND bound_call IS NULL FOR UPDATE",
                &[&consumer],
            )
            .await
            .unwrap();
        let app = f.app.clone();
        let requested_contract = contract.clone();
        let operation = tokio::spawn(async move {
            host_calls::resolve(
                &app,
                Workload {
                    instance,
                    generation: 7,
                },
                rpc::ResolveRequest {
                    context: Some(context),
                    contract: Some(requested_contract),
                    binding_scope_id: parent.to_string(),
                },
            )
            .await
        });
        wait_for_binding_insert(&observer, blocker).await;
        assert!(
            !operation.is_finished(),
            "the metadata operation must remain blocked at the child-binding write"
        );
        if let Some(expires) = expires {
            assert!(
                chrono::Utc::now() < expires,
                "the initial authority check and actual FK wait must precede parent expiration"
            );
            // Tokio's monotonic timer can wake before the wall clocks reach
            // the deadline. Release the FK lock only after both see expiry.
            tokio::time::timeout(Duration::from_secs(25), async {
                loop {
                    let expired_in_db: bool = observer
                        .query_one("SELECT clock_timestamp() >= $1", &[&expires])
                        .await
                        .unwrap()
                        .get(0);
                    assert!(
                        !operation.is_finished(),
                        "Resolve ended while the child-binding FK lock was still held"
                    );
                    if expired_in_db && chrono::Utc::now() >= expires {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .expect("parent did not expire while the child-binding FK lock was held");
        }
        locked.commit().await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(10), operation)
            .await
            .unwrap()
            .unwrap();
        let persisted: i64 = observer
            .query_one(
                "SELECT count(*) FROM dependency_bindings WHERE bound_call=$1",
                &[&parent],
            )
            .await
            .unwrap()
            .get(0);
        if expire_parent {
            assert_eq!(result.unwrap_err().code, "DEADLINE_EXCEEDED");
            assert_eq!(
                persisted, 0,
                "an expired parent must publish neither a handle nor a child binding"
            );
        } else {
            let result = result.unwrap();
            assert_eq!(result.provider_deployment_id, provider.to_string());
            assert_eq!(persisted, 1);
            assert!(Uuid::parse_str(&result.binding_id).is_ok());
        }
        assert_eq!(
            observer
                .query_one("SELECT state FROM calls WHERE id=$1", &[&parent])
                .await
                .unwrap()
                .get::<_, String>(0),
            "running",
            "this regression advances only clocks, without terminalizing or revoking the parent"
        );
    }
}
