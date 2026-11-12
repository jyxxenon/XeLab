use crate::{
    contracts::validate,
    db,
    error::{Error, Result},
};
use serde_json::{json, Value};
use std::path::{Component, Path};
use tokio_postgres::GenericClient;
use uuid::Uuid;

pub fn pool(config: &Value, cpu: i64, memory: i64) -> Result<(i64, i64)> {
    validate("NodeConfig", config)?;
    // A nominal 512 MiB machine can lose up to 32 MiB to boot reservations.
    // Always subtract budgets from observed capacity, never add that loss back.
    if config["profile"] == "compact" && (cpu < 1000 || memory < 480 * 1024 * 1024) {
        return Err(Error::exhausted());
    }
    let pc = cpu
        .checked_sub(config["kernel_cpu_millis"].as_i64().unwrap())
        .and_then(|v| v.checked_sub(config["system_cpu_millis"].as_i64().unwrap()))
        .ok_or_else(Error::exhausted)?;
    let pm = memory
        .checked_sub(config["kernel_memory_bytes"].as_i64().unwrap())
        .and_then(|v| v.checked_sub(config["system_memory_bytes"].as_i64().unwrap()))
        .ok_or_else(Error::exhausted)?;
    if pc < 0 || pm < 0 {
        return Err(Error::exhausted());
    }
    Ok((pc, pm))
}

pub fn host_capacity() -> Result<(i64, i64)> {
    let cpu = std::thread::available_parallelism()?.get() as i64 * 1000;
    let memory = host_memory()?;
    let membership = std::fs::read_to_string("/proc/self/cgroup")?;
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")?;
    let group = unified_group(&membership, &mounts)?;
    effective_capacity(Path::new("/sys/fs/cgroup"), group, cpu, memory)
}

/// Recheck the whole-node budget after compact startup has entered its own
/// kernel-only cgroup. Preserve any limits from the launcher's original cgroup
/// and intersect them with the current parent hierarchy, never the kernel leaf.
pub fn compact_host_capacity(original: (i64, i64)) -> Result<(i64, i64)> {
    // available_parallelism also consults cpu.max and would treat the kernel's
    // quota as the capacity of the entire node. Affinity remains a host bound.
    let mut affinity = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
    if unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&affinity), &mut affinity) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let cpu = i64::from(unsafe { libc::CPU_COUNT(&affinity) }) * 1000;
    let memory = host_memory()?;
    let membership = std::fs::read_to_string("/proc/self/cgroup")?;
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")?;
    compact_capacity(
        Path::new("/sys/fs/cgroup"),
        unified_group(&membership, &mounts)?,
        original,
        (cpu, memory),
    )
}

fn compact_capacity(
    root: &Path,
    group: &Path,
    original: (i64, i64),
    observed: (i64, i64),
) -> Result<(i64, i64)> {
    if group != Path::new("/xelab/kernel")
        || original.0 <= 0
        || original.1 <= 0
        || observed.0 <= 0
        || observed.1 <= 0
    {
        return Err(Error::unavailable(
            "Invalid compact startup cgroup or capacity",
        ));
    }
    effective_capacity(
        root,
        Path::new("/xelab"),
        original.0.min(observed.0),
        original.1.min(observed.1),
    )
}

fn host_memory() -> Result<i64> {
    let mem = std::fs::read_to_string("/proc/meminfo")?;
    let kb = mem
        .lines()
        .find(|l| l.starts_with("MemTotal:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<i64>().ok())
        .ok_or_else(|| Error::unavailable("Cannot discover host memory"))?;
    kb.checked_mul(1024).ok_or_else(Error::exhausted)
}

// The runtime manages /sys/fs/cgroup/xelab directly. A subtree mount hides
// ancestor budgets and is not an adequate view of the host for that adapter.
fn unified_group<'a>(membership: &'a str, mounts: &str) -> Result<&'a Path> {
    let group = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| Error::unavailable("Unified cgroup membership is unavailable"))?;
    let path = Path::new(group);
    if !path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        || !mounts.lines().any(|line| {
            let Some((fields, filesystem)) = line.split_once(" - ") else {
                return false;
            };
            let fields: Vec<_> = fields.split_whitespace().collect();
            filesystem.starts_with("cgroup2 ")
                && fields.get(3) == Some(&"/")
                && fields.get(4) == Some(&"/sys/fs/cgroup")
        })
    {
        return Err(Error::unavailable(
            "Runtime requires a complete host cgroup hierarchy",
        ));
    }
    Ok(path)
}

fn effective_capacity(
    root: &Path,
    group: &Path,
    mut cpu: i64,
    mut memory: i64,
) -> Result<(i64, i64)> {
    let relative = group
        .strip_prefix("/")
        .map_err(|_| Error::unavailable("Invalid cgroup membership"))?;
    let mut directory = root.join(relative);
    loop {
        let raw = cgroup_limit(&directory, root, "memory.max", "max")?;
        if raw.trim() != "max" {
            let limit = positive_limit(raw.trim())?;
            memory = memory.min(limit);
        }
        let raw = cgroup_limit(&directory, root, "cpu.max", "max 100000")?;
        let parts: Vec<_> = raw.split_whitespace().collect();
        if parts.len() != 2 {
            return Err(Error::unavailable("Invalid cgroup CPU limit"));
        }
        let period = positive_limit(parts[1])?;
        if parts[0] != "max" {
            let quota = positive_limit(parts[0])?;
            let millis =
                (i128::from(quota) * 1000 / i128::from(period)).min(i128::from(i64::MAX)) as i64;
            cpu = cpu.min(millis);
        }
        if directory == root {
            break;
        }
        if !directory.pop() || !directory.starts_with(root) {
            return Err(Error::unavailable("Invalid cgroup ancestry"));
        }
    }
    Ok((cpu, memory))
}

fn cgroup_limit(directory: &Path, root: &Path, name: &str, unlimited: &str) -> Result<String> {
    match std::fs::read_to_string(directory.join(name)) {
        Ok(value) => Ok(value),
        // The actual host root cgroup has no resource limit files. Missing
        // files below that root must fail closed (e.g. disabled controller).
        Err(e) if directory == root && e.kind() == std::io::ErrorKind::NotFound => {
            Ok(unlimited.into())
        }
        Err(e) => Err(e.into()),
    }
}

fn positive_limit(value: &str) -> Result<i64> {
    value
        .parse::<i64>()
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| Error::unavailable("Invalid cgroup resource limit"))
}

pub async fn initialize(
    c: &impl GenericClient,
    config: &Value,
    cpu: i64,
    memory: i64,
) -> Result<()> {
    pool(config, cpu, memory)?;
    c.execute("INSERT INTO node_budget(id,config,host_cpu_millis,host_memory_bytes,created_at,updated_at) VALUES($1,$2,$3,$4,now(),now()) ON CONFLICT(singleton) DO NOTHING",&[&Uuid::new_v4(),&config,&cpu,&memory]).await?;
    let row = c
        .query_one("SELECT * FROM node_budget FOR UPDATE", &[])
        .await?;
    let existing: Value = row.get("config");
    if (existing["profile"] == "compact") != (config["profile"] == "compact") {
        return Err(Error::conflict(
            "Resource profile differs from persisted node budget; use the existing profile",
        ));
    }
    let (pcpu, pmem) = pool(&existing, cpu, memory)?;
    if row.get::<_, i64>("reserved_cpu_millis") > pcpu
        || row.get::<_, i64>("reserved_memory_bytes") > pmem
    {
        return Err(Error::exhausted());
    }
    c.execute("UPDATE node_budget SET host_cpu_millis=$1,host_memory_bytes=$2,admission_enabled=false,revision=revision+1,updated_at=now()",&[&cpu,&memory]).await?;
    Ok(())
}

// Caller must use a transaction. Lock the budget before deployment, instance and reservation.
pub async fn reserve(c: &impl GenericClient, instance: Uuid) -> Result<()> {
    let budget = c
        .query_one("SELECT * FROM node_budget FOR UPDATE", &[])
        .await?;
    if !budget.get::<_, bool>("admission_enabled") {
        return Err(Error::unavailable(
            "Admission is disabled during reconciliation",
        ));
    }
    // Task Broker admission can hold the deployment while waiting for the instance.
    let deployment = c
        .query_one(
            "SELECT id,spec,archived_at FROM deployments
             WHERE id=(SELECT deployment_id FROM instances WHERE id=$1) FOR SHARE",
            &[&instance],
        )
        .await?;
    let deployment_id: Uuid = deployment.get("id");
    let limits: Value = c
        .query_one(
            "SELECT limits FROM instances WHERE id=$1 AND deployment_id=$2 FOR UPDATE",
            &[&instance, &deployment_id],
        )
        .await?
        .get("limits");
    validate("ResourceLimits", &limits)?;
    let spec: Value = deployment.get("spec");
    if spec["limits"] != limits
        || spec["enabled"] != true
        || deployment
            .get::<_, Option<chrono::DateTime<chrono::Utc>>>("archived_at")
            .is_some()
    {
        return Err(Error::conflict(
            "Instance does not match an enabled deployment",
        ));
    }
    let cpu = limits["cpu_millis"].as_i64().unwrap();
    let mem = limits["memory_bytes"].as_i64().unwrap();
    if let Some(r) = c
        .query_opt(
            "SELECT * FROM reservations WHERE instance_id=$1 FOR UPDATE",
            &[&instance],
        )
        .await?
    {
        if r.get::<_, String>("status") == "released" {
            return Err(Error::conflict("A released reservation cannot be revived"));
        }
        if r.get::<_, i64>("cpu_millis") != cpu || r.get::<_, i64>("memory_bytes") != mem {
            return Err(Error::conflict("Reservation limits differ"));
        }
        return Ok(());
    }
    let config: Value = budget.get("config");
    let (pc, pm) = pool(
        &config,
        budget.get("host_cpu_millis"),
        budget.get("host_memory_bytes"),
    )?;
    let used_cpu = budget
        .get::<_, i64>("reserved_cpu_millis")
        .checked_add(cpu)
        .ok_or_else(Error::exhausted)?;
    let used_mem = budget
        .get::<_, i64>("reserved_memory_bytes")
        .checked_add(mem)
        .ok_or_else(Error::exhausted)?;
    if used_cpu > pc || used_mem > pm {
        return Err(Error::exhausted());
    }
    c.execute("INSERT INTO reservations(id,instance_id,kind,cpu_millis,memory_bytes,status,created_at) VALUES($1,$2,'instance',$3,$4,'reserved',now())",&[&Uuid::new_v4(),&instance,&cpu,&mem]).await?;
    c.execute("UPDATE node_budget SET reserved_cpu_millis=$1,reserved_memory_bytes=$2,revision=revision+1,updated_at=now()",&[&used_cpu,&used_mem]).await?;
    db::outbox(c, "instance.reserved", instance, &json!({})).await
}

// Runtime must have positively observed absence of the task and its cgroup processes.
pub async fn release_stopped(c: &impl GenericClient, instance: Uuid) -> Result<()> {
    c.query_one("SELECT id FROM node_budget FOR UPDATE", &[])
        .await?;
    let i = c
        .query_one(
            "SELECT phase FROM instances WHERE id=$1 FOR UPDATE",
            &[&instance],
        )
        .await?;
    if i.get::<_, String>(0) != "stopped" {
        return Err(Error::conflict("Instance has not been confirmed stopped"));
    }
    if let Some(r) = c
        .query_opt(
            "SELECT * FROM reservations WHERE instance_id=$1 FOR UPDATE",
            &[&instance],
        )
        .await?
    {
        if r.get::<_, String>("status") != "released" {
            let cpu: i64 = r.get("cpu_millis");
            let memory: i64 = r.get("memory_bytes");
            c.execute("UPDATE node_budget SET reserved_cpu_millis=reserved_cpu_millis-$1,reserved_memory_bytes=reserved_memory_bytes-$2,revision=revision+1,updated_at=now()",&[&cpu,&memory]).await?;
            c.execute(
                "UPDATE reservations SET status='released' WHERE instance_id=$1",
                &[&instance],
            )
            .await?;
        }
    }
    Ok(())
}

pub async fn status(c: &impl GenericClient) -> Result<Value> {
    let r = c.query_one("SELECT * FROM node_budget", &[]).await?;
    let config: Value = r.get("config");
    let cpu: i64 = r.get("host_cpu_millis");
    let mem: i64 = r.get("host_memory_bytes");
    let (pc, pm) = pool(&config, cpu, mem)?;
    let mut v = db::stamp(&r);
    for (k, val) in [
        ("config", config),
        ("host_cpu_millis", json!(cpu)),
        ("host_memory_bytes", json!(mem)),
        ("plugin_cpu_pool_millis", json!(pc)),
        ("plugin_memory_pool_bytes", json!(pm)),
        (
            "reserved_cpu_millis",
            json!(r.get::<_, i64>("reserved_cpu_millis")),
        ),
        (
            "reserved_memory_bytes",
            json!(r.get::<_, i64>("reserved_memory_bytes")),
        ),
        (
            "admission_enabled",
            json!(r.get::<_, bool>("admission_enabled")),
        ),
    ] {
        v[k] = val;
    }
    validate("NodeStatus", &v)?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compact_whole_node_budget_never_borrows_boot_or_system_memory() {
        let mut config = json!({"profile":"compact", "kernel_cpu_millis":500,
            "kernel_memory_bytes":201326592, "system_cpu_millis":250,
            "system_memory_bytes":268435456, "shutdown_grace_ms":30000});
        assert_eq!(
            pool(&config, 1000, 512 * 1024 * 1024).unwrap(),
            (250, 64 * 1024 * 1024)
        );
        assert_eq!(
            pool(&config, 1000, 480 * 1024 * 1024).unwrap(),
            (250, 32 * 1024 * 1024)
        );
        assert!(pool(&config, 999, 512 * 1024 * 1024).is_err());
        assert!(pool(&config, 1000, 480 * 1024 * 1024 - 1).is_err());
        config["system_memory_bytes"] = json!(400 * 1024 * 1024);
        assert!(pool(&config, 1000, 512 * 1024 * 1024).is_err());
        config["system_memory_bytes"] = json!(256 * 1024 * 1024 - 1);
        assert!(pool(&config, 1000, 512 * 1024 * 1024).is_err());
    }
    #[test]
    fn host_capacity_respects_every_visible_ancestor_budget() {
        let root = tempfile::tempdir().unwrap();
        let leaf = root.path().join("service/worker");
        std::fs::create_dir_all(&leaf).unwrap();
        for (dir, cpu, memory) in [
            (root.path().to_path_buf(), "400000 100000", "17179869184"),
            (root.path().join("service"), "150000 100000", "8589934592"),
            (leaf.clone(), "max 100000", "max"),
        ] {
            std::fs::write(dir.join("cpu.max"), cpu).unwrap();
            std::fs::write(dir.join("memory.max"), memory).unwrap();
        }
        assert_eq!(
            effective_capacity(root.path(), Path::new("/service/worker"), 8000, 34359738368)
                .unwrap(),
            (1500, 8589934592)
        );
        std::fs::write(leaf.join("cpu.max"), "100001 100000").unwrap();
        assert_eq!(
            effective_capacity(root.path(), Path::new("/service/worker"), 8000, 34359738368)
                .unwrap()
                .0,
            1000
        );
        std::fs::write(leaf.join("memory.max"), "invalid").unwrap();
        assert!(
            effective_capacity(root.path(), Path::new("/service/worker"), 8000, 34359738368)
                .is_err()
        );
        std::fs::remove_file(leaf.join("memory.max")).unwrap();
        assert!(
            effective_capacity(root.path(), Path::new("/service/worker"), 8000, 34359738368)
                .is_err()
        );
    }
    #[test]
    fn compact_reexec_preserves_launch_limits_and_checks_parent_not_kernel_leaf() {
        let root = tempfile::tempdir().unwrap();
        let leaf = root.path().join("xelab/kernel");
        std::fs::create_dir_all(&leaf).unwrap();
        for (dir, cpu, memory) in [
            (root.path().to_path_buf(), "400000 100000", "2147483648"),
            (root.path().join("xelab"), "150000 100000", "805306368"),
            (leaf, "50000 100000", "201326592"),
        ] {
            std::fs::write(dir.join("cpu.max"), cpu).unwrap();
            std::fs::write(dir.join("memory.max"), memory).unwrap();
        }
        let resumed = |original, observed| {
            compact_capacity(root.path(), Path::new("/xelab/kernel"), original, observed).unwrap()
        };
        assert_eq!(
            resumed((1000, 536870912), (8000, 4294967296)),
            (1000, 536870912)
        );
        assert_eq!(
            resumed((8000, 4294967296), (8000, 4294967296)),
            (1500, 805306368)
        );
        assert_eq!(
            resumed((8000, 4294967296), (1000, 536870912)),
            (1000, 536870912)
        );
        std::fs::write(root.path().join("cpu.max"), "100000 100000").unwrap();
        std::fs::write(root.path().join("memory.max"), "536870912").unwrap();
        assert_eq!(
            resumed((8000, 4294967296), (8000, 4294967296)),
            (1000, 536870912)
        );
        for group in ["/", "/other/kernel", "/xelab/kernel/child"] {
            assert!(compact_capacity(
                root.path(),
                Path::new(group),
                (1000, 536870912),
                (1000, 536870912)
            )
            .is_err());
        }
        assert!(compact_capacity(
            root.path(),
            Path::new("/xelab/kernel"),
            (0, 536870912),
            (1000, 536870912)
        )
        .is_err());
        std::fs::remove_file(root.path().join("xelab/memory.max")).unwrap();
        assert!(compact_capacity(
            root.path(),
            Path::new("/xelab/kernel"),
            (1000, 536870912),
            (1000, 536870912)
        )
        .is_err());
    }
    #[test]
    fn hidden_cgroup_ancestry_cannot_establish_host_capacity() {
        let mount = "1 0 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw";
        assert_eq!(
            unified_group("0::/service\n", mount).unwrap(),
            Path::new("/service")
        );
        assert!(unified_group("0::/\n", &mount.replace(" / /sys", " /.. /sys")).is_err());
        assert!(unified_group("0::/../../service\n", mount).is_err());
        assert!(unified_group("1:memory:/\n", mount).is_err());
        assert!(unified_group("0::/\n", "").is_err());
    }
    #[test]
    fn actual_host_root_has_no_limit_files() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            effective_capacity(root.path(), Path::new("/"), 8000, 34359738368).unwrap(),
            (8000, 34359738368)
        );
    }
    #[test]
    fn reservations_never_borrow_kernel_or_system() {
        let c = json!({"kernel_cpu_millis":4000,"kernel_memory_bytes":17179869184u64,"system_cpu_millis":1000,"system_memory_bytes":1073741824u64,"shutdown_grace_ms":30000});
        assert_eq!(pool(&c, 8000, 34359738368).unwrap(), (3000, 16106127360));
        assert!(pool(&c, 4000, 34359738368).is_err());
        assert!(pool(&c, 8000, 17179869184).is_err());
    }
}
