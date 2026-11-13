use crate::{
    admission,
    config::{require_host_admin, Config},
    contracts::{digest, strict_json},
    error::{Error, Result},
    tls,
};
use serde_json::{json, Value};
use std::{
    fs,
    net::Ipv4Addr,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{io::AsyncReadExt, process::Command};
use uuid::Uuid;

#[derive(Clone)]
pub struct Runtime {
    pub config: Config,
    pub(crate) business_queue: crate::broker_queue::Queue,
}
pub struct Observation {
    pub running: bool,
    pub address: String,
}

#[path = "runtime_images.rs"]
mod images;
pub use images::ImageArchive;

static DAEMON_HOST_LEASE: std::sync::OnceLock<fs::File> = std::sync::OnceLock::new();

fn lease_directory(directory: &Path, owner: u32) -> Result<()> {
    let meta = directory.symlink_metadata()?;
    if !meta.is_dir() || meta.uid() != owner || meta.mode() & 0o022 != 0 {
        return Err(Error::invalid("Unsafe host lease directory"));
    }
    Ok(())
}

fn lease_metadata(meta: &fs::Metadata, owner: u32) -> Result<()> {
    if !meta.is_file() || meta.uid() != owner || meta.nlink() != 1 || meta.mode() & 0o077 != 0 {
        return Err(Error::invalid("Unsafe host lease file"));
    }
    Ok(())
}

fn lock_lease(file: &fs::File) -> Result<()> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(Error::conflict("Another kernel owns this host"));
    }
    Ok(())
}

fn host_lease_at(directory: &Path, owner: u32) -> Result<fs::File> {
    fs::create_dir_all(directory)?;
    lease_directory(directory, owner)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join("kernel.lock"))?;
    lease_metadata(&file.metadata()?, owner)?;
    lock_lease(&file)?;
    Ok(file)
}

// The caller transfers ownership of a live inherited descriptor. Checking its
// number first avoids constructing File from an invalid or standard descriptor.
unsafe fn inherited_lease_at(fd: RawFd, directory: &Path, owner: u32) -> Result<fs::File> {
    if fd < 3 || unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(Error::invalid("Invalid inherited host lease descriptor"));
    }
    let file = unsafe { fs::File::from_raw_fd(fd) };
    // No subsequently launched adapter or plugin may inherit the daemon lock.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    lease_directory(directory, owner)?;
    let actual = file.metadata()?;
    lease_metadata(&actual, owner)?;
    if actual.mode() & 0o777 != 0o600 {
        return Err(Error::invalid("Unsafe inherited host lease permissions"));
    }
    let expected = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join("kernel.lock"))?
        .metadata()?;
    lease_metadata(&expected, owner)?;
    if actual.dev() != expected.dev() || actual.ino() != expected.ino() {
        return Err(Error::invalid(
            "Inherited host lease does not match the host lock",
        ));
    }
    // flock belongs to the open file description and survives exec. Acquiring
    // it again is idempotent only for that description; a competing owner fails.
    lock_lease(&file)?;
    Ok(file)
}

fn exec_with_lease(command: &mut std::process::Command, lease: &fs::File) -> Result<()> {
    let fd = lease.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let error = command.exec();
    // exec only returns on failure. Restore the previous descriptor policy
    // before returning; the borrowed file continues to own the lock.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Err(error.into())
}

fn binary(name: &str) -> Result<PathBuf> {
    for root in ["/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/bin"] {
        let p = Path::new(root).join(name);
        if !p.exists() {
            continue;
        }
        let p = p.canonicalize()?;
        let m = p.metadata()?;
        if m.uid() == 0 && m.mode() & 0o022 == 0 && m.is_file() {
            return Ok(p);
        }
    }
    Err(Error::unavailable(
        "Required trusted host binary is unavailable",
    ))
}

async fn command(name: &str, args: &[String], deadline: Duration) -> Result<Vec<u8>> {
    let mut child = Command::new(binary(name)?)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::unavailable("Cannot capture host command"))?;
    let work = async {
        let mut out = Vec::new();
        (&mut stdout).take(2097153).read_to_end(&mut out).await?;
        if out.len() > 2097152 {
            return Err(Error::unavailable("Host command exceeded output limit"));
        }
        let status = child.wait().await?;
        if !status.success() {
            return Err(Error::unavailable("Host adapter command failed"));
        }
        Ok(out)
    };
    tokio::time::timeout(deadline, work)
        .await
        .map_err(|_| Error::unavailable("Host adapter timed out"))?
}
fn strs(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}

impl Runtime {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            business_queue: Default::default(),
        }
    }
    pub async fn ctr(&self, args: &[String]) -> Result<Vec<u8>> {
        let mut all = strs(&[
            "--address",
            self.config.text("runtime", "socket"),
            "--namespace",
            self.config.text("runtime", "namespace"),
        ]);
        all.extend_from_slice(args);
        command("ctr", &all, Duration::from_secs(60)).await
    }
    pub fn host_lease(&self) -> Result<fs::File> {
        require_host_admin()?;
        host_lease_at(Path::new("/run/xelab"), 0)
    }
    /// Adopt the descriptor passed by the compact startup exec.
    ///
    /// # Safety
    /// `fd` must be an exclusively owned descriptor inherited across exec. This
    /// function takes ownership of valid nonstandard descriptors, even on error.
    pub unsafe fn inherited_host_lease(fd: RawFd) -> Result<fs::File> {
        require_host_admin()?;
        unsafe { inherited_lease_at(fd, Path::new("/run/xelab"), 0) }
    }
    /// Replace the first startup image to release anonymous allocations made
    /// before cgroup migration. Shared file-backed pages can retain prior charges.
    /// The same open lock description survives exec, with no unlocked interval.
    pub fn reexec_compact(lease: &fs::File, config: &Path, capacity: (i64, i64)) -> Result<()> {
        let mut command = std::process::Command::new(std::env::current_exe()?);
        command
            .arg("--config")
            .arg(config)
            .arg("--inherited-host-lease")
            .arg(format!(
                "{}:{}:{}",
                lease.as_raw_fd(),
                capacity.0,
                capacity.1
            ));
        exec_with_lease(&mut command, lease)
    }
    /// A Tokio runtime can still be joining filesystem workers after async main
    /// returns. Keep the daemon's lease until process exit, so another kernel
    /// cannot enter that shutdown window and reuse its storage namespace.
    pub fn retain_daemon_host_lease(&self) -> Result<()> {
        Self::retain_host_lease(self.host_lease()?)
    }
    pub fn retain_host_lease(lease: fs::File) -> Result<()> {
        DAEMON_HOST_LEASE
            .set(lease)
            .map_err(|_| Error::conflict("Daemon host lease was already retained"))
    }
    /// Synchronous so compact startup can enter its allocation budget before
    /// creating Tokio, opening the database, or compiling runtime validators.
    pub fn prepare_kernel_cgroup(&self, cpu: i64, memory: i64) -> Result<()> {
        require_host_admin()?;
        admission::pool(&self.config.value["resources"], cpu, memory)?;
        if !fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")?
            .split_whitespace()
            .any(|x| x == "memory")
        {
            return Err(Error::unavailable(
                "cgroups v2 memory controller is unavailable",
            ));
        }
        let root = Path::new("/sys/fs/cgroup/xelab");
        fs::create_dir_all(root)?;
        fs::write(
            "/sys/fs/cgroup/cgroup.subtree_control",
            "+cpu +memory +pids",
        )?;
        fs::write(root.join("cgroup.subtree_control"), "+cpu +memory +pids")?;
        fs::create_dir_all(root.join("kernel"))?;
        // Compact limits protect the system pool from control-plane growth.
        // Explicitly clear them when a standard node reuses this cgroup.
        fs::write(
            root.join("kernel/memory.max"),
            if self.config.compact() {
                self.config.value["resources"]["kernel_memory_bytes"].to_string()
            } else {
                "max".into()
            },
        )?;
        fs::write(
            root.join("kernel/cpu.max"),
            if self.config.compact() {
                format!(
                    "{} 100000",
                    self.config.value["resources"]["kernel_cpu_millis"]
                        .as_u64()
                        .unwrap()
                        * 100
                )
            } else {
                "max 100000".into()
            },
        )?;
        fs::write(
            root.join("kernel/memory.swap.max"),
            if self.config.compact() { "0" } else { "max" },
        )?;
        fs::write(
            root.join("kernel/memory.min"),
            self.config.value["resources"]["kernel_memory_bytes"].to_string(),
        )?;
        fs::write(
            root.join("kernel/cgroup.procs"),
            std::process::id().to_string(),
        )?;
        Ok(())
    }
    pub async fn preflight(&self, cpu: i64, memory: i64) -> Result<()> {
        require_host_admin()?;
        admission::pool(&self.config.value["resources"], cpu, memory)?;
        for name in ["ctr", "ip", "nft"] {
            binary(name)?;
        }
        self.ctr(&strs(&["version"])).await?;
        let network: ipnet::Ipv4Net = self
            .config
            .text("runtime", "network_cidr")
            .parse()
            .map_err(|_| Error::invalid("Invalid network"))?;
        let routes = strict_json(
            &command(
                "ip",
                &strs(&["-j", "-4", "route", "show", "table", "all"]),
                Duration::from_secs(10),
            )
            .await?,
            2097152,
        )?;
        for route in routes
            .as_array()
            .ok_or_else(|| Error::unavailable("Invalid host routes"))?
        {
            if route["dev"].as_str().is_some_and(|d| d.starts_with("xh")) {
                continue;
            }
            if let Some(destination) = route["dst"].as_str().filter(|d| *d != "default") {
                let value = if destination.contains('/') {
                    destination.to_owned()
                } else {
                    format!("{destination}/32")
                };
                if let Ok(other) = value.parse::<ipnet::Ipv4Net>() {
                    if network.contains(&other.network()) || other.contains(&network.network()) {
                        return Err(Error::conflict("Plugin CIDR overlaps a host route"));
                    }
                }
            }
        }
        fs::create_dir_all(self.config.root())?;
        fs::set_permissions(self.config.root(), fs::Permissions::from_mode(0o700))?;
        self.prepare_kernel_cgroup(cpu, memory)?;
        let root = Path::new("/sys/fs/cgroup/xelab");
        fs::create_dir_all(root.join("plugins"))?;
        let (pc, pm) = admission::pool(&self.config.value["resources"], cpu, memory)?;
        if pc > 0 {
            fs::write(root.join("plugins/cpu.max"), format!("{} 100000", pc * 100))?;
        }
        fs::write(root.join("plugins/memory.max"), pm.to_string())?;
        fs::write(root.join("plugins/memory.swap.max"), "0")?;
        fs::write(
            root.join("plugins/cgroup.subtree_control"),
            "+cpu +memory +pids",
        )?;
        self.prepare_host_service_network().await?;
        // Temporary writes use bounded tmpfs.
        Ok(())
    }
    pub async fn prepare_host_service_network(&self) -> Result<()> {
        let rpc: std::net::SocketAddr = self
            .config
            .text("server", "host_rpc_listen")
            .parse()
            .map_err(|_| Error::invalid("Invalid HostService address"))?;
        let net: ipnet::Ipv4Net = self
            .config
            .text("runtime", "network_cidr")
            .parse()
            .map_err(|_| Error::invalid("Invalid plugin network"))?;
        if rpc.ip() != std::net::IpAddr::V4(Ipv4Addr::from(u32::from(net.network()) + 1)) {
            return Err(Error::invalid(
                "HostService must use the first plugin network host address",
            ));
        }
        let links = strict_json(
            &command(
                "ip",
                &strs(&["-j", "-d", "link", "show"]),
                Duration::from_secs(10),
            )
            .await?,
            2097152,
        )?;
        if let Some(link) = links
            .as_array()
            .and_then(|links| links.iter().find(|link| link["ifname"] == "xh-rpc"))
        {
            if link["linkinfo"]["info_kind"] != "dummy"
                || link["ifalias"] != "xelab-host-service-v1"
            {
                return Err(Error::conflict(
                    "HostService network interface is not managed by XeLab",
                ));
            }
        } else {
            command(
                "ip",
                &strs(&["link", "add", "xh-rpc", "type", "dummy"]),
                Duration::from_secs(10),
            )
            .await?;
            command(
                "ip",
                &strs(&["link", "set", "xh-rpc", "alias", "xelab-host-service-v1"]),
                Duration::from_secs(10),
            )
            .await?;
        }
        let addresses = strict_json(
            &command(
                "ip",
                &strs(&["-j", "address", "show", "dev", "xh-rpc"]),
                Duration::from_secs(10),
            )
            .await?,
            2097152,
        )?;
        let addresses = addresses[0]["addr_info"]
            .as_array()
            .ok_or_else(|| Error::unavailable("Invalid HostService network"))?;
        if addresses.iter().any(|a| {
            a["family"] == "inet" && (a["local"] != rpc.ip().to_string() || a["prefixlen"] != 32)
        }) {
            return Err(Error::conflict("HostService network address differs"));
        }
        if !addresses.iter().any(|a| a["local"] == rpc.ip().to_string()) {
            command(
                "ip",
                &strs(&[
                    "address",
                    "add",
                    &format!("{}/32", rpc.ip()),
                    "dev",
                    "xh-rpc",
                ]),
                Duration::from_secs(10),
            )
            .await?;
        }
        command(
            "ip",
            &strs(&["link", "set", "xh-rpc", "up"]),
            Duration::from_secs(10),
        )
        .await?;
        Ok(())
    }
    pub async fn verify_image(&self, image: &str, expected: &str) -> Result<()> {
        let content = self.ctr(&strs(&["content", "get", expected])).await?;
        if digest(&content) != expected {
            return Err(Error::invalid("Image manifest digest differs"));
        }
        let manifest = strict_json(&content, 2097152)?;
        if !matches!(
            manifest["mediaType"].as_str(),
            Some(
                "application/vnd.oci.image.manifest.v1+json"
                    | "application/vnd.docker.distribution.manifest.v2+json"
            )
        ) {
            return Err(Error::invalid(
                "M1 requires a platform-specific image manifest, not an image index",
            ));
        }
        let list = String::from_utf8(self.ctr(&strs(&["images", "list"])).await?)
            .map_err(|_| Error::unavailable("Invalid image inventory"))?;
        if !list.lines().any(|line| {
            let x: Vec<_> = line.split_whitespace().collect();
            x.len() >= 3 && x[0] == image && x[2] == expected
        }) {
            return Err(Error::not_found());
        }
        Ok(())
    }
    pub async fn mount_image(&self, image: &str, sha: &str) -> Result<PathBuf> {
        let root = self.config.root().join("images").join(&sha[7..]);
        fs::create_dir_all(&root)?;
        // ctr mount reuses its view snapshot. Avoid stacking mounts after a restart.
        if !mounted(&root)? {
            self.ctr(&[
                "images".into(),
                "mount".into(),
                image.into(),
                root.display().to_string(),
            ])
            .await?;
        }
        if !mounted(&root)? {
            return Err(Error::unavailable("Image rootfs is not mounted"));
        }
        Ok(root)
    }
    fn dir(&self, id: Uuid) -> PathBuf {
        self.config.root().join("runtime").join(id.to_string())
    }
    pub fn address(&self, id: Uuid) -> Result<String> {
        let v = strict_json(&fs::read(self.dir(id).join("network.json"))?, 4096)?;
        if v["instance"] != id.to_string() {
            return Err(Error::conflict("Runtime identity differs"));
        }
        v["peer"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| Error::unavailable("Missing runtime address"))
    }
    async fn network(&self, id: Uuid) -> Result<Value> {
        let dir = self.dir(id);
        fs::create_dir_all(&dir)?;
        let state = dir.join("network.json");
        let short = id.simple().to_string();
        let host = format!("xh{}", &short[..10]);
        let peer = format!("xp{}", &short[..10]);
        let ns = format!("xelab-{id}");
        let v = if state.exists() {
            strict_json(&fs::read(&state)?, 4096)?
        } else {
            let net: ipnet::Ipv4Net = self
                .config
                .text("runtime", "network_cidr")
                .parse()
                .map_err(|_| Error::invalid("Invalid network"))?;
            let base = u32::from(net.network());
            let slots = 1u32 << (30 - net.prefix_len());
            let mut used = std::collections::HashSet::new();
            for entry in fs::read_dir(self.config.root().join("runtime"))? {
                let file = entry?.path().join("network.json");
                if file.exists() {
                    let x = strict_json(&fs::read(file)?, 4096)?;
                    if let Some(slot) = x["slot"].as_u64() {
                        used.insert(slot as u32);
                    }
                }
            }
            let slot = (1..slots)
                .find(|n| !used.contains(n))
                .ok_or_else(Error::exhausted)?;
            let hostip = Ipv4Addr::from(base + slot * 4 + 1).to_string();
            let peerip = Ipv4Addr::from(base + slot * 4 + 2).to_string();
            let v = json!({"instance":id,"slot":slot,"host":hostip,"peer":peerip});
            tls::atomic_file(&state, &serde_json::to_vec(&v)?, 0o600)?;
            v
        };
        if v["instance"] != id.to_string() {
            return Err(Error::conflict("Network state belongs to another instance"));
        }
        if Path::new("/run/netns").join(&ns).exists() {
            if dir.join("network.ready").exists() {
                return Ok(v);
            }
            // No task can start until the complete network transaction has a marker.
            command(
                "ip",
                &strs(&["netns", "delete", &ns]),
                Duration::from_secs(10),
            )
            .await?;
        }
        if Path::new("/sys/class/net").join(&host).exists() {
            command(
                "ip",
                &strs(&["link", "delete", &host]),
                Duration::from_secs(10),
            )
            .await?;
        }
        let _ = command(
            "nft",
            &strs(&["delete", "table", "inet", &format!("xl_{}", &short[..16])]),
            Duration::from_secs(10),
        )
        .await;
        let h = v["host"]
            .as_str()
            .ok_or_else(|| Error::invalid("Invalid network state"))?;
        let p = v["peer"]
            .as_str()
            .ok_or_else(|| Error::invalid("Invalid network state"))?;
        h.parse::<Ipv4Addr>()
            .map_err(|_| Error::invalid("Invalid network state"))?;
        p.parse::<Ipv4Addr>()
            .map_err(|_| Error::invalid("Invalid network state"))?;
        let rpc: std::net::SocketAddr = self
            .config
            .text("server", "host_rpc_listen")
            .parse()
            .unwrap();
        let nft=format!("table inet xl_{} {{\n chain ingress {{ type filter hook input priority -20; policy accept; iifname \"{host}\" ct state established,related accept; iifname \"{host}\" ip saddr {p} ip daddr {} tcp dport {} accept; iifname \"{host}\" drop; }}\n chain transit {{ type filter hook forward priority -20; policy accept; iifname \"{host}\" drop; oifname \"{host}\" drop; }}\n}}\n",&short[..16],rpc.ip(),rpc.port());
        let nftfile = dir.join("network.nft");
        tls::atomic_file(&nftfile, nft.as_bytes(), 0o600)?;
        command(
            "nft",
            &["-f".into(), nftfile.display().to_string()],
            Duration::from_secs(10),
        )
        .await?;
        command("ip", &strs(&["netns", "add", &ns]), Duration::from_secs(10)).await?;
        for args in [
            vec!["link", "add", &host, "type", "veth", "peer", "name", &peer],
            vec!["link", "set", &peer, "netns", &ns],
            vec!["link", "set", &host, "up"],
        ] {
            command("ip", &strs(&args), Duration::from_secs(10)).await?;
        }
        command(
            "ip",
            &strs(&["address", "add", &format!("{h}/30"), "dev", &host]),
            Duration::from_secs(10),
        )
        .await?;
        for args in [
            vec![
                "-n",
                &ns,
                "address",
                "add",
                &format!("{p}/30"),
                "dev",
                &peer,
            ],
            vec!["-n", &ns, "link", "set", "lo", "up"],
            vec!["-n", &ns, "link", "set", &peer, "up"],
        ] {
            command("ip", &strs(&args), Duration::from_secs(10)).await?;
        }
        if rpc.ip().to_string() != h {
            command(
                "ip",
                &strs(&[
                    "-n",
                    &ns,
                    "route",
                    "add",
                    &format!("{}/32", rpc.ip()),
                    "via",
                    h,
                    "dev",
                    &peer,
                ]),
                Duration::from_secs(10),
            )
            .await?;
        }
        tls::atomic_file(&dir.join("network.ready"), b"ready", 0o600)?;
        // No default route. Forwarding is denied even if a route is later added.
        Ok(v)
    }
    pub async fn inventory(&self) -> Result<Vec<Uuid>> {
        let list = String::from_utf8(self.ctr(&strs(&["containers", "list", "--quiet"])).await?)
            .map_err(|_| Error::unavailable("Invalid container inventory"))?;
        list.lines()
            .map(|line| {
                line.parse().map_err(|_| {
                    Error::conflict("Dedicated namespace contains an unmanaged container")
                })
            })
            .collect()
    }
    pub async fn running(&self, id: Uuid) -> Result<bool> {
        let list = String::from_utf8(self.ctr(&strs(&["tasks", "list"])).await?)
            .map_err(|_| Error::unavailable("Invalid task inventory"))?;
        Ok(list.lines().any(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            fields.len() >= 3 && fields[0] == id.to_string() && fields[2] == "RUNNING"
        }))
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn ensure(
        &self,
        id: Uuid,
        deployment: Uuid,
        generation: i64,
        manifest: &Value,
        image: &str,
        sha: &str,
        limits: &Value,
        mounts: &[crate::volumes::Mount],
    ) -> Result<Observation> {
        let dir = self.dir(id);
        fs::create_dir_all(&dir)?;
        let root = self.mount_image(image, sha).await?;
        let net = self
            .network(id)
            .await
            .map_err(|_| Error::unavailable("OCI network setup failed"))?;
        let identity = dir.join("identity");
        if identity
            .join("tls.crt")
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_none_or(|age| age >= Duration::from_secs(1800))
        {
            tls::issue(&self.config, Some((id, generation)), &identity)?;
        }
        let mut spec = oci_spec(
            &self.config,
            id,
            deployment,
            generation,
            manifest,
            &root,
            &identity,
            limits,
        )?;
        add_volume_mounts(&mut spec, &root, mounts)?;
        let config = dir.join("config.json");
        if !self.inventory().await?.contains(&id) {
            tls::atomic_file(&config, &serde_json::to_vec(&spec)?, 0o600)?;
            self.ctr(&[
                "containers".into(),
                "create".into(),
                "--config".into(),
                config.display().to_string(),
                "--label".into(),
                format!("org.xelab.instance={id}"),
                "--label".into(),
                format!("org.xelab.deployment={deployment}"),
                "--label".into(),
                format!("org.xelab.generation={generation}"),
                id.to_string(),
            ])
            .await
            .map_err(|_| Error::unavailable("OCI container creation failed"))?;
        } else {
            let existing = strict_json(
                &self
                    .ctr(&strs(&["containers", "info", "--spec", &id.to_string()]))
                    .await?,
                2097152,
            )?;
            if !same_spec(&existing, &spec) {
                return Err(Error::conflict("Existing OCI instance identity differs"));
            }
        }
        if !self.running(id).await? {
            // A stopped task record is removed before recreating the same stable instance.
            let _ = self.ctr(&strs(&["tasks", "delete", &id.to_string()])).await;
            self.ctr(&strs(&["tasks", "start", "--detach", &id.to_string()]))
                .await
                .map_err(|_| Error::unavailable("OCI task start failed"))?;
        }
        let cgroup = Path::new("/sys/fs/cgroup/xelab/plugins").join(id.to_string());
        let expected = format!("{} 100000", limits["cpu_millis"].as_i64().unwrap() * 100);
        if fs::read_to_string(cgroup.join("cpu.max"))?.trim() != expected
            || fs::read_to_string(cgroup.join("memory.max"))?
                .trim()
                .parse::<u64>()
                .ok()
                != limits["memory_bytes"].as_u64()
        {
            return Err(Error::unavailable(
                "Runtime did not enforce resource limits",
            ));
        }
        Ok(Observation {
            running: self.running(id).await?,
            address: net["peer"].as_str().unwrap().to_owned(),
        })
    }
    async fn task_present(&self, id: Uuid) -> Result<bool> {
        let raw = self.ctr(&strs(&["tasks", "list"])).await?;
        let text =
            std::str::from_utf8(&raw).map_err(|_| Error::unavailable("Invalid task inventory"))?;
        let mut lines = text.lines().filter(|s| !s.trim().is_empty());
        let header: Vec<_> = lines
            .next()
            .ok_or_else(|| Error::unavailable("Missing task inventory header"))?
            .split_whitespace()
            .collect();
        if header.len() < 3 || header[..3] != ["TASK", "PID", "STATUS"] {
            return Err(Error::unavailable("Invalid task inventory header"));
        }
        let mut found = false;
        for line in lines {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 3 {
                return Err(Error::unavailable("Invalid task inventory"));
            }
            let current: Uuid = fields[0]
                .parse()
                .map_err(|_| Error::unavailable("Invalid task identity"))?;
            found |= current == id;
        }
        Ok(found)
    }
    pub async fn stop(&self, id: Uuid) -> Result<()> {
        if self.running(id).await?
            && self
                .ctr(&strs(&[
                    "tasks",
                    "kill",
                    "--signal",
                    "SIGKILL",
                    "--all",
                    &id.to_string(),
                ]))
                .await
                .is_err()
            && self.running(id).await?
        {
            return Err(Error::unavailable("OCI stop signal is unconfirmed"));
        }
        for _ in 0..40 {
            if !self.running(id).await? {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if self.running(id).await? {
            return Err(Error::unavailable("Runtime task has not stopped"));
        }
        for _ in 0..20 {
            if !self.task_present(id).await? {
                break;
            }
            let _ = self.ctr(&strs(&["tasks", "delete", &id.to_string()])).await;
            if !self.task_present(id).await? {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if self.task_present(id).await? {
            return Err(Error::unavailable("OCI task removal is unconfirmed"));
        }
        if self.inventory().await?.contains(&id)
            && self
                .ctr(&strs(&["containers", "delete", &id.to_string()]))
                .await
                .is_err()
            && self.inventory().await?.contains(&id)
        {
            return Err(Error::unavailable("OCI container removal is unconfirmed"));
        }
        if self.inventory().await?.contains(&id) || self.task_present(id).await? {
            return Err(Error::unavailable("OCI task or container remains"));
        }
        let cg = Path::new("/sys/fs/cgroup/xelab/plugins").join(id.to_string());
        if cg.try_exists()? {
            let proof = (|| -> Result<bool> {
                let procs = fs::read_to_string(cg.join("cgroup.procs"))?;
                let events = fs::read_to_string(cg.join("cgroup.events"))?;
                Ok(procs.trim().is_empty()
                    && events.lines().any(|line| {
                        line.split_whitespace().collect::<Vec<_>>() == ["populated", "0"]
                    }))
            })();
            match proof {
                Ok(true) => (),
                Ok(false) => {
                    return Err(Error::unavailable(
                        "Runtime cgroup still contains processes",
                    ))
                }
                Err(error) if cg.try_exists()? => return Err(error),
                Err(_) => (), // runc concurrently removed the now-empty group.
            }
        }
        let short = id.simple().to_string();
        let ns = format!("xelab-{id}");
        let namespace_path = Path::new("/run/netns").join(&ns);
        if namespace_path.try_exists()? {
            let _ = command(
                "ip",
                &strs(&["netns", "delete", &ns]),
                Duration::from_secs(10),
            )
            .await;
        }
        let host = format!("xh{}", &short[..10]);
        let host_path = Path::new("/sys/class/net").join(&host);
        if host_path.try_exists()? {
            let _ = command(
                "ip",
                &strs(&["link", "delete", &host]),
                Duration::from_secs(10),
            )
            .await;
        }
        for _ in 0..20 {
            if !namespace_path.try_exists()? && !host_path.try_exists()? {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        if namespace_path.try_exists()? || host_path.try_exists()? {
            return Err(Error::unavailable("OCI network cleanup is unconfirmed"));
        }
        let _ = command(
            "nft",
            &strs(&["delete", "table", "inet", &format!("xl_{}", &short[..16])]),
            Duration::from_secs(10),
        )
        .await;
        if self.dir(id).exists() {
            fs::remove_dir_all(self.dir(id))?;
        }
        Ok(())
    }
}

// containerd's Go encoder omits false terminal and empty capability arrays.
// Normalize only these known defaults; added privileges or changed paths still fail.
fn same_spec(actual: &Value, expected: &Value) -> bool {
    let mut actual = actual.clone();
    let Some(process) = actual["process"].as_object_mut() else {
        return false;
    };
    process.entry("terminal").or_insert(json!(false));
    let Some(caps) = process
        .get_mut("capabilities")
        .and_then(Value::as_object_mut)
    else {
        return false;
    };
    for key in [
        "bounding",
        "effective",
        "inheritable",
        "permitted",
        "ambient",
    ] {
        caps.entry(key).or_insert(json!([]));
    }
    [
        "annotations",
        "root",
        "process",
        "mounts",
        "linux",
        "hostname",
        "ociVersion",
    ]
    .iter()
    .all(|key| actual[*key] == expected[*key])
}

fn mounted(path: &Path) -> Result<bool> {
    let target = path
        .to_str()
        .ok_or_else(|| Error::invalid("Invalid runtime path"))?;
    Ok(fs::read_to_string("/proc/self/mountinfo")?
        .lines()
        .any(|l| l.split_whitespace().nth(4) == Some(target)))
}

#[allow(clippy::too_many_arguments)]
pub fn oci_spec(
    config: &Config,
    id: Uuid,
    deployment: Uuid,
    generation: i64,
    manifest: &Value,
    root: &Path,
    identity: &Path,
    limits: &Value,
) -> Result<Value> {
    crate::contracts::validate("ResourceLimits", limits)?;
    let mut env = vec![
        "PATH=/usr/local/bin:/usr/bin:/bin".to_owned(),
        format!(
            "XELAB_PLUGIN_ID={}",
            manifest["plugin_id"].as_str().unwrap()
        ),
        format!(
            "XELAB_PLUGIN_VERSION={}",
            manifest["version"].as_str().unwrap()
        ),
        format!("XELAB_DEPLOYMENT_ID={deployment}"),
        format!("XELAB_INSTANCE_ID={id}"),
        format!("XELAB_GENERATION={generation}"),
        format!(
            "XELAB_HOST_RPC_ENDPOINT=https://{}",
            config.text("server", "host_rpc_listen")
        ),
        "XELAB_TLS_CERT_PATH=/run/xelab/identity/tls.crt".into(),
        "XELAB_TLS_KEY_PATH=/run/xelab/identity/tls.key".into(),
        "XELAB_TLS_CA_PATH=/run/xelab/identity/ca.crt".into(),
        "XELAB_PLUGIN_RPC_LISTEN=0.0.0.0:7000".into(),
    ];
    if manifest["routes"]
        .as_array()
        .is_some_and(|routes| !routes.is_empty())
    {
        env.push("XELAB_HTTP_LISTEN=0.0.0.0:8080".into());
    }
    let tmp = format!("size={},mode=1777", limits["ephemeral_bytes"]);
    let mut spec = json!({"ociVersion":"1.0.2","hostname":"xelab-plugin","root":{"path":root,"readonly":true},"process":{"terminal":false,"user":{"uid":65532,"gid":65532},"args":manifest["entrypoint"],"env":env,"cwd":"/","noNewPrivileges":true,"capabilities":{"bounding":[],"effective":[],"inheritable":[],"permitted":[],"ambient":[]},"rlimits":[{"type":"RLIMIT_NOFILE","hard":1024,"soft":1024}]},"mounts":[{"destination":"/proc","type":"proc","source":"proc","options":["nosuid","noexec","nodev"]},{"destination":"/dev","type":"tmpfs","source":"tmpfs","options":["nosuid","strictatime","mode=755","size=65536k"]},{"destination":"/tmp","type":"tmpfs","source":"tmpfs","options":["nosuid","nodev","noexec",tmp]},{"destination":"/run","type":"tmpfs","source":"tmpfs","options":["nosuid","nodev","noexec","size=1048576","mode=755"]},{"destination":"/run/xelab/identity","type":"bind","source":identity,"options":["rbind","ro","nosuid","nodev","noexec"]}],"annotations":{"org.xelab.instance":id.to_string(),"org.xelab.deployment":deployment.to_string(),"org.xelab.generation":generation.to_string()},"linux":{"cgroupsPath":format!("/xelab/plugins/{id}"),"namespaces":[{"type":"pid"},{"type":"ipc"},{"type":"uts"},{"type":"mount"},{"type":"cgroup"},{"type":"network","path":format!("/run/netns/xelab-{id}")}],"resources":{"cpu":{"period":100000,"quota":limits["cpu_millis"].as_u64().unwrap()*100},"memory":{"limit":limits["memory_bytes"],"swap":limits["memory_bytes"]},"pids":{"limit":limits["pids"]},"devices":[{"allow":false,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":3,"access":"rw"},{"allow":true,"type":"c","major":1,"minor":5,"access":"rw"},{"allow":true,"type":"c","major":1,"minor":8,"access":"rw"},{"allow":true,"type":"c","major":1,"minor":9,"access":"rw"}]},"devices":[{"path":"/dev/null","type":"c","major":1,"minor":3,"fileMode":438,"uid":0,"gid":0},{"path":"/dev/zero","type":"c","major":1,"minor":5,"fileMode":438,"uid":0,"gid":0},{"path":"/dev/random","type":"c","major":1,"minor":8,"fileMode":438,"uid":0,"gid":0},{"path":"/dev/urandom","type":"c","major":1,"minor":9,"fileMode":438,"uid":0,"gid":0}],"maskedPaths":["/proc/kcore","/proc/keys","/proc/timer_list","/proc/sched_debug","/sys/firmware"],"readonlyPaths":["/proc/asound","/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger"],"seccomp":{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["mount","umount2","pivot_root","ptrace","process_vm_readv","process_vm_writev","bpf","perf_event_open","kexec_load","kexec_file_load","init_module","finit_module","delete_module","reboot","swapon","swapoff","open_by_handle_at","name_to_handle_at","setns","unshare","keyctl","add_key","request_key","userfaultfd","io_uring_setup","quotactl","quotactl_fd"],"action":"SCMP_ACT_ERRNO","errnoRet":1},{"names":["clone3"],"action":"SCMP_ACT_ERRNO","errnoRet":38},{"names":["clone"],"action":"SCMP_ACT_ERRNO","errnoRet":1,"args":[{"index":0,"value":268435456,"valueTwo":268435456,"op":"SCMP_CMP_MASKED_EQ"}]}]}}});
    for command in [0x401c5820u64, 0x40086602, 0x40046602] {
        spec["linux"]["seccomp"]["syscalls"].as_array_mut().unwrap().push(json!({"names":["ioctl"],"action":"SCMP_ACT_ERRNO","errnoRet":1,"args":[{"index":1,"value":4294967295u64,"valueTwo":command,"op":"SCMP_CMP_MASKED_EQ"}]}));
    }
    Ok(spec)
}

fn add_volume_mounts(
    spec: &mut Value,
    root: &Path,
    mounts: &[crate::volumes::Mount],
) -> Result<()> {
    for mount in mounts {
        // Signed images are immutable. Reject every symlink component before
        // allowing the OCI runtime to resolve a destination in that image.
        let mut destination = root.to_path_buf();
        for component in mount.destination.trim_start_matches('/').split('/') {
            if component.is_empty() || component == "." || component == ".." {
                return Err(Error::invalid("Invalid volume destination"));
            }
            destination.push(component);
            let meta = fs::symlink_metadata(&destination)?;
            if !meta.is_dir() || meta.file_type().is_symlink() {
                return Err(Error::invalid(
                    "Volume destination must be an existing image directory without symlinks",
                ));
            }
        }
        spec["mounts"].as_array_mut().unwrap().push(json!({"destination":mount.destination,"type":"bind","source":mount.source,"options":["bind",mount.access,"nosuid","nodev","noexec"]}));
        spec["annotations"][format!("org.xelab.volume.{}", mount.volume)] =
            json!(mount.fence.to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::IntoRawFd;

    #[test]
    fn compact_lease_adoption_checks_identity_and_preserves_parent_lock() {
        let directory = tempfile::tempdir().unwrap();
        let owner = unsafe { libc::geteuid() };
        let parent = host_lease_at(directory.path(), owner).unwrap();
        let inherited = parent.try_clone().unwrap().into_raw_fd();
        assert_eq!(unsafe { libc::fcntl(inherited, libc::F_SETFD, 0) }, 0);
        let adopted = unsafe { inherited_lease_at(inherited, directory.path(), owner) }.unwrap();
        assert_ne!(
            unsafe { libc::fcntl(adopted.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        drop(adopted);
        assert!(host_lease_at(directory.path(), owner).is_err());

        let other = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        other
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .unwrap();
        assert!(unsafe {
            inherited_lease_at(
                other.as_file().try_clone().unwrap().into_raw_fd(),
                directory.path(),
                owner,
            )
        }
        .is_err());
        // Rejecting an unrelated descriptor must neither close the caller's
        // other owner nor unlock the correct host lease.
        assert!(other.as_file().metadata().is_ok());
        assert!(host_lease_at(directory.path(), owner).is_err());
        assert!(unsafe { inherited_lease_at(-1, directory.path(), owner) }.is_err());
        assert!(unsafe { inherited_lease_at(0, directory.path(), owner) }.is_err());

        fs::set_permissions(
            directory.path().join("kernel.lock"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        assert!(unsafe {
            inherited_lease_at(
                parent.try_clone().unwrap().into_raw_fd(),
                directory.path(),
                owner,
            )
        }
        .is_err());
        fs::set_permissions(
            directory.path().join("kernel.lock"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(host_lease_at(directory.path(), owner).is_err());
        drop(parent);
        assert!(host_lease_at(directory.path(), owner).is_ok());
    }

    #[test]
    fn compact_failed_exec_restores_cloexec_and_retains_lock() {
        let directory = tempfile::tempdir().unwrap();
        let owner = unsafe { libc::geteuid() };
        let lease = host_lease_at(directory.path(), owner).unwrap();
        let flags = unsafe { libc::fcntl(lease.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        let mut command = std::process::Command::new(directory.path().join("missing-executable"));
        assert!(exec_with_lease(&mut command, &lease).is_err());
        assert_eq!(
            unsafe { libc::fcntl(lease.as_raw_fd(), libc::F_GETFD) },
            flags
        );
        assert!(host_lease_at(directory.path(), owner).is_err());
        drop(lease);
        assert!(host_lease_at(directory.path(), owner).is_ok());
    }

    #[test]
    fn compact_host_lease_survives_real_exec_without_unlocking() {
        let directory = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "runtime::tests::compact_lease_exec_child",
                "--nocapture",
            ])
            .env("XELAB_TEST_LEASE_DIR", directory.path())
            .env_remove("XELAB_TEST_INHERITED_LEASE")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_to_string(directory.path().join("after-exec")).unwrap(),
            "locked"
        );
    }

    #[test]
    fn compact_lease_exec_child() {
        let Some(directory) = std::env::var_os("XELAB_TEST_LEASE_DIR") else {
            return;
        };
        let directory = PathBuf::from(directory);
        let owner = unsafe { libc::geteuid() };
        if let Ok(fd) = std::env::var("XELAB_TEST_INHERITED_LEASE") {
            let lease =
                unsafe { inherited_lease_at(fd.parse().unwrap(), &directory, owner) }.unwrap();
            assert_ne!(
                unsafe { libc::fcntl(lease.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
            assert!(host_lease_at(&directory, owner).is_err());
            fs::write(directory.join("after-exec"), "locked").unwrap();
        } else {
            let lease = host_lease_at(&directory, owner).unwrap();
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "runtime::tests::compact_lease_exec_child",
                    "--nocapture",
                ])
                .env("XELAB_TEST_LEASE_DIR", &directory)
                .env("XELAB_TEST_INHERITED_LEASE", lease.as_raw_fd().to_string());
            panic!("exec failed: {:?}", exec_with_lease(&mut command, &lease));
        }
    }

    #[test]
    fn omitted_oci_defaults_are_equivalent_but_added_privileges_are_not() {
        let expected = json!({"process":{"terminal":false,"capabilities":{"bounding":[],"effective":[],"inheritable":[],"permitted":[],"ambient":[]}}});
        let mut actual = json!({"process":{"capabilities":{}}});
        assert!(same_spec(&actual, &expected));
        actual["process"]["capabilities"]["effective"] = json!(["CAP_SYS_ADMIN"]);
        assert!(!same_spec(&actual, &expected));
        actual = json!({"process":{"terminal":true,"capabilities":{}}});
        assert!(!same_spec(&actual, &expected));
    }
    #[test]
    fn oci_spec_is_nonprivileged_and_has_hard_limits() {
        let t: toml::Value =
            toml::from_str(include_str!("../../../docs/contracts/examples/kernel.toml")).unwrap();
        let c = Config::from_value(serde_json::to_value(t).unwrap()).unwrap();
        let limits =
            json!({"cpu_millis":500,"memory_bytes":134217728,"ephemeral_bytes":1048576,"pids":32});
        let spec = oci_spec(
            &c,
            Uuid::new_v4(),
            Uuid::new_v4(),
            1,
            &json!({"plugin_id":"org.xelab.echo","version":"1.0.0","entrypoint":["/echo"]}),
            Path::new("/trusted/rootfs"),
            Path::new("/trusted/identity"),
            &limits,
        )
        .unwrap();
        assert_eq!(spec["process"]["user"]["uid"], 65532);
        assert_eq!(spec["root"]["readonly"], true);
        assert_eq!(spec["linux"]["resources"]["cpu"]["quota"], 50000);
        assert_eq!(spec["process"]["capabilities"]["effective"], json!([]));
        assert!(spec["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["source"] != "/"));
    }
}
