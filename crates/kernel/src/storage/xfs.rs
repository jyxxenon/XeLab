//! XFS project quotas on a trusted, operator-provisioned filesystem.
//!
//! Linux UAPI: linux/dqblk_xfs.h and linux/fs.h. All quota block counts are
//! 512-byte basic blocks, NOT filesystem blocks. quotactl_fd pins the filesystem
//! to an open descriptor instead of re-resolving a device or shell command.
use crate::{
    config::require_host_admin,
    error::{Error, Result},
};
use serde::Serialize;
use std::{
    ffi::{CStr, CString},
    fs::File,
    io, mem,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
};
use uuid::Uuid;

const PROJINHERIT: u32 = 0x200;
const RTINHERIT: u32 = 0x100;
const QUOTA_FLAGS: u16 = (1 << 4) | (1 << 5);
const LIMIT_FIELDS: u16 = 0x3f;
const MAX_BYTES: u64 = 9_007_199_254_740_991;
pub(crate) const ROOT_LOCK_BUSY: &str = "Storage backend is already in use";

#[repr(C)]
#[derive(Default)]
struct Xattr {
    flags: u32,
    extent_size: u32,
    extents: u32,
    project: u32,
    cow_extent_size: u32,
    padding: [u8; 8],
}
#[repr(C)]
#[derive(Default)]
struct DiskQuota {
    version: i8,
    flags: i8,
    fields: u16,
    id: u32,
    block_hard: u64,
    block_soft: u64,
    inode_hard: u64,
    inode_soft: u64,
    blocks: u64,
    inodes: u64,
    inode_timer: i32,
    block_timer: i32,
    inode_warns: u16,
    block_warns: u16,
    timer_high: [i8; 4],
    rt_hard: u64,
    rt_soft: u64,
    rt_blocks: u64,
    rt_timer: i32,
    rt_warns: u16,
    padding: i16,
    reserved: [u8; 8],
}
#[repr(C)]
#[derive(Default)]
struct QuotaFile {
    inode: u64,
    blocks: u64,
    extents: u32,
    padding: u32,
}
#[repr(C)]
#[derive(Default)]
struct QuotaState {
    version: i8,
    padding: u8,
    flags: u16,
    cached: u32,
    user: QuotaFile,
    group: QuotaFile,
    project: QuotaFile,
    block_time: i32,
    inode_time: i32,
    rt_time: i32,
    block_warns: u16,
    inode_warns: u16,
    rt_warns: u16,
    padding2: u16,
    padding3: u32,
    reserved: [u64; 7],
}

// Stable V1 geometry is sufficient to reject a separate realtime allocation
// pool, which is accounted independently and must not bypass the byte limit.
#[repr(C)]
#[derive(Default)]
struct Geometry {
    block_size: u32,
    rt_extent_size: u32,
    ag_blocks: u32,
    ag_count: u32,
    log_blocks: u32,
    sector_size: u32,
    inode_size: u32,
    max_inode_percent: u32,
    data_blocks: u64,
    rt_blocks: u64,
    rt_extents: u64,
    log_start: u64,
    uuid: [u8; 16],
    stripe_unit: u32,
    stripe_width: u32,
    version: i32,
    flags: u32,
    log_sector_size: u32,
    rt_sector_size: u32,
    directory_block_size: u32,
}

fn quota<T>(fd: &File, subop: u32, id: u32, data: &mut T) -> io::Result<()> {
    let command = (((b'X' as u32) << 8 | subop) << 8) | 2;
    // SAFETY: each caller supplies the repr(C) UAPI object matching subop;
    // the descriptor and writable object live through this synchronous syscall.
    if unsafe {
        libc::syscall(
            libc::SYS_quotactl_fd,
            fd.as_raw_fd(),
            command,
            id,
            data as *mut T,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn attributes(fd: &File) -> Result<Xattr> {
    let mut attr = Xattr::default();
    // SAFETY: FSGETXATTR writes exactly one initialized, correctly sized Xattr.
    if unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            libc::_IOR::<Xattr>(b'X' as u32, 31),
            &mut attr,
        )
    } < 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(attr)
}
fn open_at(parent: &File, name: &CStr) -> io::Result<File> {
    // SAFETY: name is NUL terminated; ownership of a successful new fd is transferred once.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn trusted(fd: &File, private: bool) -> Result<()> {
    let m = fd.metadata()?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & (if private { 0o077 } else { 0o022 }) != 0 {
        return Err(Error::unavailable(
            "Storage requires root-owned protected directories",
        ));
    }
    Ok(())
}
fn trusted_root(path: &Path) -> Result<File> {
    require_host_admin()?;
    if !path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        || path == Path::new("/")
    {
        return Err(Error::invalid(
            "Storage root must be an absolute directory below root",
        ));
    }
    let mut fd = File::open("/")?;
    trusted(&fd, false)?;
    for c in path.components() {
        if let Component::Normal(name) = c {
            let name = CString::new(name.as_bytes())
                .map_err(|_| Error::invalid("Invalid storage directory"))?;
            fd = open_at(&fd, &name)?;
            trusted(&fd, false)?;
        }
    }
    trusted(&fd, true)?;
    Ok(fd)
}

#[derive(Debug, Serialize)]
pub struct BackendStatus {
    pub backend: &'static str,
    pub scope: &'static str,
    pub filesystem_uuid: Uuid,
    pub project_namespace_exclusivity_verified: bool,
    pub volume_service_ready: bool,
    pub block_size: u64,
    pub inode_size_bytes: u64,
    pub project_accounting: bool,
    pub hard_limits_enforced: bool,
}
fn check_fd(fd: &File) -> Result<BackendStatus> {
    trusted(fd, true)?;
    // SAFETY: fstatfs initializes the correctly sized libc statfs on success.
    let mut stat: libc::statfs = unsafe { mem::zeroed() };
    if unsafe { libc::fstatfs(fd.as_raw_fd(), &mut stat) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if stat.f_type != libc::XFS_SUPER_MAGIC || stat.f_bsize < 512 {
        return Err(Error::unavailable("Storage requires XFS project quota"));
    }
    // statvfs reports this mount's flags, including a read-only bind mount of
    // an otherwise writable filesystem. Quota capability alone is insufficient.
    let mut vfs: libc::statvfs = unsafe { mem::zeroed() };
    // SAFETY: fstatvfs writes one correctly sized libc statvfs into live storage.
    if unsafe { libc::fstatvfs(fd.as_raw_fd(), &mut vfs) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if vfs.f_flag & libc::ST_RDONLY != 0 {
        return Err(Error::unavailable("Storage mount is read-only"));
    }
    let mut geometry = Geometry::default();
    // SAFETY: FSGEOMETRY_V1 writes the fixed repr(C) V1 layout.
    if unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            libc::_IOR::<Geometry>(b'X' as u32, 100),
            &mut geometry,
        )
    } < 0
    {
        return Err(io::Error::last_os_error().into());
    }
    if geometry.rt_blocks != 0
        || geometry.block_size as u64 != stat.f_bsize as u64
        || geometry.inode_size < 256
        || !geometry.inode_size.is_power_of_two()
        || geometry.inode_size > geometry.block_size
    {
        return Err(Error::unavailable("Realtime XFS storage is not supported"));
    }
    let mut state = QuotaState {
        version: 1,
        ..Default::default()
    };
    quota(fd, 8, 0, &mut state)?;
    if state.version != 1 || state.flags & QUOTA_FLAGS != QUOTA_FLAGS {
        return Err(Error::unavailable(
            "XFS project accounting and hard limit enforcement are required",
        ));
    }
    let attr = attributes(fd)?;
    if attr.project != 0 || attr.flags & (PROJINHERIT | RTINHERIT) != 0 {
        return Err(Error::unavailable(
            "Storage root must not inherit a project or realtime allocation",
        ));
    }
    Ok(BackendStatus {
        backend: "xfs_project",
        scope: "quota_capability_only",
        filesystem_uuid: Uuid::from_bytes(geometry.uuid),
        project_namespace_exclusivity_verified: false,
        volume_service_ready: false,
        block_size: stat.f_bsize as u64,
        inode_size_bytes: geometry.inode_size as u64,
        project_accounting: true,
        hard_limits_enforced: true,
    })
}
/// Read-only quota capability check; never enables, formats or mounts storage.
/// Success does NOT verify a dedicated filesystem / exclusive project namespace.
/// A protected subdirectory on shared XFS can pass; inspect the explicit false
/// exclusivity/service-readiness fields before using this host-only primitive.
pub fn check(path: &Path) -> Result<BackendStatus> {
    check_fd(&trusted_root(path)?)
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct Limits {
    pub capacity_bytes: u64,
    pub inodes: u64,
}
impl Limits {
    fn validate(self, block_size: u64) -> Result<()> {
        if !(1_048_576..=MAX_BYTES).contains(&self.capacity_bytes)
            || !self.capacity_bytes.is_multiple_of(block_size)
            || self.inodes == 0
            || self.inodes > MAX_BYTES
        {
            return Err(Error::invalid(
                "Backend limits require aligned capacity and a nonzero inode budget",
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Serialize)]
pub struct ProjectStatus {
    pub project_id: u32,
    pub limits: Limits,
    pub used_bytes: u64,
    pub used_inodes: u64,
}

/// Exclusively locks this root, not the filesystem-wide project namespace.
/// The operator must dedicate the filesystem; other managers are not detected.
/// Host-side backend handle. IDs come from the durable volume allocator;
/// this adapter never recycles a project identity.
/// Partial creation is quarantined (root-only directory / reserved quota).
/// The caller must persist intent BEFORE create and recover it before publishing.
pub struct ProjectStore {
    root: File,
    block_size: u64,
    inode_size: u64,
}

fn try_lock_root(root: &File) -> io::Result<bool> {
    // SAFETY: flock holds the lock until the owning file description is closed.
    if unsafe { libc::flock(root.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::WouldBlock {
        return Ok(false);
    }
    Err(error)
}

impl ProjectStore {
    pub fn open(path: &Path) -> Result<Self> {
        Self::try_open(path)?.ok_or_else(|| Error::conflict(ROOT_LOCK_BUSY))
    }

    pub(crate) fn try_open(path: &Path) -> Result<Option<Self>> {
        let root = trusted_root(path)?;
        if !try_lock_root(&root)? {
            return Ok(None);
        }
        let status = check_fd(&root)?;
        Ok(Some(Self {
            root,
            block_size: status.block_size,
            inode_size: status.inode_size_bytes,
        }))
    }
    fn validate_id(id: u32) -> Result<()> {
        if id == 0 || id > i32::MAX as u32 {
            return Err(Error::invalid("Invalid project ID"));
        }
        Ok(())
    }
    fn read_quota(&self, id: u32) -> io::Result<DiskQuota> {
        let mut q = DiskQuota::default();
        quota(&self.root, 3, id, &mut q)?;
        Ok(q)
    }
    fn set_limits(&self, id: u32, limits: Limits) -> Result<()> {
        // Soft == hard means no grace-period overcommit. Realtime allocation
        // is not supported; directory inheritance is explicitly disabled.
        let mut q = DiskQuota {
            version: 1,
            flags: 2,
            fields: LIMIT_FIELDS,
            id,
            block_hard: limits.capacity_bytes / 512,
            block_soft: limits.capacity_bytes / 512,
            inode_hard: limits.inodes,
            inode_soft: limits.inodes,
            ..Default::default()
        };
        quota(&self.root, 4, id, &mut q)?;
        Ok(())
    }
    fn dir(&self, volume: Uuid) -> Result<File> {
        let name = CString::new(volume.to_string()).unwrap();
        let dir = open_at(&self.root, &name)?;
        trusted(&dir, true)?;
        if dir.metadata()?.dev() != self.root.metadata()?.dev()
            || mount_id(&dir)? != mount_id(&self.root)?
        {
            return Err(Error::unavailable(
                "Volume directory crosses a filesystem boundary",
            ));
        }
        Ok(dir)
    }
    fn persist(&self) -> Result<()> {
        // SAFETY: syncfs flushes this open filesystem including quota metadata.
        if unsafe { libc::syncfs(self.root.as_raw_fd()) } < 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }
    /// Create ONLY a new private directory. Existing data is never reassigned.
    pub fn create(&mut self, volume: Uuid, id: u32, limits: Limits) -> Result<ProjectStatus> {
        Self::validate_id(id)?;
        limits.validate(self.block_size)?;
        check_fd(&self.root)?;
        match self.read_quota(id) {
            Ok(q)
                if q.block_hard != 0
                    || q.block_soft != 0
                    || q.inode_hard != 0
                    || q.inode_soft != 0
                    || q.blocks != 0
                    || q.inodes != 0
                    || q.rt_hard != 0
                    || q.rt_soft != 0
                    || q.rt_blocks != 0 =>
            {
                return Err(Error::conflict("Project ID is already reserved"))
            }
            Ok(_) => (),
            // XFS reports an unallocated dquot as ENOENT. ESRCH can mean
            // quotas were disabled and must remain an error.
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => (),
            Err(e) => return Err(e.into()),
        }
        let name = CString::new(volume.to_string()).unwrap();
        // SAFETY: root is trusted and name is generated from a UUID, never user path text.
        if unsafe { libc::mkdirat(self.root.as_raw_fd(), name.as_ptr(), 0o700) } < 0 {
            return Err(Error::conflict(
                "Volume directory cannot be exclusively created",
            ));
        }
        let dir = self.dir(volume)?;
        self.set_limits(id, limits)?;
        let mut attr = attributes(&dir)?;
        attr.project = id;
        attr.flags = (attr.flags | PROJINHERIT) & !RTINHERIT;
        attr.padding = [0; 8];
        // SAFETY: FSSETXATTR consumes the matching, initialized UAPI object.
        if unsafe { libc::ioctl(dir.as_raw_fd(), libc::_IOW::<Xattr>(b'X' as u32, 32), &attr) } < 0
        {
            return Err(io::Error::last_os_error().into());
        }
        self.persist()?;
        let status = self.inspect(volume, id)?;
        if status.limits != limits {
            return Err(Error::unavailable("Project limits failed verification"));
        }
        Ok(status)
    }
    /// Recover only the exact UUID/project/limits from a durable creating intent.
    /// A project-zero directory must still be empty; existing data is never
    /// reassigned. Publishing metadata and exposing data are the caller's job.
    /// Only a complete, uniquely mounted XFS root may own a project namespace.
    /// A protected shared subdirectory remains a quota capability, not a service.
    pub fn verify_mount_root(&self) -> Result<()> {
        check_fd(&self.root)?;
        let path = std::fs::read_link(format!("/proc/self/fd/{}", self.root.as_raw_fd()))?;
        let device = self.root.metadata()?.dev();
        let device = format!("{}:{}", libc::major(device), libc::minor(device));
        let mount = mount_id(&self.root)?;
        let mut matches = 0;
        for line in std::fs::read_to_string("/proc/self/mountinfo")?.lines() {
            let Some((fields, kind)) = line.split_once(" - ") else {
                continue;
            };
            let fields: Vec<_> = fields.split_whitespace().collect();
            if fields.get(2) != Some(&device.as_str()) {
                continue;
            }
            if fields.len() < 6
                || fields[0].parse::<u64>().ok() != Some(mount)
                || fields[3] != "/"
                || !kind.starts_with("xfs ")
                || decode_mount(fields[4])?.as_bytes() != path.as_os_str().as_bytes()
            {
                return Err(Error::unavailable(
                    "Volume service requires a dedicated XFS mount without aliases",
                ));
            }
            matches += 1;
        }
        if matches != 1 {
            return Err(Error::unavailable(
                "Volume mount boundary cannot be established",
            ));
        }
        Ok(())
    }
    /// The caller persists this token and expected filesystem UUID before asking
    /// for creation. Missing markers are never regenerated for a ready binding.
    pub fn namespace_identity(
        &mut self,
        filesystem: Uuid,
        token: Uuid,
        creating: bool,
    ) -> Result<()> {
        self.verify_mount_root()?;
        if self.status()?.filesystem_uuid != filesystem {
            return Err(Error::unavailable(
                "Volume filesystem UUID differs from durable binding",
            ));
        }
        let marker = CString::new(".xelab-volume-root").unwrap();
        let fd = unsafe {
            libc::openat(
                self.root.as_raw_fd(),
                marker.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd >= 0 {
            let mut file = unsafe { File::from_raw_fd(fd) };
            let m = file.metadata()?;
            if !m.is_file()
                || m.uid() != 0
                || m.mode() & 0o777 != 0o600
                || m.nlink() != 1
                || m.dev() != self.root.metadata()?.dev()
            {
                return Err(Error::unavailable(
                    "Volume namespace marker is not protected",
                ));
            }
            use std::io::Read;
            let mut bytes = Vec::new();
            (&mut file).take(38).read_to_end(&mut bytes)?;
            if bytes != format!("{token}\n").as_bytes() {
                return Err(Error::unavailable("Volume namespace identity differs"));
            }
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotFound || !creating {
            return Err(Error::unavailable(
                "Registered volume namespace is unavailable",
            ));
        }
        let mut next = DiskQuota::default();
        match quota(&self.root, 9, 1, &mut next) {
            Ok(()) => {
                return Err(Error::conflict(
                    "Unregistered filesystem already has project quota identities",
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        for entry in std::fs::read_dir(format!("/proc/self/fd/{}", self.root.as_raw_fd()))? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| Error::conflict("Unregistered volume filesystem is not empty"))?;
            if !name
                .strip_prefix(".xelab-volume-root-")
                .is_some_and(|s| Uuid::parse_str(s).is_ok())
            {
                return Err(Error::conflict(
                    "Unregistered volume filesystem is not empty",
                ));
            }
            let m = entry.metadata()?;
            if !m.is_file()
                || m.uid() != 0
                || m.mode() & 0o777 != 0o600
                || m.nlink() != 1
                || m.len() > 37
            {
                return Err(Error::conflict(
                    "Unregistered volume filesystem contains an unknown object",
                ));
            }
        }
        let temporary = CString::new(format!(".xelab-volume-root-{}", Uuid::new_v4())).unwrap();
        let result = (|| {
            let fd = unsafe {
                libc::openat(
                    self.root.as_raw_fd(),
                    temporary.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error().into());
            }
            let mut file = unsafe { File::from_raw_fd(fd) };
            use std::io::Write;
            file.write_all(format!("{token}\n").as_bytes())?;
            file.sync_all()?;
            if unsafe {
                libc::renameat2(
                    self.root.as_raw_fd(),
                    temporary.as_ptr(),
                    self.root.as_raw_fd(),
                    marker.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } < 0
            {
                return Err(io::Error::last_os_error().into());
            }
            self.persist()?;
            Ok(())
        })();
        let _ = unsafe { libc::unlinkat(self.root.as_raw_fd(), temporary.as_ptr(), 0) };
        result
    }
    pub fn recover_create(
        &mut self,
        volume: Uuid,
        id: u32,
        limits: Limits,
    ) -> Result<ProjectStatus> {
        Self::validate_id(id)?;
        limits.validate(self.block_size)?;
        check_fd(&self.root)?;
        let name = CString::new(volume.to_string()).unwrap();
        match open_at(&self.root, &name) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return self.create(volume, id, limits)
            }
            Err(e) => return Err(e.into()),
            Ok(_) => (),
        }
        let dir = self.dir(volume)?;
        let mut attr = attributes(&dir)?;
        if attr.project == id && attr.flags & PROJINHERIT != 0 && attr.flags & RTINHERIT == 0 {
            let status = self.inspect(volume, id)?;
            if status.limits != limits {
                return Err(Error::conflict(
                    "Recovered volume limits differ from durable intent",
                ));
            }
            return Ok(status);
        }
        if attr.project != 0
            || attr.flags & (PROJINHERIT | RTINHERIT) != 0
            || std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))?
                .next()
                .is_some()
        {
            return Err(Error::conflict(
                "Partial volume is not an empty unassigned directory",
            ));
        }
        let q = match self.read_quota(id) {
            Ok(q) => q,
            Err(e) if e.kind() == io::ErrorKind::NotFound => DiskQuota::default(),
            Err(e) => return Err(e.into()),
        };
        let blank =
            q.block_hard == 0 && q.block_soft == 0 && q.inode_hard == 0 && q.inode_soft == 0;
        let intended = q.block_hard == limits.capacity_bytes / 512
            && q.block_soft == q.block_hard
            && q.inode_hard == limits.inodes
            && q.inode_soft == q.inode_hard;
        if (!blank && !intended)
            || q.blocks != 0
            || q.inodes != 0
            || q.rt_hard != 0
            || q.rt_soft != 0
            || q.rt_blocks != 0
        {
            return Err(Error::conflict(
                "Partial project quota differs from durable intent",
            ));
        }
        self.set_limits(id, limits)?;
        attr.project = id;
        attr.flags = (attr.flags | PROJINHERIT) & !RTINHERIT;
        attr.padding = [0; 8];
        if unsafe { libc::ioctl(dir.as_raw_fd(), libc::_IOW::<Xattr>(b'X' as u32, 32), &attr) } < 0
        {
            return Err(io::Error::last_os_error().into());
        }
        self.persist()?;
        let status = self.inspect(volume, id)?;
        if status.limits != limits {
            return Err(Error::unavailable(
                "Recovered volume quota verification failed",
            ));
        }
        Ok(status)
    }
    /// Keep the UUID directory root-owned and private. Only its data child is
    /// exposed to an authorized workload; the caller must install the runtime
    /// ioctl restrictions before allowing the workload to mutate that directory.
    pub fn prepare_data(&mut self, volume: Uuid, id: u32) -> Result<()> {
        self.inspect(volume, id)?;
        let parent = self.dir(volume)?;
        let name = CString::new("data").unwrap();
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } < 0
            && io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
        {
            return Err(io::Error::last_os_error().into());
        }
        let data = open_at(&parent, &name)?;
        let meta = data.metadata()?;
        let attr = attributes(&data)?;
        if meta.dev() != parent.metadata()?.dev()
            || mount_id(&data)? != mount_id(&self.root)?
            || attr.project != id
            || attr.flags & PROJINHERIT == 0
            || attr.flags & RTINHERIT != 0
            || ![0, 65532].contains(&meta.uid())
        {
            return Err(Error::unavailable("Volume data directory identity differs"));
        }
        if meta.uid() == 0 {
            if std::fs::read_dir(format!("/proc/self/fd/{}", data.as_raw_fd()))?
                .next()
                .is_some()
            {
                return Err(Error::conflict("Unassigned data directory is not empty"));
            }
            if unsafe { libc::fchown(data.as_raw_fd(), 65532, 65532) } < 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
        data.sync_all()?;
        parent.sync_all()?;
        self.persist()?;
        Ok(())
    }
    fn data_directory(&self, volume: Uuid, id: u32) -> Result<File> {
        self.inspect(volume, id)?;
        let parent = self.dir(volume)?;
        let data = open_at(&parent, &CString::new("data").unwrap())?;
        let meta = data.metadata()?;
        let attr = attributes(&data)?;
        if meta.uid() != 65532
            || mount_id(&data)? != mount_id(&self.root)?
            || meta.dev() != self.root.metadata()?.dev()
            || attr.project != id
            || attr.flags & PROJINHERIT == 0
            || attr.flags & RTINHERIT != 0
        {
            return Err(Error::unavailable("Volume data directory identity differs"));
        }
        Ok(data)
    }
    /// Caller owns writer stop proofs and its volume hold. Usage counters alone
    /// do not prove emptiness; inspect the exact verified data inode instead.
    pub fn data_is_empty(&self, volume: Uuid, id: u32) -> Result<bool> {
        let data = self.data_directory(volume, id)?;
        Ok(
            std::fs::read_dir(format!("/proc/self/fd/{}", data.as_raw_fd()))?
                .next()
                .transpose()?
                .is_none(),
        )
    }
    pub fn data_path(&self, volume: Uuid, id: u32) -> Result<std::path::PathBuf> {
        self.data_directory(volume, id)?;
        let root = std::fs::read_link(format!("/proc/self/fd/{}", self.root.as_raw_fd()))?;
        Ok(root.join(volume.to_string()).join("data"))
    }
    /// Reset ONLY the unpublished data child under an already durable private
    /// allocation. Caller must own the offline gate and have joined old writers.
    /// The UUID directory, project identity, limits and root marker are retained.
    pub fn clear_private_data(&mut self, volume: Uuid, id: u32) -> Result<()> {
        self.inspect(volume, id)?;
        let parent = self.dir(volume)?;
        let name = CString::new("data").unwrap();
        match open_at(&parent, &name) {
            Ok(data) => {
                let attr = attributes(&data)?;
                if data.metadata()?.dev() != self.root.metadata()?.dev()
                    || mount_id(&data)? != mount_id(&self.root)?
                    || attr.project != id
                    || attr.flags & PROJINHERIT == 0
                    || attr.flags & RTINHERIT != 0
                {
                    return Err(Error::conflict("Private restore data identity differs"));
                }
                remove_contents(&data, self.root.metadata()?.dev(), mount_id(&self.root)?)?;
                if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) }
                    < 0
                {
                    return Err(io::Error::last_os_error().into());
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        parent.sync_all()?;
        self.persist()
    }
    /// The caller must first fence every attachment and positively confirm old
    /// containers/mount namespaces have exited. This routine never stops a task.
    /// Quota IDs and their limits remain tombstoned after physical deletion.
    pub fn remove_data(&mut self, volume: Uuid, id: u32) -> Result<bool> {
        Self::validate_id(id)?;
        check_fd(&self.root)?;
        let name = CString::new(volume.to_string()).unwrap();
        match open_at(&self.root, &name) {
            Ok(_) => {
                self.inspect(volume, id)?;
                let dir = self.dir(volume)?;
                remove_contents(&dir, self.root.metadata()?.dev(), mount_id(&self.root)?)?;
                if unsafe {
                    libc::unlinkat(self.root.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR)
                } < 0
                {
                    return Err(io::Error::last_os_error().into());
                }
                self.persist()?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        let q = self.read_quota(id)?;
        Ok(q.blocks == 0 && q.inodes == 0 && q.rt_blocks == 0)
    }
    /// Clean up a failed *unpublished* creating intent. An unassigned directory
    /// must be empty and its project must have no usage; unknown data is retained.
    pub fn discard_create(&mut self, volume: Uuid, id: u32) -> Result<bool> {
        Self::validate_id(id)?;
        check_fd(&self.root)?;
        let name = CString::new(volume.to_string()).unwrap();
        match open_at(&self.root, &name) {
            Ok(_) => {
                let dir = self.dir(volume)?;
                let attr = attributes(&dir)?;
                if attr.project == id {
                    return self.remove_data(volume, id);
                }
                if attr.project != 0
                    || attr.flags & (PROJINHERIT | RTINHERIT) != 0
                    || std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))?
                        .next()
                        .is_some()
                {
                    return Err(Error::conflict(
                        "Unpublished volume contains unassigned data",
                    ));
                }
                let empty = match self.read_quota(id) {
                    Ok(q) => q.blocks == 0 && q.inodes == 0 && q.rt_blocks == 0,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => true,
                    Err(e) => return Err(e.into()),
                };
                if !empty {
                    return Err(Error::conflict("Unpublished project has unexpected usage"));
                }
                if unsafe {
                    libc::unlinkat(self.root.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR)
                } < 0
                {
                    return Err(io::Error::last_os_error().into());
                }
                self.persist()?;
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => match self.read_quota(id) {
                Ok(q) => Ok(q.blocks == 0 && q.inodes == 0 && q.rt_blocks == 0),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(true),
                Err(e) => Err(e.into()),
            },
            Err(e) => Err(e.into()),
        }
    }
    pub fn status(&self) -> Result<BackendStatus> {
        check_fd(&self.root)
    }
    pub fn aligned_limits(&self, capacity: u64) -> Result<Limits> {
        let limits = Limits {
            capacity_bytes: capacity,
            inodes: (capacity / 4096).clamp(256, 65536),
        };
        limits.validate(self.block_size)?;
        Ok(limits)
    }
    pub fn metadata_charge(&self, limits: Limits) -> Result<u64> {
        limits.validate(self.block_size)?;
        // Inode chunks are outside the byte dquot. Reserve their maximum size
        // conservatively, plus permanent namespace/dquot metadata per identity.
        limits
            .inodes
            .checked_mul(self.inode_size)
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| n.checked_add(65536))
            .ok_or_else(Error::exhausted)
    }
    pub fn available_bytes(&self) -> Result<u64> {
        check_fd(&self.root)?;
        let mut stat: libc::statvfs = unsafe { mem::zeroed() };
        if unsafe { libc::fstatvfs(self.root.as_raw_fd(), &mut stat) } < 0 {
            return Err(io::Error::last_os_error().into());
        }
        (stat.f_bavail as u64)
            .checked_mul(stat.f_frsize as u64)
            .ok_or_else(Error::exhausted)
    }
    pub fn inspect(&self, volume: Uuid, id: u32) -> Result<ProjectStatus> {
        Self::validate_id(id)?;
        check_fd(&self.root)?;
        let attr = attributes(&self.dir(volume)?)?;
        if attr.project != id || attr.flags & PROJINHERIT == 0 || attr.flags & RTINHERIT != 0 {
            return Err(Error::unavailable(
                "Volume project identity or inheritance does not match",
            ));
        }
        let q = self.read_quota(id)?;
        if q.version != 1
            || q.flags & 2 == 0
            || q.id != id
            || q.block_hard == 0
            || q.inode_hard == 0
            || q.block_soft != q.block_hard
            || q.inode_soft != q.inode_hard
            || q.rt_hard != 0
            || q.rt_soft != 0
            || q.rt_blocks != 0
        {
            return Err(Error::unavailable(
                "Volume quota is not a supported enforced limit",
            ));
        }
        Ok(ProjectStatus {
            project_id: id,
            limits: Limits {
                capacity_bytes: q.block_hard.checked_mul(512).ok_or_else(Error::exhausted)?,
                inodes: q.inode_hard,
            },
            used_bytes: q.blocks.checked_mul(512).ok_or_else(Error::exhausted)?,
            used_inodes: q.inodes,
        })
    }
    /// Grow an existing project. The Volume service must reserve the complete
    /// capacity and metadata budget in SQL before changing this limit.
    pub fn expand(&mut self, volume: Uuid, id: u32, limits: Limits) -> Result<ProjectStatus> {
        limits.validate(self.block_size)?;
        let old = self.inspect(volume, id)?;
        if limits.capacity_bytes <= old.limits.capacity_bytes || limits.inodes < old.limits.inodes {
            return Err(Error::conflict("Volume limits can only grow"));
        }
        self.set_limits(id, limits)?;
        self.persist()?;
        let status = self.inspect(volume, id)?;
        if status.limits != limits {
            return Err(Error::unavailable("Expanded limits failed verification"));
        }
        Ok(status)
    }
}

fn decode_mount(input: &str) -> Result<String> {
    let mut output = Vec::new();
    let mut source = input.as_bytes().iter().copied();
    while let Some(byte) = source.next() {
        if byte != b'\\' {
            output.push(byte);
            continue;
        }
        let escaped = [source.next(), source.next(), source.next()];
        let value = match escaped {
            [Some(b'0'), Some(b'4'), Some(b'0')] => b' ',
            [Some(b'0'), Some(b'1'), Some(b'1')] => b'\t',
            [Some(b'0'), Some(b'1'), Some(b'2')] => b'\n',
            [Some(b'1'), Some(b'3'), Some(b'4')] => b'\\',
            _ => return Err(Error::unavailable("Invalid storage mount entry")),
        };
        output.push(value);
    }
    String::from_utf8(output).map_err(|_| Error::unavailable("Invalid storage mount encoding"))
}

pub(crate) fn mount_id(file: &File) -> Result<u64> {
    let mut stat: libc::statx = unsafe { mem::zeroed() };
    let empty = CString::new("").unwrap();
    if unsafe {
        libc::statx(
            file.as_raw_fd(),
            empty.as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_MNT_ID,
            &mut stat,
        )
    } < 0
        || stat.stx_mask & libc::STATX_MNT_ID == 0
    {
        return Err(Error::unavailable("Cannot verify storage mount boundary"));
    }
    Ok(stat.stx_mnt_id)
}
// Constant descriptor count and no recursion: tenant-created directory depth
// cannot exhaust the kernel process stack or its open-file limit. The caller
// has already stopped all writers, so the finite quota-limited tree cannot grow.
fn remove_contents(dir: &File, device: u64, mount: u64) -> Result<()> {
    use std::os::unix::fs::DirEntryExt;
    let top = dir.metadata()?.ino();
    let mut current = dir.try_clone()?;
    loop {
        if current.metadata()?.dev() != device || mount_id(&current)? != mount {
            return Err(Error::conflict("Volume deletion crossed a mount boundary"));
        }
        let entry = std::fs::read_dir(format!("/proc/self/fd/{}", current.as_raw_fd()))?
            .next()
            .transpose()?;
        if let Some(entry) = entry {
            let name = CString::new(entry.file_name().as_bytes())
                .map_err(|_| Error::invalid("Invalid volume entry name"))?;
            let mut stat: libc::stat = unsafe { mem::zeroed() };
            if unsafe {
                libc::fstatat(
                    current.as_raw_fd(),
                    name.as_ptr(),
                    &mut stat,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } < 0
            {
                return Err(io::Error::last_os_error().into());
            }
            if stat.st_dev != device {
                return Err(Error::conflict("Volume deletion crossed a filesystem"));
            }
            if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
                let child = open_at(&current, &name)?;
                if child.metadata()?.ino() != stat.st_ino {
                    return Err(Error::conflict("Volume deletion identity changed"));
                }
                current = child;
            } else if unsafe { libc::unlinkat(current.as_raw_fd(), name.as_ptr(), 0) } < 0 {
                return Err(io::Error::last_os_error().into());
            }
            continue;
        }
        current.sync_all()?;
        let inode = current.metadata()?.ino();
        if inode == top {
            break;
        }
        let parent = open_at(&current, &CString::new("..").unwrap())?;
        if parent.metadata()?.dev() != device || mount_id(&parent)? != mount {
            return Err(Error::conflict("Volume deletion crossed a mount boundary"));
        }
        let entry = std::fs::read_dir(format!("/proc/self/fd/{}", parent.as_raw_fd()))?
            .find_map(|entry| match entry {
                Ok(entry) if entry.ino() == inode => Some(Ok(entry)),
                Ok(_) => None,
                Err(e) => Some(Err(e)),
            })
            .transpose()?
            .ok_or_else(|| Error::conflict("Volume deletion parent changed"))?;
        let name = CString::new(entry.file_name().as_bytes())
            .map_err(|_| Error::invalid("Invalid volume entry name"))?;
        if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } < 0 {
            return Err(io::Error::last_os_error().into());
        }
        current = parent;
    }
    dir.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mount_paths_decode_only_kernel_mountinfo_escapes() {
        assert_eq!(
            decode_mount("/mount/with\\040space\\134slash").unwrap(),
            "/mount/with space\\slash"
        );
        assert!(decode_mount("/mount/invalid\\999").is_err());
    }
    #[test]
    fn deletion_walk_handles_deep_trees_without_following_symlinks() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let outside = tempfile::tempdir_in("/tmp").unwrap();
        let victim = outside.path().join("retained");
        std::fs::write(&victim, b"retained").unwrap();
        let top = File::open(root.path()).unwrap();
        let mut current = top.try_clone().unwrap();
        for _ in 0..2500 {
            let name = CString::new("d").unwrap();
            assert_eq!(
                unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), 0o700) },
                0
            );
            current = open_at(&current, &name).unwrap();
        }
        let link = CString::new("outside").unwrap();
        let target = CString::new(victim.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::symlinkat(target.as_ptr(), current.as_raw_fd(), link.as_ptr()) },
            0
        );
        drop(current);
        remove_contents(&top, top.metadata().unwrap().dev(), mount_id(&top).unwrap()).unwrap();
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
        assert_eq!(std::fs::read(victim).unwrap(), b"retained");
    }
    #[test]
    fn uapi_layout_and_capacity_boundaries() {
        assert_eq!(mem::size_of::<DiskQuota>(), 112);
        assert_eq!(mem::offset_of!(DiskQuota, rt_hard), 72);
        assert_eq!(mem::size_of::<QuotaState>(), 160);
        assert_eq!(mem::offset_of!(QuotaState, reserved), 104);
        assert_eq!(mem::size_of::<Xattr>(), 28);
        assert_eq!(mem::size_of::<Geometry>(), 112);
        assert_eq!(mem::offset_of!(Geometry, rt_blocks), 40);
        assert!(Limits {
            capacity_bytes: 1_048_576,
            inodes: 256
        }
        .validate(4096)
        .is_ok());
        for n in [0, 1_048_575, 1_048_577, MAX_BYTES, u64::MAX] {
            assert!(Limits {
                capacity_bytes: n,
                inodes: 256
            }
            .validate(4096)
            .is_err());
        }
        assert!(Limits {
            capacity_bytes: 1_048_576,
            inodes: 0
        }
        .validate(4096)
        .is_err());
        assert!(ProjectStore::validate_id(0).is_err());
        assert!(ProjectStore::validate_id(u32::MAX).is_err());
    }
    #[test]
    fn root_lock_distinguishes_contention_from_io_failure() {
        use std::os::unix::fs::OpenOptionsExt;

        let dir = tempfile::tempdir().unwrap();
        let held = File::open(dir.path()).unwrap();
        let other = File::open(dir.path()).unwrap();
        assert!(try_lock_root(&held).unwrap());
        assert!(!try_lock_root(&other).unwrap());
        drop(held);
        assert!(try_lock_root(&other).unwrap());

        let path_only = File::options()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open(dir.path())
            .unwrap();
        assert_eq!(
            try_lock_root(&path_only).unwrap_err().raw_os_error(),
            Some(libc::EBADF)
        );
    }

    #[test]
    fn rejects_unsafe_or_non_xfs_roots_without_mutation() {
        for p in ["relative", "/", "/etc/../etc", "/tmp", "/proc"] {
            assert!(check(Path::new(p)).is_err());
        }
        // Default tests need neither mount nor CAP_SYS_ADMIN.
        let d = tempfile::tempdir().unwrap();
        assert!(ProjectStore::open(d.path()).is_err());
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
    }
}
