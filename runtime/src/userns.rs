//! User namespaces: root inside the sandbox is an unprivileged UID on the host.
//!
//! Every sandbox maps its UIDs and GIDs 0..65536 to host IDs starting at
//! `ID_BASE`, which no real user owns. Inside, the command runs as uid 0 with
//! full capabilities, but those capabilities only count in its own user
//! namespace. Its mount, PID, UTS and cgroup namespaces were created before
//! the user namespace and still belong to the host's, so sandbox root can't
//! mount, unmount or change the hostname. If it ever escapes, it lands on the
//! host as uid 2000000000, which owns nothing.

use std::fs;

use anyhow::{Context, Result};
use nix::unistd::{Gid, Pid, Uid, setgroups, setresgid, setresuid};

/// First host UID/GID of the sandbox range. Well above the 524288..1074266112
/// range /etc/subuid gives the VM's user. Must match scripts/fetch-alpine.sh.
pub const ID_BASE: u32 = 2_000_000_000;
/// How many IDs each sandbox gets: 0..65535 inside, like a normal system.
pub const ID_COUNT: u32 = 65_536;

/// Writes the child's ID maps. Only a process outside the new user namespace
/// (with CAP_SETUID/CAP_SETGID over its parent namespace) is allowed to.
pub fn write_maps(pid: Pid) -> Result<()> {
    let map = format!("0 {ID_BASE} {ID_COUNT}");
    for file in ["uid_map", "gid_map"] {
        let path = format!("/proc/{pid}/{file}");
        fs::write(&path, &map).with_context(|| format!("write {map:?} to {path}"))?;
    }
    Ok(())
}

/// Called inside the new user namespace once the maps exist. Until then the
/// process shows up as the overflow ID (65534, "nobody"), because its real
/// host UID, 0, isn't in the map.
pub fn become_root() -> Result<()> {
    let root_gid = Gid::from_raw(0);
    let root_uid = Uid::from_raw(0);
    // Drop the host's supplementary groups; they mean nothing in here.
    setgroups(&[]).context("setgroups")?;
    setresgid(root_gid, root_gid, root_gid).context("setresgid")?;
    setresuid(root_uid, root_uid, root_uid).context("setresuid")?;
    Ok(())
}
