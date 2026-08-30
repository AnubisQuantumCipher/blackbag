//! Process hardening applied before any secret enters memory.
//!
//! black-bagg 0.2.x did this and the 0.4.x rewrite dropped it. On a stock Omarchy
//! box the loss is not theoretical: `/proc/sys/kernel/core_pattern` pipes to
//! systemd-coredump, `ulimit -c` is unlimited, and zram swap is active — so a
//! crash while the vault is open writes the DEK and decrypted records to
//! `/var/lib/systemd/coredump`.

use std::fs;

/// What hardening actually took effect, so the UI can report it honestly
/// instead of asserting a posture it did not achieve.
#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub struct HardenReport {
    /// RLIMIT_CORE was set to 0.
    pub core_dumps_disabled: bool,
    /// PR_SET_DUMPABLE was set to 0 (also blocks ptrace by non-root).
    pub non_dumpable: bool,
    /// A debugger was attached when we looked.
    pub traced: bool,
    /// PR_SET_NO_NEW_PRIVS was set.
    pub no_new_privs: bool,
}

/// Apply every hardening step we can. Best-effort by design: a failure to
/// harden must not stop the user reaching their credentials, but it MUST be
/// visible, which is why this returns a report rather than swallowing results.
pub fn harden_process() -> HardenReport {
    let mut report = HardenReport::default();

    // 1. No core dumps. Belt: the resource limit. Braces: PR_SET_DUMPABLE, which
    //    also stops same-uid ptrace attach regardless of yama/ptrace_scope.
    let lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    report.core_dumps_disabled = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) } == 0;
    report.non_dumpable = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0;
    report.no_new_privs = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0;
    report.traced = tracer_pid().is_some();

    report
}

/// PID of an attached tracer, if any. Read from `/proc/self/status`; a missing
/// or unreadable field is reported as "no tracer seen", never as "safe".
pub fn tracer_pid() -> Option<i32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("TracerPid:"))?;
    let pid: i32 = line.split_whitespace().nth(1)?.parse().ok()?;
    if pid == 0 {
        None
    } else {
        Some(pid)
    }
}

/// Whether this system would write a core file for us if we crashed *right now*,
/// independent of what we asked for. Used by `doctor` to tell the truth about
/// the host rather than about our intent.
pub fn host_core_pattern() -> String {
    fs::read_to_string("/proc/sys/kernel/core_pattern")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Active swap devices. The Black-Bag threat model leans on "secrets never hit
/// disk"; on a box with zram or a swap partition that is only true because of
/// mlock, so the cockpit shows this next to the mlock state.
pub fn swap_devices() -> Vec<String> {
    let Ok(text) = fs::read_to_string("/proc/swaps") else {
        return Vec::new();
    };
    text.lines()
        .skip(1)
        .filter_map(|l| l.split_whitespace().next().map(str::to_string))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardening_is_reported_not_assumed() {
        let report = harden_process();
        // We cannot assert success — a container may forbid prctl — but the
        // report must be internally consistent with the tracer probe.
        assert_eq!(report.traced, tracer_pid().is_some());
    }

    #[test]
    fn host_probes_do_not_panic_on_odd_hosts() {
        let _ = host_core_pattern();
        let _ = swap_devices();
    }
}
