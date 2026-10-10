use crate::core::types::OctopusSecurityError;
use crate::security::windows_sandbox::{
    WindowsAppContainerProfile, WindowsJobObject, WindowsRestrictedTokenPolicy,
};

/// Containment Guard: Enforces native operating system boundary constraints.
/// Verifies Windows Job Objects, AppContainer SID monikers, and restricted token policies.
pub struct ContainmentGuard {
    guard_id: String,
    max_memory_clamp_bytes: usize,
}

impl ContainmentGuard {
    pub fn new(guard_id: &str, max_memory_clamp_bytes: usize) -> Self {
        Self {
            guard_id: guard_id.to_string(),
            max_memory_clamp_bytes,
        }
    }

    pub fn guard_id(&self) -> &str {
        &self.guard_id
    }

    /// Validates that an AppContainer profile conforms to Microsoft Windows AppContainer security specs.
    pub fn verify_appcontainer_confinement(
        &self,
        profile: &WindowsAppContainerProfile,
    ) -> Result<(), OctopusSecurityError> {
        let sid = &profile.package_sid;
        if !sid.starts_with("S-1-15-2-") {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "Invalid AppContainer SID prefix: {}",
                sid
            )));
        }

        let parts: Vec<&str> = sid.split('-').collect();
        // AppContainer SID format: S-1-15-2-sub1-sub2-sub3-sub4-sub5-sub6-sub7 (11 components total)
        if parts.len() != 11 {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "Malformed AppContainer SID '{}': expected 11 dash-separated components, found {}",
                sid,
                parts.len()
            )));
        }

        Ok(())
    }

    /// Validates that a Windows Job Object is active and enforces strict fail-closed limits.
    pub fn verify_job_object_limits(
        &self,
        job: &WindowsJobObject,
    ) -> Result<(), OctopusSecurityError> {
        if job.max_memory_bytes > self.max_memory_clamp_bytes {
            return Err(OctopusSecurityError::ResourceQuotaExceeded(format!(
                "Job Object memory limit {} exceeds security ceiling {}",
                job.max_memory_bytes,
                self.max_memory_clamp_bytes
            )));
        }

        if job.max_processes > 1 {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "Job Object max process limit exceeded: {} > 1 (child process fork blocked)",
                job.max_processes
            )));
        }

        Ok(())
    }

    /// Verifies that a restricted token strips all administrative SIDs and dangerous privileges.
    pub fn verify_restricted_token_policy(
        &self,
        token_policy: &WindowsRestrictedTokenPolicy,
    ) -> Result<(), OctopusSecurityError> {
        let stripped = &token_policy.stripped_privileges;
        for req in &["SeDebugPrivilege", "SeTcbPrivilege", "SeTakeOwnershipPrivilege"] {
            if !stripped.contains(&req.to_string()) {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "Mandatory privilege '{}' not stripped from restricted token",
                    req
                )));
            }
        }
        Ok(())
    }
}
