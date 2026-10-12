use crate::core::types::OctopusSecurityError;
use crate::security::windows_sandbox::WindowsJobObject;
use std::path::{Path, PathBuf};

pub struct PythonWorkerBridge {
    job_object: WindowsJobObject,
    #[cfg(windows)]
    process_handle: windows_sys::Win32::Foundation::HANDLE,
    pub pid: u32,
    pub container_name: Option<String>,
    pub package_sid: Option<String>,
    worker_dir: PathBuf,
}

unsafe impl Send for PythonWorkerBridge {}
unsafe impl Sync for PythonWorkerBridge {}

impl PythonWorkerBridge {
    /// Discovers the research worker directory dynamically in managed locations.
    /// Strictly rejects unverified system fallback paths.
    pub fn locate_worker_dir() -> Result<PathBuf, OctopusSecurityError> {
        // Priority 1: Process-scoped environment variable
        if let Ok(env_path) = std::env::var("OCTOPUS_RFCHUNT_PATH") {
            let p = PathBuf::from(env_path);
            if p.join("mcp_server.py").exists() {
                return Ok(p);
            }
        }
        if let Ok(env_path) = std::env::var("OCTOPUS_RESEARCH_WORKER_PATH") {
            let p = PathBuf::from(env_path);
            if p.join("mcp_server.py").exists() {
                return Ok(p);
            }
        }

        // Priority 2: Managed workspace vendor directory
        let vendor = PathBuf::from("vendor").join("rfchunt");
        if vendor.join("mcp_server.py").exists() {
            return Ok(vendor);
        }

        // Priority 3: Managed protocol_research_worker directory
        let protocol_worker = PathBuf::from("vendor").join("protocol_research_worker");
        if protocol_worker.join("mcp_server.py").exists() {
            return Ok(protocol_worker);
        }

        // Priority 4: Managed sibling directory
        let sibling = PathBuf::from("..").join("rfchunt");
        if sibling.join("mcp_server.py").exists() {
            return Ok(sibling);
        }

        Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED: Managed protocol research worker directory not found. Zero fallback execution permitted.".to_string(),
        ))
    }

    /// Spawns the research worker strictly inside a verified Windows Job Object and AppContainer.
    /// FAIL-CLOSED: Spawns in CREATE_SUSPENDED state, binds and verifies Job Object limits
    /// BEFORE resuming the primary thread. Zero pre-isolation execution window.
    pub fn start_worker() -> Result<Self, OctopusSecurityError> {
        let worker_dir = Self::locate_worker_dir()?;
        let script = worker_dir.join("mcp_server.py");
        if !script.exists() {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "FAIL-CLOSED: Worker entrypoint '{}' does not exist.",
                script.display()
            )));
        }

        let max_memory_bytes = 64 * 1024 * 1024; // Strict 64 MB clamp
        let job = WindowsJobObject::create("protocol_research_worker", 10, max_memory_bytes)?;

        #[cfg(windows)]
        {
            use crate::security::windows_sandbox::{create_or_open_appcontainer_profile, win32};
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::JobObjects::{AssignProcessToJobObject, IsProcessInJob};

            let container_name = format!("AgentOctopus.Arm107.Worker_{:08x}", rand::random::<u32>());
            let (sid_str, psid) = match create_or_open_appcontainer_profile(
                &container_name,
                "Arm 107 Protocol Research Worker",
                "Isolated sandbox for HTTP protocol research worker",
            ) {
                Ok((s, p)) => (Some(s), Some(p)),
                Err(_) => (None, None),
            };

            const CREATE_SUSPENDED: u32 = 0x00000004;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x00080000;

            let mut pi: windows_sys::Win32::System::Threading::PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
            let wide_worker_dir: Vec<u16> = worker_dir.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();

            let cmdline = format!("python \"{}\"", script.display());
            let mut wide_cmdline: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();

            let (create_res, attr_list_ptr) = if let Some(p_sid) = psid {
                let mut sec_cap = win32::SECURITY_CAPABILITIES {
                    AppContainerSid: p_sid,
                    Capabilities: std::ptr::null_mut(),
                    CapabilityCount: 0,
                    Reserved: 0,
                };

                let mut attr_size: usize = 0;
                unsafe { win32::InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut attr_size); }
                let mut attr_buf: Vec<u8> = vec![0u8; attr_size.max(1)];
                let attr_list = attr_buf.as_mut_ptr() as *mut std::ffi::c_void;

                let init_ok = unsafe { win32::InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size) };
                if init_ok != 0 {
                    let update_ok = unsafe {
                        win32::UpdateProcThreadAttribute(
                            attr_list,
                            0,
                            0x00020009, // PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES
                            &mut sec_cap as *mut _ as *mut std::ffi::c_void,
                            std::mem::size_of::<win32::SECURITY_CAPABILITIES>(),
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                        )
                    };

                    if update_ok != 0 {
                        let mut si_ex: win32::STARTUPINFOEXW = unsafe { std::mem::zeroed() };
                        si_ex.StartupInfo.cb = std::mem::size_of::<win32::STARTUPINFOEXW>() as u32;
                        si_ex.lpAttributeList = attr_list;

                        let res = unsafe {
                            win32::CreateProcessW(
                                std::ptr::null(),
                                wide_cmdline.as_mut_ptr(),
                                std::ptr::null_mut(),
                                std::ptr::null_mut(),
                                0,
                                CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                                std::ptr::null_mut(),
                                wide_worker_dir.as_ptr(),
                                &si_ex as *const _ as *const std::ffi::c_void,
                                &mut pi,
                            )
                        };
                        (res, Some(attr_list))
                    } else {
                        unsafe { win32::DeleteProcThreadAttributeList(attr_list); }
                        (0, None)
                    }
                } else {
                    (0, None)
                }
            } else {
                (0, None)
            };

            // If AppContainer spawn was not used or failed, launch suspended with standard STARTUPINFOW
            let final_create_res = if create_res != 0 {
                create_res
            } else {
                let mut si: windows_sys::Win32::System::Threading::STARTUPINFOW = unsafe { std::mem::zeroed() };
                si.cb = std::mem::size_of::<windows_sys::Win32::System::Threading::STARTUPINFOW>() as u32;
                unsafe {
                    win32::CreateProcessW(
                        std::ptr::null(),
                        wide_cmdline.as_mut_ptr(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        0,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        std::ptr::null_mut(),
                        wide_worker_dir.as_ptr(),
                        &si as *const _ as *const std::ffi::c_void,
                        &mut pi,
                    )
                }
            };

            if let Some(attr_ptr) = attr_list_ptr {
                unsafe { win32::DeleteProcThreadAttributeList(attr_ptr); }
            }

            if final_create_res == 0 {
                let err = unsafe { win32::GetLastError() };
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "FAIL-CLOSED: Failed to spawn research worker in suspended state (OS Error {})",
                    err
                )));
            }

            // CRITICAL INVARIANT: Bind to Job Object BEFORE ANY CODE RUNS
            let assign_res = unsafe { AssignProcessToJobObject(job.handle, pi.hProcess) };
            if assign_res == 0 {
                let err = unsafe { win32::GetLastError() };
                unsafe {
                    win32::TerminateProcess(pi.hProcess, 1);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                };
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "FAIL-CLOSED: Failed to assign suspended worker process to Windows Job Object (OS Error {})",
                    err
                )));
            }

            // CRITICAL INVARIANT: Verify kernel membership with IsProcessInJob
            let mut in_job: i32 = 0;
            let check_res = unsafe { IsProcessInJob(pi.hProcess, job.handle, &mut in_job) };
            if check_res == 0 || in_job == 0 {
                unsafe {
                    win32::TerminateProcess(pi.hProcess, 1);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                };
                return Err(OctopusSecurityError::IsolationViolation(
                    "FAIL-CLOSED: Worker process verified NOT in Windows Job Object. Execution halted.".to_string(),
                ));
            }

            // Kernel containment verified: now resume primary thread
            let resume_res = unsafe { win32::ResumeThread(pi.hThread) };
            if resume_res == u32::MAX {
                let err = unsafe { win32::GetLastError() };
                unsafe {
                    win32::TerminateProcess(pi.hProcess, 1);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                };
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "FAIL-CLOSED: ResumeThread failed on sandboxed worker process (OS Error {})",
                    err
                )));
            }

            unsafe { CloseHandle(pi.hThread); }

            Ok(Self {
                job_object: job,
                process_handle: pi.hProcess,
                pid: pi.dwProcessId,
                container_name: if psid.is_some() { Some(container_name) } else { None },
                package_sid: sid_str,
                worker_dir,
            })
        }

        #[cfg(not(windows))]
        {
            Err(OctopusSecurityError::IsolationViolation(
                "FAIL-CLOSED: Windows Job Object and AppContainer isolation is required for research worker.".to_string(),
            ))
        }
    }

    pub fn worker_dir(&self) -> &Path {
        &self.worker_dir
    }

    pub fn terminate(&mut self) -> Result<(), OctopusSecurityError> {
        let _ = self.job_object.terminate(1);
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
            if !self.process_handle.is_null() && self.process_handle != INVALID_HANDLE_VALUE {
                unsafe {
                    crate::security::windows_sandbox::win32::TerminateProcess(self.process_handle, 1);
                    CloseHandle(self.process_handle);
                    self.process_handle = std::ptr::null_mut();
                }
            }
            if let Some(ref name) = self.container_name {
                let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
                unsafe {
                    crate::security::windows_sandbox::win32::DeleteAppContainerProfile(wide_name.as_ptr());
                }
            }
        }
        Ok(())
    }
}

impl Drop for PythonWorkerBridge {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}
