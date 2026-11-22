use agent_octopus::security::cedar_arm::CedarPolicyEngine;
use agent_octopus::security::executable_identity::{
    open_and_lock_executable_for_cli, ExecutableIdentityVerifier,
};
use agent_octopus::security::rate_limit_backoff::{
    CorrelatedEvidenceBundle, EdrAction, HarFlowFact, NetworkProtocol, PreSpawnReaPolicy,
    RateLimitVoterEnsemble, ReaBinaryFact, ReteEngine,
};
use agent_octopus::security::rea_binary_gate::{
    inspect_binary_bytes, inspect_locked_file, BinaryFormat,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

static TEST_SEQ: AtomicUsize = AtomicUsize::new(0);

struct TempFileGuard(PathBuf);

impl TempFileGuard {
    fn new(name: &str, bytes: &[u8]) -> Self {
        let seq = TEST_SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "octopus_rea_test_{}_{}_{}",
            std::process::id(),
            seq,
            name
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let p = dir.join(name);
        std::fs::write(&p, bytes).expect("write temp fixture");
        Self(p)
    }

    fn path(&self) -> &PathBuf {
        &self.0
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(parent) = self.0.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }
}

fn push_u16(buf: &mut Vec<u8>, v: u16, le: bool) {
    if le {
        buf.extend_from_slice(&v.to_le_bytes());
    } else {
        buf.extend_from_slice(&v.to_be_bytes());
    }
}

fn push_u32(buf: &mut Vec<u8>, v: u32, le: bool) {
    if le {
        buf.extend_from_slice(&v.to_le_bytes());
    } else {
        buf.extend_from_slice(&v.to_be_bytes());
    }
}

fn push_u64(buf: &mut Vec<u8>, v: u64, le: bool) {
    if le {
        buf.extend_from_slice(&v.to_le_bytes());
    } else {
        buf.extend_from_slice(&v.to_be_bytes());
    }
}

struct PeSectionSpec<'a> {
    name: &'a str,
    virtual_size: u32,
    virtual_addr: u32,
    characteristics: u32,
    data: &'a [u8],
    force_raw_size_zero: bool,
}

fn build_synthetic_pe(is_64: bool, sections: &[PeSectionSpec<'_>], with_cert: bool) -> Vec<u8> {
    let lfanew: usize = 0x80;
    let opt_size: usize = if is_64 { 240 } else { 224 };
    let sec_table_off = lfanew + 4 + 20 + opt_size;
    let headers_end = sec_table_off + sections.len() * 40;
    let first_sec_off = headers_end.div_ceil(0x200) * 0x200;

    let mut raw_offsets = Vec::with_capacity(sections.len());
    let mut cur_off = first_sec_off;
    for sec in sections {
        raw_offsets.push(cur_off);
        if !sec.force_raw_size_zero && !sec.data.is_empty() {
            let aligned = sec.data.len().div_ceil(0x200) * 0x200;
            cur_off += aligned;
        }
    }

    let cert_off = cur_off;
    let cert_blob = if with_cert {
        let mut c = Vec::new();
        // WIN_CERTIFICATE: dwLength=64, wRevision=0x0200, wCertificateType=0x0002 (PKCS_SIGNED_DATA)
        c.extend_from_slice(&64u32.to_le_bytes());
        c.extend_from_slice(&0x0200u16.to_le_bytes());
        c.extend_from_slice(&0x0002u16.to_le_bytes());
        c.resize(64, 0x30);
        c
    } else {
        Vec::new()
    };
    let total_len = cert_off + cert_blob.len();
    let mut buf = vec![0u8; total_len];

    // DOS header
    buf[0..2].copy_from_slice(b"MZ");
    buf[0x3C..0x40].copy_from_slice(&(lfanew as u32).to_le_bytes());

    // NT signature + COFF
    buf[lfanew..lfanew + 4].copy_from_slice(b"PE\0\0");
    let coff = lfanew + 4;
    let machine: u16 = if is_64 { 0x8664 } else { 0x014C };
    buf[coff..coff + 2].copy_from_slice(&machine.to_le_bytes());
    buf[coff + 2..coff + 4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
    buf[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());

    // Optional header
    let opt = coff + 20;
    let magic: u16 = if is_64 { 0x020B } else { 0x010B };
    buf[opt..opt + 2].copy_from_slice(&magic.to_le_bytes());
    let ep_rva = sections.first().map(|s| s.virtual_addr).unwrap_or(0x1000);
    buf[opt + 16..opt + 20].copy_from_slice(&ep_rva.to_le_bytes());

    let num_rva_off = if is_64 { opt + 108 } else { opt + 92 };
    let sec_dir_off = if is_64 { opt + 144 } else { opt + 128 };
    buf[num_rva_off..num_rva_off + 4].copy_from_slice(&16u32.to_le_bytes());
    if with_cert {
        buf[sec_dir_off..sec_dir_off + 4].copy_from_slice(&(cert_off as u32).to_le_bytes());
        buf[sec_dir_off + 4..sec_dir_off + 8]
            .copy_from_slice(&(cert_blob.len() as u32).to_le_bytes());
    }

    // Section headers + payloads
    for (i, sec) in sections.iter().enumerate() {
        let sh = sec_table_off + i * 40;
        let nb = sec.name.as_bytes();
        let copy_len = nb.len().min(8);
        buf[sh..sh + copy_len].copy_from_slice(&nb[..copy_len]);
        buf[sh + 8..sh + 12].copy_from_slice(&sec.virtual_size.to_le_bytes());
        buf[sh + 12..sh + 16].copy_from_slice(&sec.virtual_addr.to_le_bytes());
        let raw_sz = if sec.force_raw_size_zero {
            0u32
        } else {
            sec.data.len() as u32
        };
        let raw_ptr = if sec.force_raw_size_zero || sec.data.is_empty() {
            0u32
        } else {
            raw_offsets[i] as u32
        };
        buf[sh + 16..sh + 20].copy_from_slice(&raw_sz.to_le_bytes());
        buf[sh + 20..sh + 24].copy_from_slice(&raw_ptr.to_le_bytes());
        buf[sh + 36..sh + 40].copy_from_slice(&sec.characteristics.to_le_bytes());

        if !sec.force_raw_size_zero && !sec.data.is_empty() {
            let off = raw_offsets[i];
            buf[off..off + sec.data.len()].copy_from_slice(sec.data);
        }
    }

    if !cert_blob.is_empty() {
        buf[cert_off..cert_off + cert_blob.len()].copy_from_slice(&cert_blob);
    }

    buf
}

fn build_synthetic_elf(
    is_64: bool,
    le: bool,
    p_flags: u32,
    p_memsz_override: Option<u64>,
    force_filesz_zero: bool,
    payload: &[u8],
) -> Vec<u8> {
    build_synthetic_elf_with_machine(
        is_64,
        le,
        0x3E, // EM_X86_64
        p_flags,
        p_memsz_override,
        force_filesz_zero,
        payload,
    )
}

fn build_synthetic_elf_with_machine(
    is_64: bool,
    le: bool,
    e_machine: u16,
    p_flags: u32,
    p_memsz_override: Option<u64>,
    force_filesz_zero: bool,
    payload: &[u8],
) -> Vec<u8> {
    let ehdr_size = if is_64 { 64usize } else { 52usize };
    let phdr_size = if is_64 { 56usize } else { 32usize };
    let seg_off = 0x1000usize;

    let mut hdr = Vec::with_capacity(seg_off + payload.len());
    hdr.extend_from_slice(b"\x7FELF");
    hdr.push(if is_64 { 2 } else { 1 }); // EI_CLASS
    hdr.push(if le { 1 } else { 2 }); // EI_DATA
    hdr.push(1); // EI_VERSION
    hdr.resize(16, 0);

    push_u16(&mut hdr, 2, le); // ET_EXEC
    push_u16(&mut hdr, e_machine, le);
    push_u32(&mut hdr, 1, le); // e_version
    if is_64 {
        push_u64(&mut hdr, 0x401000, le); // e_entry
        push_u64(&mut hdr, ehdr_size as u64, le); // e_phoff
        push_u64(&mut hdr, 0, le); // e_shoff
    } else {
        push_u32(&mut hdr, 0x08048000, le); // e_entry
        push_u32(&mut hdr, ehdr_size as u32, le); // e_phoff
        push_u32(&mut hdr, 0, le); // e_shoff
    }
    push_u32(&mut hdr, 0, le); // e_flags
    push_u16(&mut hdr, ehdr_size as u16, le);
    push_u16(&mut hdr, phdr_size as u16, le);
    push_u16(&mut hdr, 1, le); // e_phnum
    push_u16(&mut hdr, 0, le);
    push_u16(&mut hdr, 0, le);
    push_u16(&mut hdr, 0, le);
    assert_eq!(hdr.len(), ehdr_size);

    let filesz = if force_filesz_zero {
        0u64
    } else {
        payload.len() as u64
    };
    let memsz = p_memsz_override.unwrap_or(filesz.max(4096));

    if is_64 {
        push_u32(&mut hdr, 1, le); // PT_LOAD
        push_u32(&mut hdr, p_flags, le);
        push_u64(&mut hdr, seg_off as u64, le);
        push_u64(&mut hdr, 0x401000, le);
        push_u64(&mut hdr, 0x401000, le);
        push_u64(&mut hdr, filesz, le);
        push_u64(&mut hdr, memsz, le);
        push_u64(&mut hdr, 0x1000, le);
    } else {
        push_u32(&mut hdr, 1, le); // PT_LOAD
        push_u32(&mut hdr, seg_off as u32, le);
        push_u32(&mut hdr, 0x08048000, le);
        push_u32(&mut hdr, 0x08048000, le);
        push_u32(&mut hdr, filesz as u32, le);
        push_u32(&mut hdr, memsz as u32, le);
        push_u32(&mut hdr, p_flags, le);
        push_u32(&mut hdr, 0x1000, le);
    }

    hdr.resize(seg_off, 0);
    if !force_filesz_zero {
        hdr.extend_from_slice(payload);
    }
    hdr
}

fn build_synthetic_macho64(
    le: bool,
    segname: &str,
    initprot: u32,
    signed: bool,
    payload: &[u8],
) -> Vec<u8> {
    build_synthetic_macho64_with_cputype(le, 0x0100_000C, segname, initprot, signed, payload)
}

fn build_synthetic_macho64_with_cputype(
    le: bool,
    cputype: u32,
    segname: &str,
    initprot: u32,
    signed: bool,
    payload: &[u8],
) -> Vec<u8> {
    let hdr_size = 32usize;
    let seg_cmd_size = 72usize;
    let sig_cmd_size = if signed { 16usize } else { 0usize };
    let sizeofcmds = (seg_cmd_size + sig_cmd_size) as u32;
    let ncmds = if signed { 2u32 } else { 1u32 };

    let seg_fileoff = 0x1000usize;
    let sig_off = seg_fileoff + ((payload.len().max(16) + 0xF) & !0xF);
    let sig_size = 32usize;

    let mut out = Vec::new();
    // magic
    if le {
        out.extend_from_slice(&0xFEED_FACFu32.to_le_bytes());
    } else {
        out.extend_from_slice(&0xFEED_FACFu32.to_be_bytes());
    }
    push_u32(&mut out, cputype, le);
    push_u32(&mut out, 0, le);
    push_u32(&mut out, 2, le); // MH_EXECUTE
    push_u32(&mut out, ncmds, le);
    push_u32(&mut out, sizeofcmds, le);
    push_u32(&mut out, 0, le);
    push_u32(&mut out, 0, le);
    assert_eq!(out.len(), hdr_size);

    // LC_SEGMENT_64 (0x19)
    push_u32(&mut out, 0x19, le);
    push_u32(&mut out, seg_cmd_size as u32, le);
    let mut name_buf = [0u8; 16];
    let nb = segname.as_bytes();
    let clen = nb.len().min(16);
    name_buf[..clen].copy_from_slice(&nb[..clen]);
    out.extend_from_slice(&name_buf);
    push_u64(&mut out, 0x1_0000_0000, le);
    push_u64(&mut out, (payload.len() as u64).max(4096), le);
    push_u64(&mut out, seg_fileoff as u64, le);
    push_u64(&mut out, payload.len() as u64, le);
    push_u32(&mut out, initprot, le); // maxprot
    push_u32(&mut out, initprot, le); // initprot
    push_u32(&mut out, 0, le);
    push_u32(&mut out, 0, le);

    if signed {
        push_u32(&mut out, 0x1D, le); // LC_CODE_SIGNATURE
        push_u32(&mut out, 16, le);
        push_u32(&mut out, sig_off as u32, le);
        push_u32(&mut out, sig_size as u32, le);
    }

    out.resize(seg_fileoff, 0);
    out.extend_from_slice(payload);
    if signed {
        out.resize(sig_off, 0);
        // SuperBlob magic 0xFADE0CC0 (always big-endian in Apple CodeSignature)
        out.extend_from_slice(&0xFADE_0CC0u32.to_be_bytes());
        out.extend_from_slice(&(sig_size as u32).to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.resize(sig_off + sig_size, 0);
    }
    out
}

fn high_entropy_bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((i.wrapping_mul(131).wrapping_add(i >> 3)) ^ (i * 17)) as u8)
        .collect()
}

#[test]
fn pe32_and_pe64_clean_signed_and_unsigned() {
    let benign_code = [0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3];
    for is_64 in [false, true] {
        let unsigned_pe = build_synthetic_pe(
            is_64,
            &[PeSectionSpec {
                name: ".text",
                virtual_size: 4096,
                virtual_addr: 0x1000,
                characteristics: 0x6000_0020, // CNT_CODE | MEM_EXECUTE | MEM_READ
                data: &benign_code,
                force_raw_size_zero: false,
            }],
            false,
        );
        let v = inspect_binary_bytes(&unsigned_pe, "clean.exe");
        assert_eq!(
            v.format,
            if is_64 {
                BinaryFormat::Pe64
            } else {
                BinaryFormat::Pe32
            }
        );
        assert!(!v.is_packed);
        assert!(!v.has_wx_violation);
        assert_eq!(v.direct_syscall_count, 0);
        assert!(!v.is_authenticode_signed);

        let signed_pe = build_synthetic_pe(
            is_64,
            &[PeSectionSpec {
                name: ".text",
                virtual_size: 4096,
                virtual_addr: 0x1000,
                characteristics: 0x6000_0020,
                data: &benign_code,
                force_raw_size_zero: false,
            }],
            true,
        );
        let vs = inspect_binary_bytes(&signed_pe, "signed.exe");
        assert!(vs.is_authenticode_signed);
        assert!(vs.is_code_signed);
        assert!(!vs.is_packed);
    }
}

#[test]
fn pe_packers_wx_entropy_and_hells_halos_gate_detection() {
    // 1. UPX0/UPX1 + hollow raw size + UPX!
    let upx_pe = build_synthetic_pe(
        true,
        &[
            PeSectionSpec {
                name: "UPX0",
                virtual_size: 0x10000,
                virtual_addr: 0x1000,
                characteristics: 0xE000_0080, // W^X + uninit
                data: &[],
                force_raw_size_zero: true,
            },
            PeSectionSpec {
                name: "UPX1",
                virtual_size: 0x4000,
                virtual_addr: 0x11000,
                characteristics: 0xE000_0060,
                data: b"UPX!packed_stub_payload",
                force_raw_size_zero: false,
            },
        ],
        false,
    );
    let vu = inspect_binary_bytes(&upx_pe, "upx.exe");
    assert!(vu.is_packed);
    assert!(vu.has_packer_marker);
    assert!(vu.has_wx_violation);
    assert!(vu.has_raw_size_anomaly);

    // 2. Other packer markers (MPRESS, VMProtect, Themida, ASPack)
    for sec in ["MPRESS1", ".vmp0", ".themida", ".aspack"] {
        let p = build_synthetic_pe(
            true,
            &[PeSectionSpec {
                name: sec,
                virtual_size: 4096,
                virtual_addr: 0x1000,
                characteristics: 0x6000_0020,
                data: b"\x90\x90\xC3",
                force_raw_size_zero: false,
            }],
            false,
        );
        let vp = inspect_binary_bytes(&p, sec);
        assert!(vp.has_packer_marker, "must detect packer section {}", sec);
        assert!(vp.is_packed, "must mark is_packed for {}", sec);
    }

    // 3. High entropy (>= 6.4) WITHOUT anomaly -> must NOT trigger is_packed (0 false positives!)
    let hi = high_entropy_bytes(8192);
    let clean_hi_pe = build_synthetic_pe(
        true,
        &[PeSectionSpec {
            name: ".text",
            virtual_size: 8192,
            virtual_addr: 0x1000,
            characteristics: 0x6000_0020,
            data: &hi,
            force_raw_size_zero: false,
        }],
        true,
    );
    let v_clean_hi = inspect_binary_bytes(&clean_hi_pe, "clean_hi.exe");
    assert!(v_clean_hi.obfuscation_entropy >= 6.4);
    assert!(
        !v_clean_hi.is_packed,
        "high-entropy clean PE without anomaly must NOT false-positive"
    );

    // 4. High entropy (>= 6.4) WITH W^X or raw-size anomaly -> must trigger is_packed
    let bad_hi_pe = build_synthetic_pe(
        true,
        &[PeSectionSpec {
            name: ".text",
            virtual_size: 8192,
            virtual_addr: 0x1000,
            characteristics: 0xE000_0020, // WRITE | EXECUTE
            data: &hi,
            force_raw_size_zero: false,
        }],
        false,
    );
    let v_bad_hi = inspect_binary_bytes(&bad_hi_pe, "bad_hi.exe");
    assert!(v_bad_hi.has_wx_violation);
    assert!(v_bad_hi.is_packed);

    // 5. Hell's Gate, Halo's Gate, alternate mov r10,rcx, and int 0x2e stubs
    let mut syscall_code = Vec::new();
    // Hell's Gate: 4C 8B D1 B8 18 00 00 00 0F 05
    syscall_code.extend_from_slice(&[
        0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
    ]);
    // Halo's Gate: 4C 8B D1 B8 19 00 00 00 90 90 90 0F 05
    syscall_code.extend_from_slice(&[
        0x4C, 0x8B, 0xD1, 0xB8, 0x19, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x0F, 0x05, 0xC3,
    ]);
    // Alt: 49 89 CA B8 1A 00 00 00 0F 05
    syscall_code.extend_from_slice(&[
        0x49, 0x89, 0xCA, 0xB8, 0x1A, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
    ]);
    // int 0x2e: 4C 8B D1 B8 1B 00 00 00 CD 2E
    syscall_code.extend_from_slice(&[
        0x4C, 0x8B, 0xD1, 0xB8, 0x1B, 0x00, 0x00, 0x00, 0xCD, 0x2E, 0xC3,
    ]);

    let syscall_pe = build_synthetic_pe(
        true,
        &[PeSectionSpec {
            name: ".text",
            virtual_size: 4096,
            virtual_addr: 0x1000,
            characteristics: 0x6000_0020,
            data: &syscall_code,
            force_raw_size_zero: false,
        }],
        false,
    );
    let v_sys = inspect_binary_bytes(&syscall_pe, "hells_gate.exe");
    assert_eq!(
        v_sys.direct_syscall_count, 4,
        "{:?}",
        v_sys.syscall_stub_details
    );
}

#[test]
fn elf32_elf64_le_be_wx_upx_and_syscall_sleds() {
    let benign = [0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3];
    for (is_64, le) in [(false, true), (false, false), (true, true), (true, false)] {
        let clean =
            build_synthetic_elf(is_64, le, 0x5 /* PF_R | PF_X */, None, false, &benign);
        let vc = inspect_binary_bytes(&clean, "clean.elf");
        assert_eq!(
            vc.format,
            if is_64 {
                BinaryFormat::Elf64
            } else {
                BinaryFormat::Elf32
            }
        );
        assert!(!vc.has_wx_violation);
        assert!(!vc.is_packed);
        assert_eq!(vc.direct_syscall_count, 0);

        let wx = build_synthetic_elf(
            is_64,
            le,
            0x7, /* PF_R | PF_W | PF_X */
            None,
            false,
            b"UPX!stub",
        );
        let vwx = inspect_binary_bytes(&wx, "wx_upx.elf");
        assert!(vwx.has_wx_violation);
        assert!(vwx.is_packed);
    }

    // x86-64 ELF direct-syscall stub sled
    let mut x64_sled = Vec::new();
    x64_sled.extend_from_slice(&[0xB8, 0x3B, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3]); // execve
    x64_sled.extend_from_slice(&[0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3]); // write
    let elf_x64_sys = build_synthetic_elf(true, true, 0x5, None, false, &x64_sled);
    let vx64 = inspect_binary_bytes(&elf_x64_sys, "x64_sled.elf");
    assert!(
        vx64.direct_syscall_count >= 2,
        "{:?}",
        vx64.syscall_stub_details
    );

    // AArch64 ELF direct-syscall stub sled (LE & BE): mov x8, #221 (0xD2801BA8); svc #0 (0xD4000001)
    for le in [true, false] {
        let mut arm64_sled = Vec::new();
        push_u32(&mut arm64_sled, 0xD280_1BA8, le);
        push_u32(&mut arm64_sled, 0xD400_0001, le);
        push_u32(&mut arm64_sled, 0xD280_07E8, le);
        push_u32(&mut arm64_sled, 0xD400_0001, le);
        let elf_arm64 = build_synthetic_elf_with_machine(
            true,
            le,
            183, // EM_AARCH64
            0x5,
            None,
            false,
            &arm64_sled,
        );
        let va64 = inspect_binary_bytes(&elf_arm64, "arm64_sled.elf");
        assert_eq!(
            va64.direct_syscall_count, 2,
            "le={}: {:?}",
            le, va64.syscall_stub_details
        );
    }
}

#[test]
fn macho64_fat_signed_wx_svc80_and_java_class_negative() {
    let benign = [0xD6, 0x5F, 0x03, 0xC0];
    let clean_signed = build_synthetic_macho64(true, "__TEXT", 0x5, true, &benign);
    let vcs = inspect_binary_bytes(&clean_signed, "clean_signed.macho");
    assert_eq!(vcs.format, BinaryFormat::MachO64);
    assert!(vcs.is_code_signed);
    assert!(vcs.is_authenticode_signed);
    assert!(!vcs.is_packed);
    assert!(!vcs.has_wx_violation);

    let unsigned_wx = build_synthetic_macho64(true, "__TEXT", 0x7, false, b"UPX!bad");
    let vwx = inspect_binary_bytes(&unsigned_wx, "wx.macho");
    assert!(!vwx.is_code_signed);
    assert!(vwx.has_wx_violation);
    assert!(vwx.is_packed);

    // ARM64 Darwin svc #0x80 stub sled: mov x16, #59 (0xD2800770); svc #0x80 (0xD4001001)
    let mut darwin_sled = Vec::new();
    push_u32(&mut darwin_sled, 0xD280_0770, true);
    push_u32(&mut darwin_sled, 0xD400_1001, true);
    push_u32(&mut darwin_sled, 0xD280_0090, true);
    push_u32(&mut darwin_sled, 0xD400_1001, true);
    let macho_sys = build_synthetic_macho64(true, "__TEXT", 0x5, true, &darwin_sled);
    let vms = inspect_binary_bytes(&macho_sys, "svc80.macho");
    assert_eq!(
        vms.direct_syscall_count, 2,
        "{:?}",
        vms.syscall_stub_details
    );

    // Fat Mach-O combining clean signed slice + W^X unsigned slice -> fail-closed worst case
    let slice0_off = 0x1000u32;
    let slice1_off = 0x1000u32 + ((clean_signed.len() as u32 + 0xFFF) & !0xFFF);
    let mut fat = Vec::new();
    fat.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes());
    fat.extend_from_slice(&2u32.to_be_bytes()); // nfat_arch = 2
                                                // fat_arch 0
    fat.extend_from_slice(&0x0100_000Cu32.to_be_bytes());
    fat.extend_from_slice(&0u32.to_be_bytes());
    fat.extend_from_slice(&slice0_off.to_be_bytes());
    fat.extend_from_slice(&(clean_signed.len() as u32).to_be_bytes());
    fat.extend_from_slice(&12u32.to_be_bytes());
    // fat_arch 1
    fat.extend_from_slice(&0x0100_0007u32.to_be_bytes());
    fat.extend_from_slice(&3u32.to_be_bytes());
    fat.extend_from_slice(&slice1_off.to_be_bytes());
    fat.extend_from_slice(&(unsigned_wx.len() as u32).to_be_bytes());
    fat.extend_from_slice(&12u32.to_be_bytes());

    fat.resize(slice0_off as usize, 0);
    fat.extend_from_slice(&clean_signed);
    fat.resize(slice1_off as usize, 0);
    fat.extend_from_slice(&unsigned_wx);

    let vfat = inspect_binary_bytes(&fat, "universal_bad.macho");
    assert_eq!(vfat.format, BinaryFormat::MachOFat);
    assert!(vfat.has_wx_violation);
    assert!(vfat.is_packed);
    assert!(
        !vfat.is_code_signed,
        "Fat with 1 unsigned slice must report unsigned"
    );

    // Java .class negative test (0xCAFEBABE, minor=0, major=65)
    let mut java_class = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x41];
    java_class.resize(512, 0x22);
    let vj = inspect_binary_bytes(&java_class, "Agent.class");
    assert_eq!(vj.format, BinaryFormat::Unknown);
    assert!(!vj.is_packed);
    assert!(!vj.has_wx_violation);
}

#[test]
fn truncated_and_malformed_headers_never_panic() {
    let empty: &[u8] = &[];
    let _ = inspect_binary_bytes(empty, "empty");
    for prefix in [
        b"MZ".as_slice(),
        b"\x7FELF".as_slice(),
        b"\xCF\xFA\xED\xFE".as_slice(),
        b"\xCA\xFE\xBA\xBE".as_slice(),
    ] {
        for len in 1..=64 {
            let mut buf = vec![0xFFu8; len];
            let cp = prefix.len().min(len);
            buf[..cp].copy_from_slice(&prefix[..cp]);
            let _ = inspect_binary_bytes(&buf, "trunc");
        }
    }

    // Extreme PE values: e_lfanew = u32::MAX, NumberOfSections = u16::MAX, cert_off = u32::MAX
    let mut bad_pe = vec![0u8; 256];
    bad_pe[0..2].copy_from_slice(b"MZ");
    bad_pe[0x3C..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
    let _ = inspect_binary_bytes(&bad_pe, "max_lfanew");

    bad_pe[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    bad_pe[0x40..0x44].copy_from_slice(b"PE\0\0");
    bad_pe[0x44 + 2..0x44 + 4].copy_from_slice(&u16::MAX.to_le_bytes());
    let _ = inspect_binary_bytes(&bad_pe, "max_sections");

    // Extreme ELF values: e_phoff = u64::MAX, e_phnum = u16::MAX
    let mut bad_elf = vec![0u8; 128];
    bad_elf[0..4].copy_from_slice(b"\x7FELF");
    bad_elf[4] = 2;
    bad_elf[5] = 1;
    bad_elf[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    bad_elf[56..58].copy_from_slice(&u16::MAX.to_le_bytes());
    let _ = inspect_binary_bytes(&bad_elf, "max_elf");

    // Extreme Mach-O values: ncmds = u32::MAX, cmdsize = 0
    let mut bad_macho = vec![0u8; 64];
    bad_macho[0..4].copy_from_slice(&0xFEED_FACFu32.to_le_bytes());
    bad_macho[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    bad_macho[20..24].copy_from_slice(&32u32.to_le_bytes());
    let _ = inspect_binary_bytes(&bad_macho, "max_macho");
}

#[test]
fn sub_2ms_latency_sla_on_large_12mb_binary_and_current_exe() {
    // 1. 12 MiB synthetic PE binary (both slice and locked file handle)
    let big_code = vec![0x90u8; 12 * 1024 * 1024];
    let big_pe = build_synthetic_pe(
        true,
        &[PeSectionSpec {
            name: ".text",
            virtual_size: big_code.len() as u32,
            virtual_addr: 0x1000,
            characteristics: 0x6000_0020,
            data: &big_code,
            force_raw_size_zero: false,
        }],
        true,
    );
    assert!(big_pe.len() >= 12 * 1024 * 1024);

    let mut slice_micros = Vec::with_capacity(20);
    for _ in 0..20 {
        let t0 = Instant::now();
        let v = inspect_binary_bytes(&big_pe, "big_12mb.exe");
        let dt = t0.elapsed().as_micros() as u64;
        assert!(!v.is_packed);
        assert!(v.is_authenticode_signed);
        slice_micros.push(dt);
    }
    slice_micros.sort_unstable();
    let p95_slice = slice_micros[18];
    assert!(
        p95_slice < 2_000,
        "12 MiB slice inspection p95={}us exceeded 2000us SLA: {:?}",
        p95_slice,
        slice_micros
    );

    // 2. Real locked handle on current_exe() (20 iterations: p95 < 2000us)
    let cur_exe = std::env::current_exe().expect("current_exe");
    let mut cur_micros = Vec::with_capacity(20);
    for _ in 0..20 {
        let mut locked = open_and_lock_executable_for_cli(&cur_exe, "test_bin")
            .expect("lock current_exe for CLI");
        let v_exe = inspect_locked_file(
            &mut locked.locked_file,
            &cur_exe,
            locked.metadata.file_size,
            &locked.metadata.normalized_stem,
            false,
        )
        .expect("inspect current_exe");
        assert!(!v_exe.is_packed);
        cur_micros.push(v_exe.inspection_micros);
    }
    cur_micros.sort_unstable();
    let p95_cur = cur_micros[18];
    assert!(
        p95_cur < 2_000,
        "current_exe inspection p95={}us exceeded 2000us SLA: {:?}",
        p95_cur,
        cur_micros
    );

    // Tier-2 verifier must STILL reject python!
    assert!(
        ExecutableIdentityVerifier::default()
            .verify_and_lock("python", None)
            .is_err(),
        "Tier-2 ExecutableIdentityVerifier must continue rejecting python"
    );

    // On Windows, System32\cmd.exe must pass Windows Catalog check when check_catalog_sig=true
    #[cfg(windows)]
    {
        let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let cmd_path = PathBuf::from(sys_root).join("System32").join("cmd.exe");
        if cmd_path.exists() {
            let mut cmd_locked =
                open_and_lock_executable_for_cli(&cmd_path, "cmd").expect("lock System32 cmd.exe");
            let v_cmd = inspect_locked_file(
                &mut cmd_locked.locked_file,
                &cmd_path,
                cmd_locked.metadata.file_size,
                "cmd",
                true,
            )
            .expect("inspect cmd.exe");
            assert!(
                v_cmd.is_authenticode_signed,
                "cmd.exe must verify via Windows Catalog"
            );
            assert!(!v_cmd.is_packed);
            assert_eq!(v_cmd.direct_syscall_count, 0);
        }
    }

    // 3. Uncached 12 MiB locked-file inspection across 5 warm-on-disk files (avoids single-shot
    // Windows Defender temp-.exe cold-write AV scan flake while genuinely measuring uncached I/O + parse)
    use std::io::Read;
    let guards: Vec<TempFileGuard> = (0..5)
        .map(|i| TempFileGuard::new(&format!("big12mb_{}.exe", i), &big_pe))
        .collect();
    for g in &guards {
        if let Ok(mut f) = std::fs::File::open(g.path()) {
            let mut tmp = [0u8; 64];
            let _ = f.read(&mut tmp);
        }
    }
    let mut file_micros = Vec::with_capacity(guards.len());
    for g in &guards {
        let mut big_locked =
            open_and_lock_executable_for_cli(g.path(), "big12mb").expect("lock 12mb temp");
        let v_file = inspect_locked_file(
            &mut big_locked.locked_file,
            g.path(),
            big_locked.metadata.file_size,
            "big12mb",
            false,
        )
        .expect("inspect 12mb locked file");
        assert!(!v_file.is_packed);
        file_micros.push(v_file.inspection_micros);
    }
    file_micros.sort_unstable();
    let median_file = file_micros[file_micros.len() / 2];
    assert!(
        median_file < 2_000,
        "12 MiB locked file uncached median={}us exceeded 2000us SLA: {:?}",
        median_file,
        file_micros
    );

    // 4. Cached 12 MiB locked-file inspection (20 iterations: p95 < 2000us)
    let mut cached_micros = Vec::with_capacity(20);
    for _ in 0..20 {
        let mut big_locked =
            open_and_lock_executable_for_cli(guards[0].path(), "big12mb").expect("lock 12mb temp");
        let v_file = inspect_locked_file(
            &mut big_locked.locked_file,
            guards[0].path(),
            big_locked.metadata.file_size,
            "big12mb",
            false,
        )
        .expect("inspect cached 12mb locked file");
        cached_micros.push(v_file.inspection_micros);
    }
    cached_micros.sort_unstable();
    let p95_cached = cached_micros[18];
    assert!(
        p95_cached < 2_000,
        "12 MiB locked file cached p95={}us exceeded 2000us SLA: {:?}",
        p95_cached,
        cached_micros
    );
}

#[test]
fn rete_bridge_and_cedar_strict_validation_for_rea_exec_attributes() {
    let cedar_src = r#"
permit (
    principal,
    action == Octopus::Action::"exec",
    resource is Octopus::Command
) when {
    !(context has is_packed && context.is_packed)
    && !(context has has_wx_violation && context.has_wx_violation)
    && !(context has direct_syscall_count && context.direct_syscall_count > 0)
};
forbid (
    principal,
    action == Octopus::Action::"exec",
    resource is Octopus::Command
) when {
    (context has is_packed && context.is_packed)
    || (context has has_wx_violation && context.has_wx_violation)
    || (context has direct_syscall_count && context.direct_syscall_count > 0)
    || (context has obfuscation_entropy_x100 && context.obfuscation_entropy_x100 >= 640
        && context has high_obfuscation_entropy && context.high_obfuscation_entropy
        && !(context has is_authenticode_signed && context.is_authenticode_signed))
    || (context has binary_format && context.binary_format == "unknown")
};
"#;
    let engine = CedarPolicyEngine::from_validated_policy_set(cedar_src)
        .expect("Cedar schema ValidationMode::Strict must accept REA exec attributes");

    let ok_eval = engine
        .evaluate(
            "cli_runner",
            "exec",
            "python",
            "Command",
            serde_json::json!({
                "executable": "python",
                "stem": "python",
                "args_joined": "python app.py",
                "cwd": "/tmp",
                "sandbox_mode": "standard",
                "is_wasm": false,
                "is_packed": false,
                "has_wx_violation": false,
                "direct_syscall_count": 0,
                "obfuscation_entropy_x100": 556,
                "high_obfuscation_entropy": false,
                "is_authenticode_signed": true,
                "binary_format": "pe64"
            }),
        )
        .expect("cedar eval clean");
    assert!(ok_eval.is_allowed);

    let bad_eval = engine
        .evaluate(
            "cli_runner",
            "exec",
            "evil",
            "Command",
            serde_json::json!({
                "executable": "evil.exe",
                "stem": "evil",
                "args_joined": "evil.exe",
                "cwd": "/tmp",
                "sandbox_mode": "standard",
                "is_wasm": false,
                "is_packed": true,
                "has_wx_violation": true,
                "direct_syscall_count": 2,
                "obfuscation_entropy_x100": 725,
                "high_obfuscation_entropy": true,
                "is_authenticode_signed": false,
                "binary_format": "pe64"
            }),
        )
        .expect("cedar eval packed");
    assert!(!bad_eval.is_allowed);

    // Verify RETE gate & Hard Invariant 1 end-to-end
    let rete = ReteEngine::new();
    let fact = ReaBinaryFact {
        pid: 4242,
        binary_path: "packed.exe".into(),
        is_packed: true,
        direct_syscall_count: 1,
        obfuscation_entropy: 7.0,
        is_authenticode_signed: false,
        yara_detections: vec![],
    };
    let gate_res = rete.evaluate_pre_spawn_rea_gate(
        fact.clone(),
        true,
        false,
        &[],
        BinaryFormat::Pe64,
        &PreSpawnReaPolicy::default(),
    );
    assert!(!gate_res.allowed);
    let bundle = CorrelatedEvidenceBundle {
        pid: 4242,
        flow: Some(HarFlowFact {
            flow_id: "f".into(),
            pid: 4242,
            protocol: NetworkProtocol::HttpHttps,
            dst_host: "example.com".into(),
            dst_port: 443,
            samples: vec![],
            backoff_compliant: true,
            observed_jitter_present: true,
            honors_retry_after: true,
            flood_detected: false,
        }),
        process: None,
        binary: Some(fact),
        protocol: NetworkProtocol::HttpHttps,
        dst_host: "example.com".into(),
    };
    let consensus = RateLimitVoterEnsemble.evaluate_and_vote(&bundle);
    assert!(
        !matches!(
            consensus.action,
            EdrAction::AllowAndWhitelistWindow {
                duration_secs: 3600,
                ..
            }
        ),
        "Hard Invariant 1 must not whitelist packed binary"
    );
}

#[test]
fn iter2_forged_win_certificate_syscall_variants_low_entropy_anomalies_and_fair_budget() {
    // 1. Direct-syscall stub variants (all 4 newly covered forms)
    let mut variants = Vec::new();
    // 49 89 CA B8 1A 00 00 00 90 90 0F 05
    variants.extend_from_slice(&[
        0x49, 0x89, 0xCA, 0xB8, 0x1A, 0x00, 0x00, 0x00, 0x90, 0x90, 0x0F, 0x05, 0xC3,
    ]);
    // 49 89 CA B8 1B 00 00 00 CD 2E
    variants.extend_from_slice(&[
        0x49, 0x89, 0xCA, 0xB8, 0x1B, 0x00, 0x00, 0x00, 0xCD, 0x2E, 0xC3,
    ]);
    // 4C 8B D1 B8 18 00 00 00 + 24x 0x90 + 0F 05
    variants.extend_from_slice(&[0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00]);
    variants.extend(std::iter::repeat_n(0x90u8, 24));
    variants.extend_from_slice(&[0x0F, 0x05, 0xC3]);
    // 49 89 CA B8 1C 00 00 00 + 24x 0x90 + CD 2E
    variants.extend_from_slice(&[0x49, 0x89, 0xCA, 0xB8, 0x1C, 0x00, 0x00, 0x00]);
    variants.extend(std::iter::repeat_n(0x90u8, 24));
    variants.extend_from_slice(&[0xCD, 0x2E, 0xC3]);

    let var_pe = build_synthetic_pe(
        true,
        &[PeSectionSpec {
            name: ".text",
            virtual_size: 4096,
            virtual_addr: 0x1000,
            characteristics: 0x6000_0020,
            data: &variants,
            force_raw_size_zero: false,
        }],
        false,
    );
    let vv = inspect_binary_bytes(&var_pe, "variants.exe");
    assert_eq!(
        vv.direct_syscall_count, 4,
        "all 4 direct-syscall stub variants must be detected: {:?}",
        vv.syscall_stub_details
    );

    // 2. ep_in_writable_section (with Hell's Gate inside writable .data) & hollow_exec_section at low entropy (< 6.4)
    let ep_data_pe = build_synthetic_pe(
        true,
        &[PeSectionSpec {
            name: ".data",
            virtual_size: 4096,
            virtual_addr: 0x1000,
            characteristics: 0xC000_0040, // CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE (NO EXEC!)
            data: &[0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05],
            force_raw_size_zero: false,
        }],
        false,
    );
    let v_ep = inspect_binary_bytes(&ep_data_pe, "ep_in_data.exe");
    assert!(v_ep.has_raw_size_anomaly);
    assert!(v_ep.obfuscation_entropy < 6.4);
    assert_eq!(
        v_ep.direct_syscall_count, 1,
        "EP section must be scanned even without IMAGE_SCN_MEM_EXECUTE"
    );

    let hollow_pe = build_synthetic_pe(
        true,
        &[PeSectionSpec {
            name: ".text",
            virtual_size: 0x10000,
            virtual_addr: 0x1000,
            characteristics: 0x6000_0020,
            data: &[],
            force_raw_size_zero: true,
        }],
        false,
    );
    let v_hollow = inspect_binary_bytes(&hollow_pe, "hollow_exec.exe");
    assert!(v_hollow.has_raw_size_anomaly);
    assert!(v_hollow.obfuscation_entropy < 6.4);

    let rete = ReteEngine::new();
    let gate_ep = rete.evaluate_pre_spawn_rea_gate(
        v_ep.to_rea_binary_fact(5001),
        v_ep.has_wx_violation,
        v_ep.has_raw_size_anomaly,
        &v_ep.header_anomalies,
        v_ep.format,
        &PreSpawnReaPolicy::default(),
    );
    assert!(!gate_ep.allowed);
    let gate_hollow = rete.evaluate_pre_spawn_rea_gate(
        v_hollow.to_rea_binary_fact(5002),
        v_hollow.has_wx_violation,
        v_hollow.has_raw_size_anomaly,
        &v_hollow.header_anomalies,
        v_hollow.format,
        &PreSpawnReaPolicy::default(),
    );
    assert!(!gate_hollow.allowed);
    assert!(gate_hollow
        .reasons
        .iter()
        .any(|r| r.contains("raw_size_or_section_anomaly")));

    // 3. Fair per-section exec scan budget: two 256 KiB NOP sections cannot hide a 3rd .evil section
    let nop_256k = vec![0x90u8; 256 * 1024];
    let evil_stub = [
        0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
    ];
    let budget_pe = build_synthetic_pe(
        true,
        &[
            PeSectionSpec {
                name: ".text0",
                virtual_size: nop_256k.len() as u32,
                virtual_addr: 0x1000,
                characteristics: 0x6000_0020,
                data: &nop_256k,
                force_raw_size_zero: false,
            },
            PeSectionSpec {
                name: ".text1",
                virtual_size: nop_256k.len() as u32,
                virtual_addr: 0x50000,
                characteristics: 0x6000_0020,
                data: &nop_256k,
                force_raw_size_zero: false,
            },
            PeSectionSpec {
                name: ".evil",
                virtual_size: 4096,
                virtual_addr: 0xA0000,
                characteristics: 0x6000_0020,
                data: &evil_stub,
                force_raw_size_zero: false,
            },
        ],
        false,
    );
    let v_budget = inspect_binary_bytes(&budget_pe, "budget_bypass.exe");
    assert_eq!(
        v_budget.direct_syscall_count, 1,
        "3rd .evil section after two 256 KiB sections must still be scanned: {:?}",
        v_budget.syscall_stub_details
    );

    // 4. Forged dummy WIN_CERTIFICATE must be rejected by inspect_locked_file when check_catalog_sig=true on Windows
    #[cfg(windows)]
    {
        let forged_pe = build_synthetic_pe(
            true,
            &[PeSectionSpec {
                name: ".text",
                virtual_size: 4096,
                virtual_addr: 0x1000,
                characteristics: 0x6000_0020,
                data: &[0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3],
                force_raw_size_zero: false,
            }],
            true,
        );
        // Pure slice parser checks structure
        let v_slice = inspect_binary_bytes(&forged_pe, "forged_slice.exe");
        assert!(v_slice.is_authenticode_signed);

        // Live locked-file gate with check_catalog_sig=true MUST cryptographically verify and reject dummy WIN_CERTIFICATE
        let g = TempFileGuard::new("forged_cert.exe", &forged_pe);
        let mut locked =
            open_and_lock_executable_for_cli(g.path(), "forged_cert").expect("lock forged_cert");
        let v_live = inspect_locked_file(
            &mut locked.locked_file,
            g.path(),
            locked.metadata.file_size,
            "forged_cert",
            true,
        )
        .expect("inspect forged_cert");
        assert!(
            !v_live.is_authenticode_signed && !v_live.is_code_signed,
            "forged dummy WIN_CERTIFICATE must fail cryptographic WinVerifyTrust check"
        );
    }
}

#[test]
fn iter3_reordered_and_interleaved_direct_syscalls_and_zero_false_positives() {
    let cases: [(&str, &[u8]); 6] = [
        (
            "reordered_b8_first_4c8bd1_0f05",
            &[
                0xB8, 0x18, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xD1, 0x0F, 0x05, 0xC3,
            ],
        ),
        (
            "reordered_b8_first_4989ca_cd2e",
            &[
                0xB8, 0x18, 0x00, 0x00, 0x00, 0x49, 0x89, 0xCA, 0xCD, 0x2E, 0xC3,
            ],
        ),
        (
            "reordered_b8_first_4989ca_nops_0f05",
            &[
                0xB8, 0x1A, 0x00, 0x00, 0x00, 0x49, 0x89, 0xCA, 0x90, 0x90, 0x0F, 0x05, 0xC3,
            ],
        ),
        (
            "interleaved_4c8bd1_2nops_b8_0f05",
            &[
                0x4C, 0x8B, 0xD1, 0x90, 0x90, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
            ],
        ),
        (
            "interleaved_4989ca_nop_b8_cd2e",
            &[
                0x49, 0x89, 0xCA, 0x90, 0xB8, 0x1B, 0x00, 0x00, 0x00, 0xCD, 0x2E, 0xC3,
            ],
        ),
        (
            "interleaved_12byte_lookbehind_boundary",
            &[
                0x4C, 0x8B, 0xD1, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xB8, 0x1C,
                0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
            ],
        ),
    ];

    let rete = ReteEngine::new();
    let mut combined = Vec::new();
    for (name, bytes) in cases {
        combined.extend_from_slice(bytes);
        let pe = build_synthetic_pe(
            true,
            &[PeSectionSpec {
                name: ".text",
                virtual_size: 4096,
                virtual_addr: 0x1000,
                characteristics: 0x6000_0020,
                data: bytes,
                force_raw_size_zero: false,
            }],
            false,
        );
        let v = inspect_binary_bytes(&pe, name);
        assert_eq!(
            v.direct_syscall_count, 1,
            "case {} must detect exactly 1 direct syscall stub: {:?}",
            name, v.syscall_stub_details
        );
        let gate = rete.evaluate_pre_spawn_rea_gate(
            v.to_rea_binary_fact(6001),
            v.has_wx_violation,
            v.has_raw_size_anomaly,
            &v.header_anomalies,
            v.format,
            &PreSpawnReaPolicy::default(),
        );
        assert!(
            !gate.allowed,
            "case {} must be denied by RETE pre-spawn gate",
            name
        );
    }

    let combined_pe = build_synthetic_pe(
        true,
        &[PeSectionSpec {
            name: ".text",
            virtual_size: 4096,
            virtual_addr: 0x1000,
            characteristics: 0x6000_0020,
            data: &combined,
            force_raw_size_zero: false,
        }],
        false,
    );
    let vc = inspect_binary_bytes(&combined_pe, "combined_iter3.exe");
    assert_eq!(
        vc.direct_syscall_count, 6,
        "all 6 reordered/interleaved stubs must be detected without double-counting: {:?}",
        vc.syscall_stub_details
    );

    // Negative check: current_exe() is clean of packing/W^X (note: test binary itself embeds
    // inline Hell's Gate byte literals as movabs immediates in .text), and real host binaries
    // (cmd.exe, where.exe, python.exe, git.exe, octopus.exe) must have 0 direct syscall false positives.
    let cur_exe = std::env::current_exe().expect("current_exe");
    let mut cur_locked =
        open_and_lock_executable_for_cli(&cur_exe, "test_bin").expect("lock current_exe");
    let v_cur = inspect_locked_file(
        &mut cur_locked.locked_file,
        &cur_exe,
        cur_locked.metadata.file_size,
        &cur_locked.metadata.normalized_stem,
        false,
    )
    .expect("inspect current_exe");
    assert!(!v_cur.is_packed);
    assert!(!v_cur.has_wx_violation);

    #[cfg(windows)]
    {
        let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let mut host_candidates: Vec<(String, PathBuf)> = vec![
            (
                "cmd".to_string(),
                PathBuf::from(&sys_root).join("System32").join("cmd.exe"),
            ),
            (
                "where".to_string(),
                PathBuf::from(&sys_root).join("System32").join("where.exe"),
            ),
        ];
        if let Ok(path_env) = std::env::var("PATH") {
            for tool in ["python.exe", "git.exe"] {
                if let Some(found) = std::env::split_paths(&path_env)
                    .map(|d| d.join(tool))
                    .find(|p| p.is_file())
                {
                    let stem = tool.trim_end_matches(".exe").to_string();
                    host_candidates.push((stem, found));
                }
            }
        }
        let release_octopus = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("release")
            .join("octopus.exe");
        if release_octopus.is_file() {
            host_candidates.push(("octopus".to_string(), release_octopus));
        }
        for (stem, path) in host_candidates {
            if path.exists() {
                let mut locked =
                    open_and_lock_executable_for_cli(&path, &stem).expect("lock host binary");
                let v_host = inspect_locked_file(
                    &mut locked.locked_file,
                    &path,
                    locked.metadata.file_size,
                    &stem,
                    false,
                )
                .expect("inspect host binary");
                assert_eq!(
                    v_host.direct_syscall_count,
                    0,
                    "host binary {} must have 0 direct syscall false positives: {:?}",
                    path.display(),
                    v_host.syscall_stub_details
                );
            }
        }
    }
}

#[test]
fn iter4_alt_ssn_encodings_symmetric_48byte_lookbehind_and_boundaries() {
    // Helper to build a vec with prefix + N NOPs + suffix
    let with_nops = |prefix: &[u8], nops: usize, suffix: &[u8]| -> Vec<u8> {
        let mut buf = Vec::with_capacity(prefix.len() + nops + suffix.len());
        buf.extend_from_slice(prefix);
        buf.extend(std::iter::repeat_n(0x90u8, nops));
        buf.extend_from_slice(suffix);
        buf
    };

    let cases: Vec<(&str, Vec<u8>)> = vec![
        // 48 C7 C0 (mov rax, imm32): adjacent, interleaved, reordered, 0F 05 & CD 2E
        (
            "mov_rax_4c8bd1_adj_0f05",
            vec![
                0x4C, 0x8B, 0xD1, 0x48, 0xC7, 0xC0, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
            ],
        ),
        (
            "mov_rax_4989ca_interleaved_cd2e",
            vec![
                0x49, 0x89, 0xCA, 0x90, 0x90, 0x48, 0xC7, 0xC0, 0x19, 0x00, 0x00, 0x00, 0x90, 0xCD,
                0x2E, 0xC3,
            ],
        ),
        (
            "mov_rax_reordered_4989ca_cd2e",
            vec![
                0x48, 0xC7, 0xC0, 0x1A, 0x00, 0x00, 0x00, 0x49, 0x89, 0xCA, 0xCD, 0x2E, 0xC3,
            ],
        ),
        (
            "mov_rax_reordered_4c8bd1_0f05",
            vec![
                0x48, 0xC7, 0xC0, 0x1B, 0x00, 0x00, 0x00, 0x90, 0x4C, 0x8B, 0xD1, 0x90, 0x0F, 0x05,
                0xC3,
            ],
        ),
        // 6A <u8> 58 (push imm8; pop rax): adjacent, interleaved, reordered, 0F 05 & CD 2E
        (
            "push8_pop_rax_4c8bd1_adj_0f05",
            vec![0x4C, 0x8B, 0xD1, 0x6A, 0x18, 0x58, 0x0F, 0x05, 0xC3],
        ),
        (
            "push8_pop_rax_4989ca_interleaved_cd2e",
            vec![
                0x49, 0x89, 0xCA, 0x90, 0x6A, 0x1C, 0x58, 0x90, 0xCD, 0x2E, 0xC3,
            ],
        ),
        (
            "push8_pop_rax_reordered_4c8bd1_0f05",
            vec![
                0x6A, 0x1D, 0x58, 0x90, 0x4C, 0x8B, 0xD1, 0x90, 0x0F, 0x05, 0xC3,
            ],
        ),
        (
            "push8_pop_rax_reordered_4989ca_cd2e",
            vec![0x6A, 0x1E, 0x58, 0x49, 0x89, 0xCA, 0xCD, 0x2E, 0xC3],
        ),
        // 68 <lo> <hi> 00 00 58 (push imm32; pop rax): adjacent, interleaved, reordered, 0F 05 & CD 2E
        (
            "push32_pop_rax_4c8bd1_adj_0f05",
            vec![
                0x4C, 0x8B, 0xD1, 0x68, 0x18, 0x00, 0x00, 0x00, 0x58, 0x0F, 0x05, 0xC3,
            ],
        ),
        (
            "push32_pop_rax_4989ca_interleaved_cd2e",
            vec![
                0x49, 0x89, 0xCA, 0x90, 0x68, 0x1F, 0x00, 0x00, 0x00, 0x58, 0x90, 0xCD, 0x2E, 0xC3,
            ],
        ),
        (
            "push32_pop_rax_reordered_4c8bd1_0f05",
            vec![
                0x68, 0x20, 0x00, 0x00, 0x00, 0x58, 0x4C, 0x8B, 0xD1, 0x0F, 0x05, 0xC3,
            ],
        ),
        (
            "push32_pop_rax_reordered_4989ca_cd2e",
            vec![
                0x68, 0x21, 0x00, 0x00, 0x00, 0x58, 0x90, 0x49, 0x89, 0xCA, 0x90, 0xCD, 0x2E, 0xC3,
            ],
        ),
        // LOOKBEHIND_BYTES = 48 coverage: 10 NOPs, 44 NOPs, and exact 45 NOPs (3 + 45 = 48 bytes)
        (
            "lookbehind_4c8bd1_10nops_b8_0f05",
            with_nops(
                &[0x4C, 0x8B, 0xD1],
                10,
                &[0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3],
            ),
        ),
        (
            "lookbehind_4c8bd1_44nops_48c7c0_0f05",
            with_nops(
                &[0x4C, 0x8B, 0xD1],
                44,
                &[0x48, 0xC7, 0xC0, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3],
            ),
        ),
        (
            "lookbehind_4c8bd1_exact45nops_6a_cd2e",
            with_nops(
                &[0x4C, 0x8B, 0xD1],
                45,
                &[0x6A, 0x18, 0x58, 0xCD, 0x2E, 0xC3],
            ),
        ),
    ];

    let rete = ReteEngine::new();
    let expected_count = cases.len() as u32;
    let mut combined = Vec::new();

    for (name, bytes) in &cases {
        combined.extend_from_slice(bytes);
        let pe = build_synthetic_pe(
            true,
            &[PeSectionSpec {
                name: ".text",
                virtual_size: 4096,
                virtual_addr: 0x1000,
                characteristics: 0x6000_0020,
                data: bytes,
                force_raw_size_zero: false,
            }],
            false,
        );
        let v = inspect_binary_bytes(&pe, name);
        assert_eq!(
            v.direct_syscall_count, 1,
            "case {} must detect exactly 1 direct syscall stub: {:?}",
            name, v.syscall_stub_details
        );
        let gate = rete.evaluate_pre_spawn_rea_gate(
            v.to_rea_binary_fact(7001),
            v.has_wx_violation,
            v.has_raw_size_anomaly,
            &v.header_anomalies,
            v.format,
            &PreSpawnReaPolicy::default(),
        );
        assert!(
            !gate.allowed,
            "case {} must be denied by RETE pre-spawn gate",
            name
        );
    }

    // Combined multi-stub detection without double-counting
    let combined_pe = build_synthetic_pe(
        true,
        &[PeSectionSpec {
            name: ".text",
            virtual_size: 4096,
            virtual_addr: 0x1000,
            characteristics: 0x6000_0020,
            data: &combined,
            force_raw_size_zero: false,
        }],
        false,
    );
    let vc = inspect_binary_bytes(&combined_pe, "combined_iter4.exe");
    assert_eq!(
        vc.direct_syscall_count, expected_count,
        "all {} iter4 stubs must be detected without double-counting: {:?}",
        expected_count, vc.syscall_stub_details
    );

    // Just-outside >48 byte lookbehind boundary: 4C 8B D1 (3 bytes) + 46 NOPs = 49 bytes before SSN load
    let outside_lb = with_nops(
        &[0x4C, 0x8B, 0xD1],
        46,
        &[0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3],
    );
    let outside_pe = build_synthetic_pe(
        true,
        &[PeSectionSpec {
            name: ".text",
            virtual_size: 4096,
            virtual_addr: 0x1000,
            characteristics: 0x6000_0020,
            data: &outside_lb,
            force_raw_size_zero: false,
        }],
        false,
    );
    let v_out = inspect_binary_bytes(&outside_pe, "outside_48_lb.exe");
    assert_eq!(
        v_out.direct_syscall_count, 0,
        "49-byte lookbehind gap (>48) must not match: {:?}",
        v_out.syscall_stub_details
    );

    // Ensure last_matched_end prevents a subsequent unpaired syscall from borrowing a prior stub's mov r10, rcx
    let chained_no_r10 = vec![
        0x4C, 0x8B, 0xD1, 0x6A, 0x18, 0x58, 0x0F, 0x05, // valid stub 1
        0x6A, 0x19, 0x58, 0x0F, 0x05, 0xC3, // unpaired stub 2 without mov r10, rcx
    ];
    let chained_pe = build_synthetic_pe(
        true,
        &[PeSectionSpec {
            name: ".text",
            virtual_size: 4096,
            virtual_addr: 0x1000,
            characteristics: 0x6000_0020,
            data: &chained_no_r10,
            force_raw_size_zero: false,
        }],
        false,
    );
    let v_chain = inspect_binary_bytes(&chained_pe, "chained_no_r10.exe");
    assert_eq!(
        v_chain.direct_syscall_count, 1,
        "second stub lacking mov r10, rcx must not borrow prior stub's prefix past last_matched_end: {:?}",
        v_chain.syscall_stub_details
    );
}

fn build_synthetic_pe_with_lfanew(
    lfanew: usize,
    is_64: bool,
    sections: &[PeSectionSpec<'_>],
    with_cert: bool,
) -> Vec<u8> {
    let opt_size: usize = if is_64 { 240 } else { 224 };
    let sec_table_off = lfanew + 4 + 20 + opt_size;
    let headers_end = sec_table_off + sections.len() * 40;
    let first_sec_off = headers_end.div_ceil(0x200) * 0x200;

    let mut raw_offsets = Vec::with_capacity(sections.len());
    let mut cur_off = first_sec_off;
    for sec in sections {
        raw_offsets.push(cur_off);
        if !sec.force_raw_size_zero && !sec.data.is_empty() {
            let aligned = sec.data.len().div_ceil(0x200) * 0x200;
            cur_off += aligned;
        }
    }

    let cert_off = cur_off;
    let cert_blob = if with_cert {
        let mut c = Vec::new();
        c.extend_from_slice(&64u32.to_le_bytes());
        c.extend_from_slice(&0x0200u16.to_le_bytes());
        c.extend_from_slice(&0x0002u16.to_le_bytes());
        c.resize(64, 0x30);
        c
    } else {
        Vec::new()
    };
    let total_len = cert_off + cert_blob.len();
    let mut buf = vec![0u8; total_len];

    buf[0..2].copy_from_slice(b"MZ");
    buf[0x3C..0x40].copy_from_slice(&(lfanew as u32).to_le_bytes());

    buf[lfanew..lfanew + 4].copy_from_slice(b"PE\0\0");
    let coff = lfanew + 4;
    let machine: u16 = if is_64 { 0x8664 } else { 0x014C };
    buf[coff..coff + 2].copy_from_slice(&machine.to_le_bytes());
    buf[coff + 2..coff + 4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
    buf[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());

    let opt = coff + 20;
    let magic: u16 = if is_64 { 0x020B } else { 0x010B };
    buf[opt..opt + 2].copy_from_slice(&magic.to_le_bytes());
    let ep_rva = sections.first().map(|s| s.virtual_addr).unwrap_or(0x1000);
    buf[opt + 16..opt + 20].copy_from_slice(&ep_rva.to_le_bytes());

    let num_rva_off = if is_64 { opt + 108 } else { opt + 92 };
    let sec_dir_off = if is_64 { opt + 144 } else { opt + 128 };
    buf[num_rva_off..num_rva_off + 4].copy_from_slice(&16u32.to_le_bytes());
    if with_cert {
        buf[sec_dir_off..sec_dir_off + 4].copy_from_slice(&(cert_off as u32).to_le_bytes());
        buf[sec_dir_off + 4..sec_dir_off + 8]
            .copy_from_slice(&(cert_blob.len() as u32).to_le_bytes());
    }

    for (i, sec) in sections.iter().enumerate() {
        let sh = sec_table_off + i * 40;
        let nb = sec.name.as_bytes();
        let copy_len = nb.len().min(8);
        buf[sh..sh + copy_len].copy_from_slice(&nb[..copy_len]);
        buf[sh + 8..sh + 12].copy_from_slice(&sec.virtual_size.to_le_bytes());
        buf[sh + 12..sh + 16].copy_from_slice(&sec.virtual_addr.to_le_bytes());
        let raw_sz = if sec.force_raw_size_zero {
            0u32
        } else {
            sec.data.len() as u32
        };
        let raw_ptr = if sec.force_raw_size_zero || sec.data.is_empty() {
            0u32
        } else {
            raw_offsets[i] as u32
        };
        buf[sh + 16..sh + 20].copy_from_slice(&raw_sz.to_le_bytes());
        buf[sh + 20..sh + 24].copy_from_slice(&raw_ptr.to_le_bytes());
        buf[sh + 36..sh + 40].copy_from_slice(&sec.characteristics.to_le_bytes());

        if !sec.force_raw_size_zero && !sec.data.is_empty() {
            let off = raw_offsets[i];
            buf[off..off + sec.data.len()].copy_from_slice(sec.data);
        }
    }

    if !cert_blob.is_empty() {
        buf[cert_off..cert_off + cert_blob.len()].copy_from_slice(&cert_blob);
    }

    buf
}

#[test]
fn iter5_large_lfanew_past_64k_header_anomalies_fail_closed_and_dense_terminator_sla() {
    let rete = ReteEngine::new();

    // 1. PE with e_lfanew >= 65_536 (0x10080) and section table past 65_536 carrying W^X + Hell's Gate
    let hells_gate = [
        0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
    ];
    let large_lfanew_evil = build_synthetic_pe_with_lfanew(
        0x10080,
        true,
        &[PeSectionSpec {
            name: ".text",
            virtual_size: 4096,
            virtual_addr: 0x1000,
            characteristics: 0xE000_0020, // WRITE | EXECUTE
            data: &hells_gate,
            force_raw_size_zero: false,
        }],
        false,
    );
    let v_evil = inspect_binary_bytes(&large_lfanew_evil, "large_lfanew_evil.exe");
    assert_eq!(v_evil.format, BinaryFormat::Pe64);
    assert!(
        v_evil.header_anomalies.is_empty(),
        "{:?}",
        v_evil.header_anomalies
    );
    assert!(v_evil.has_wx_violation);
    assert_eq!(v_evil.direct_syscall_count, 1);

    let g_evil = TempFileGuard::new("large_lfanew_evil.exe", &large_lfanew_evil);
    let mut locked_evil =
        open_and_lock_executable_for_cli(g_evil.path(), "large_lfanew_evil").expect("lock evil");
    let v_evil_file = inspect_locked_file(
        &mut locked_evil.locked_file,
        g_evil.path(),
        locked_evil.metadata.file_size,
        "large_lfanew_evil",
        false,
    )
    .expect("inspect evil locked");
    assert_eq!(v_evil_file.format, BinaryFormat::Pe64);
    assert!(v_evil_file.has_wx_violation);
    assert_eq!(v_evil_file.direct_syscall_count, 1);

    let gate_evil = rete.evaluate_pre_spawn_rea_gate(
        v_evil_file.to_rea_binary_fact(8001),
        v_evil_file.has_wx_violation,
        v_evil_file.has_raw_size_anomaly,
        &v_evil_file.header_anomalies,
        v_evil_file.format,
        &PreSpawnReaPolicy::default(),
    );
    assert!(!gate_evil.allowed);

    // Clean signed PE with e_lfanew = 0x10080
    let large_lfanew_clean = build_synthetic_pe_with_lfanew(
        0x10080,
        true,
        &[PeSectionSpec {
            name: ".text",
            virtual_size: 4096,
            virtual_addr: 0x1000,
            characteristics: 0x6000_0020,
            data: &[0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3],
            force_raw_size_zero: false,
        }],
        true,
    );
    let v_clean = inspect_binary_bytes(&large_lfanew_clean, "large_lfanew_clean.exe");
    assert_eq!(v_clean.format, BinaryFormat::Pe64);
    assert!(v_clean.is_authenticode_signed);
    assert!(!v_clean.has_wx_violation);
    assert_eq!(v_clean.direct_syscall_count, 0);
    assert!(v_clean.header_anomalies.is_empty());
    let gate_clean = rete.evaluate_pre_spawn_rea_gate(
        v_clean.to_rea_binary_fact(8002),
        v_clean.has_wx_violation,
        v_clean.has_raw_size_anomaly,
        &v_clean.header_anomalies,
        v_clean.format,
        &PreSpawnReaPolicy::default(),
    );
    assert!(gate_clean.allowed, "{:?}", gate_clean.reasons);

    // 2. header_anomalies non-empty & BinaryFormat::Unknown fail closed when policy.enabled == true
    let unknown_v = inspect_binary_bytes(b"NOT_A_NATIVE_BINARY_PAYLOAD", "weird.bin");
    assert_eq!(unknown_v.format, BinaryFormat::Unknown);
    let gate_unknown = rete.evaluate_pre_spawn_rea_gate(
        unknown_v.to_rea_binary_fact(8003),
        unknown_v.has_wx_violation,
        unknown_v.has_raw_size_anomaly,
        &unknown_v.header_anomalies,
        unknown_v.format,
        &PreSpawnReaPolicy::default(),
    );
    assert!(!gate_unknown.allowed);
    assert!(gate_unknown
        .reasons
        .iter()
        .any(|r| r.contains("unknown_binary_format_rejected")));

    let mut trunc_pe = vec![0u8; 0x80];
    trunc_pe[0..2].copy_from_slice(b"MZ");
    trunc_pe[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    let v_trunc = inspect_binary_bytes(&trunc_pe, "trunc_pe.exe");
    assert!(!v_trunc.header_anomalies.is_empty());
    let gate_trunc = rete.evaluate_pre_spawn_rea_gate(
        v_trunc.to_rea_binary_fact(8004),
        v_trunc.has_wx_violation,
        v_trunc.has_raw_size_anomaly,
        &v_trunc.header_anomalies,
        v_trunc.format,
        &PreSpawnReaPolicy::default(),
    );
    assert!(!gate_trunc.allowed);
    assert!(gate_trunc
        .reasons
        .iter()
        .any(|r| r.contains("binary_header_anomalies")));

    let disabled_pol = PreSpawnReaPolicy {
        enabled: false,
        ..PreSpawnReaPolicy::default()
    };
    let gate_disabled = rete.evaluate_pre_spawn_rea_gate(
        v_trunc.to_rea_binary_fact(8005),
        v_trunc.has_wx_violation,
        v_trunc.has_raw_size_anomaly,
        &v_trunc.header_anomalies,
        v_trunc.format,
        &disabled_pol,
    );
    assert!(gate_disabled.allowed);

    // 3. Intermediate decoy terminator inside B8 0F 05 00 00 must not hide the real terminator
    let decoy_inside_b8 = [
        0x4C, 0x8B, 0xD1, 0xB8, 0x0F, 0x05, 0x00, 0x00, 0x90, 0x0F, 0x05, 0xC3,
    ];
    let decoy_pe = build_synthetic_pe(
        true,
        &[PeSectionSpec {
            name: ".text",
            virtual_size: 4096,
            virtual_addr: 0x1000,
            characteristics: 0x6000_0020,
            data: &decoy_inside_b8,
            force_raw_size_zero: false,
        }],
        false,
    );
    let v_decoy = inspect_binary_bytes(&decoy_pe, "decoy_inside_b8.exe");
    assert_eq!(v_decoy.direct_syscall_count, 1);

    // 4. Pathological dense-terminator inputs + MAX_STUB_DETAILS = 32 cap
    // (a) 256 KiB of `6A 18 58 0F 05` (no mov r10, rcx)
    let mut dense_push_term = Vec::with_capacity(256 * 1024);
    while dense_push_term.len() + 5 <= 256 * 1024 {
        dense_push_term.extend_from_slice(&[0x6A, 0x18, 0x58, 0x0F, 0x05]);
    }
    let dense_pe_1 = build_synthetic_pe(
        true,
        &[PeSectionSpec {
            name: ".text",
            virtual_size: dense_push_term.len() as u32,
            virtual_addr: 0x1000,
            characteristics: 0x6000_0020,
            data: &dense_push_term,
            force_raw_size_zero: false,
        }],
        false,
    );
    let v_dense1 = inspect_binary_bytes(&dense_pe_1, "dense_6a_0f05_256k.exe");
    assert_eq!(v_dense1.direct_syscall_count, 0);
    assert!(v_dense1.syscall_stub_details.is_empty());

    // (b) 96 sections x ~5.5 KiB (~512 KiB budget) of `6A 18 58 0F 05`
    let mut sec_payload = Vec::with_capacity(5500);
    while sec_payload.len() + 5 <= 5500 {
        sec_payload.extend_from_slice(&[0x6A, 0x18, 0x58, 0x0F, 0x05]);
    }
    let sec_names: Vec<String> = (0..96).map(|i| format!(".s{:02}", i)).collect();
    let specs_96: Vec<PeSectionSpec<'_>> = sec_names
        .iter()
        .enumerate()
        .map(|(i, n)| PeSectionSpec {
            name: n.as_str(),
            virtual_size: 8192,
            virtual_addr: 0x1000 + (i as u32) * 0x2000,
            characteristics: 0x6000_0020,
            data: &sec_payload,
            force_raw_size_zero: false,
        })
        .collect();
    let dense_pe_96 = build_synthetic_pe(true, &specs_96, false);
    let v_dense96 = inspect_binary_bytes(&dense_pe_96, "dense_96sec_512k.exe");
    assert_eq!(v_dense96.direct_syscall_count, 0);

    // (c) 256 KiB of `4C 8B D1 0F 05` (no SSN)
    let mut dense_r10_term = Vec::with_capacity(256 * 1024);
    while dense_r10_term.len() + 5 <= 256 * 1024 {
        dense_r10_term.extend_from_slice(&[0x4C, 0x8B, 0xD1, 0x0F, 0x05]);
    }
    let dense_pe_r10 = build_synthetic_pe(
        true,
        &[PeSectionSpec {
            name: ".text",
            virtual_size: dense_r10_term.len() as u32,
            virtual_addr: 0x1000,
            characteristics: 0x6000_0020,
            data: &dense_r10_term,
            force_raw_size_zero: false,
        }],
        false,
    );
    let v_dense_r10 = inspect_binary_bytes(&dense_pe_r10, "dense_r10_no_ssn.exe");
    assert_eq!(v_dense_r10.direct_syscall_count, 0);

    // (d) 256 KiB of valid PE stubs (`4C 8B D1 6A 18 58 0F 05`) -> accurate count + details capped <= 32
    let mut dense_valid_pe = Vec::with_capacity(256 * 1024);
    let expected_pe_stubs = (256 * 1024) / 8;
    for _ in 0..expected_pe_stubs {
        dense_valid_pe.extend_from_slice(&[0x4C, 0x8B, 0xD1, 0x6A, 0x18, 0x58, 0x0F, 0x05]);
    }
    let dense_pe_valid = build_synthetic_pe(
        true,
        &[PeSectionSpec {
            name: ".text",
            virtual_size: dense_valid_pe.len() as u32,
            virtual_addr: 0x1000,
            characteristics: 0x6000_0020,
            data: &dense_valid_pe,
            force_raw_size_zero: false,
        }],
        false,
    );
    let v_dense_valid = inspect_binary_bytes(&dense_pe_valid, "dense_valid_pe.exe");
    assert_eq!(v_dense_valid.direct_syscall_count, expected_pe_stubs as u32);
    assert!(
        v_dense_valid.syscall_stub_details.len() <= 32,
        "PE details len={} exceeded 32 cap",
        v_dense_valid.syscall_stub_details.len()
    );

    // (e) 256 KiB dense ELF (`B8 3B 00 00 00 0F 05`) -> accurate count + details <= 32
    let mut dense_elf_code = Vec::with_capacity(256 * 1024);
    let expected_elf_stubs = (256 * 1024) / 7;
    for _ in 0..expected_elf_stubs {
        dense_elf_code.extend_from_slice(&[0xB8, 0x3B, 0x00, 0x00, 0x00, 0x0F, 0x05]);
    }
    let dense_elf = build_synthetic_elf(true, true, 0x5, None, false, &dense_elf_code);
    let v_dense_elf = inspect_binary_bytes(&dense_elf, "dense_elf_256k.elf");
    assert_eq!(v_dense_elf.direct_syscall_count, expected_elf_stubs as u32);
    assert!(
        v_dense_elf.syscall_stub_details.len() <= 32,
        "ELF details len={} exceeded 32 cap",
        v_dense_elf.syscall_stub_details.len()
    );

    // (f) 256 KiB dense Mach-O ARM64 (`mov x16, #59; svc #0x80`) -> accurate count + details <= 32
    let mut dense_macho_code = Vec::with_capacity(256 * 1024);
    let expected_macho_stubs = (256 * 1024) / 8;
    for _ in 0..expected_macho_stubs {
        push_u32(&mut dense_macho_code, 0xD280_0770, true);
        push_u32(&mut dense_macho_code, 0xD400_1001, true);
    }
    let dense_macho = build_synthetic_macho64(true, "__TEXT", 0x5, true, &dense_macho_code);
    let v_dense_macho = inspect_binary_bytes(&dense_macho, "dense_macho_256k.macho");
    assert_eq!(
        v_dense_macho.direct_syscall_count,
        expected_macho_stubs as u32
    );
    assert!(
        v_dense_macho.syscall_stub_details.len() <= 32,
        "Mach-O details len={} exceeded 32 cap",
        v_dense_macho.syscall_stub_details.len()
    );
}

#[test]
fn iter6_wasm_header_validation_pe_slowpath_anti_early_exit_and_arch_dispatch() {
    let rete = ReteEngine::new();

    // 1. 5-byte truncated Wasm magic (\x00asm\x01) and invalid version (\x00asm\x02\x00\x00\x00)
    //    must keep BinaryFormat::Wasm, emit wasm_truncated_or_invalid_header, and fail closed in RETE.
    for (label, bytes) in [
        ("wasm_5b.exe", b"\x00asm\x01".as_slice()),
        ("wasm_bad_ver.exe", b"\x00asm\x02\x00\x00\x00".as_slice()),
    ] {
        let v = inspect_binary_bytes(bytes, label);
        assert_eq!(v.format, BinaryFormat::Wasm);
        assert!(
            v.header_anomalies
                .iter()
                .any(|a| a == "wasm_truncated_or_invalid_header"),
            "{}: expected wasm_truncated_or_invalid_header, got {:?}",
            label,
            v.header_anomalies
        );
        let gate = rete.evaluate_pre_spawn_rea_gate(
            v.to_rea_binary_fact(9001),
            v.has_wx_violation,
            v.has_raw_size_anomaly,
            &v.header_anomalies,
            v.format,
            &PreSpawnReaPolicy {
                require_signed_binaries: false,
                ..PreSpawnReaPolicy::default()
            },
        );
        assert!(!gate.allowed, "{} must fail closed", label);
        assert!(gate
            .reasons
            .iter()
            .any(|r| r.contains("wasm_truncated_or_invalid_header")));
    }

    // Valid 8-byte Wasm header must have empty header_anomalies and pass RETE
    let valid_wasm = inspect_binary_bytes(b"\x00asm\x01\x00\x00\x00", "valid.wasm");
    assert_eq!(valid_wasm.format, BinaryFormat::Wasm);
    assert!(valid_wasm.header_anomalies.is_empty());
    let gate_valid_wasm = rete.evaluate_pre_spawn_rea_gate(
        valid_wasm.to_rea_binary_fact(9002),
        valid_wasm.has_wx_violation,
        valid_wasm.has_raw_size_anomaly,
        &valid_wasm.header_anomalies,
        valid_wasm.format,
        &PreSpawnReaPolicy {
            require_signed_binaries: false,
            ..PreSpawnReaPolicy::default()
        },
    );
    assert!(gate_valid_wasm.allowed, "{:?}", gate_valid_wasm.reasons);

    // 2. PE slow-path decoy + anti-early-exit cases across 2x256 KiB (512 KiB)
    // (a) 0F 05 decoy + 4C 8B D1 90 6A 18 58 0F 05
    let mut p_decoy = vec![0x0Fu8, 0x05];
    let mut per_sec_expected = 0u32;
    while p_decoy.len() + 9 <= 256 * 1024 {
        p_decoy.extend_from_slice(&[0x4C, 0x8B, 0xD1, 0x90, 0x6A, 0x18, 0x58, 0x0F, 0x05]);
        per_sec_expected += 1;
    }
    let pe_decoy = build_synthetic_pe(
        true,
        &[
            PeSectionSpec {
                name: ".text0",
                virtual_size: p_decoy.len() as u32,
                virtual_addr: 0x1000,
                characteristics: 0x6000_0020,
                data: &p_decoy,
                force_raw_size_zero: false,
            },
            PeSectionSpec {
                name: ".text1",
                virtual_size: p_decoy.len() as u32,
                virtual_addr: 0x50000,
                characteristics: 0x6000_0020,
                data: &p_decoy,
                force_raw_size_zero: false,
            },
        ],
        false,
    );
    let v_decoy = inspect_binary_bytes(&pe_decoy, "pe_slowpath_decoy_512k.exe");
    assert_eq!(v_decoy.direct_syscall_count, per_sec_expected * 2);
    assert!(v_decoy.syscall_stub_details.len() <= 32);

    // (b) 4C 8B D1 0F 05 x N + tail B8 18 00 00 00 (anti-early-exit SSN)
    let mut p_tail_b8 = Vec::with_capacity(256 * 1024);
    while p_tail_b8.len() + 10 <= 256 * 1024 {
        p_tail_b8.extend_from_slice(&[0x4C, 0x8B, 0xD1, 0x0F, 0x05]);
    }
    p_tail_b8.extend_from_slice(&[0xB8, 0x18, 0x00, 0x00, 0x00]);
    let pe_tail_b8 = build_synthetic_pe(
        true,
        &[
            PeSectionSpec {
                name: ".text0",
                virtual_size: p_tail_b8.len() as u32,
                virtual_addr: 0x1000,
                characteristics: 0x6000_0020,
                data: &p_tail_b8,
                force_raw_size_zero: false,
            },
            PeSectionSpec {
                name: ".text1",
                virtual_size: p_tail_b8.len() as u32,
                virtual_addr: 0x50000,
                characteristics: 0x6000_0020,
                data: &p_tail_b8,
                force_raw_size_zero: false,
            },
        ],
        false,
    );
    let v_tail_b8 = inspect_binary_bytes(&pe_tail_b8, "pe_tail_b8.exe");
    assert_eq!(v_tail_b8.direct_syscall_count, 0);

    // Adding a terminator right after the tail B8 must still be detected accurately!
    let mut p_tail_b8_hit = p_tail_b8.clone();
    p_tail_b8_hit.extend_from_slice(&[0x0F, 0x05]);
    let pe_tail_b8_hit = build_synthetic_pe(
        true,
        &[PeSectionSpec {
            name: ".text",
            virtual_size: p_tail_b8_hit.len() as u32,
            virtual_addr: 0x1000,
            characteristics: 0x6000_0020,
            data: &p_tail_b8_hit,
            force_raw_size_zero: false,
        }],
        false,
    );
    let v_tail_b8_hit = inspect_binary_bytes(&pe_tail_b8_hit, "pe_tail_b8_hit.exe");
    assert_eq!(v_tail_b8_hit.direct_syscall_count, 1);

    // (c) head 4C 8B D1 + 6A 18 58 0F 05 x N + tail 4C 8B D1 (anti-early-exit r10)
    let mut p_ht_r10 = vec![0x4C, 0x8B, 0xD1];
    while p_ht_r10.len() + 8 <= 256 * 1024 {
        p_ht_r10.extend_from_slice(&[0x6A, 0x18, 0x58, 0x0F, 0x05]);
    }
    p_ht_r10.extend_from_slice(&[0x4C, 0x8B, 0xD1]);
    let pe_ht_r10 = build_synthetic_pe(
        true,
        &[
            PeSectionSpec {
                name: ".text0",
                virtual_size: p_ht_r10.len() as u32,
                virtual_addr: 0x1000,
                characteristics: 0x6000_0020,
                data: &p_ht_r10,
                force_raw_size_zero: false,
            },
            PeSectionSpec {
                name: ".text1",
                virtual_size: p_ht_r10.len() as u32,
                virtual_addr: 0x50000,
                characteristics: 0x6000_0020,
                data: &p_ht_r10,
                force_raw_size_zero: false,
            },
        ],
        false,
    );
    let v_ht_r10 = inspect_binary_bytes(&pe_ht_r10, "pe_ht_r10.exe");
    assert_eq!(v_ht_r10.direct_syscall_count, 2);

    // 3. ELF64 e_machine selective dispatch (62=x86_64, 183=AArch64, 0=both)
    let mut mixed_elf_code = Vec::new();
    mixed_elf_code.extend_from_slice(&[0xB8, 0x3B, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3]);
    push_u32(&mut mixed_elf_code, 0xD280_1BA8, true);
    push_u32(&mut mixed_elf_code, 0xD400_0001, true);
    let elf_x64_only =
        build_synthetic_elf_with_machine(true, true, 62, 0x5, None, false, &mixed_elf_code);
    let elf_a64_only =
        build_synthetic_elf_with_machine(true, true, 183, 0x5, None, false, &mixed_elf_code);
    let elf_unknown_arch =
        build_synthetic_elf_with_machine(true, true, 0, 0x5, None, false, &mixed_elf_code);
    assert_eq!(
        inspect_binary_bytes(&elf_x64_only, "x64.elf").direct_syscall_count,
        1
    );
    assert_eq!(
        inspect_binary_bytes(&elf_a64_only, "a64.elf").direct_syscall_count,
        1
    );
    assert_eq!(
        inspect_binary_bytes(&elf_unknown_arch, "unk.elf").direct_syscall_count,
        2
    );

    // 4. Mach-O64 cputype selective dispatch + Fat Mach-O 2-arch shared 512 KiB budget
    let mut mixed_macho_code = Vec::new();
    push_u32(&mut mixed_macho_code, 0xD280_0770, true);
    push_u32(&mut mixed_macho_code, 0xD400_1001, true);
    mixed_macho_code.extend_from_slice(&[0xB8, 0x3B, 0x00, 0x00, 0x02, 0x0F, 0x05, 0xC3]);
    let macho_arm64 = build_synthetic_macho64_with_cputype(
        true,
        0x0100_000C,
        "__TEXT",
        0x5,
        true,
        &mixed_macho_code,
    );
    let macho_x64 = build_synthetic_macho64_with_cputype(
        true,
        0x0100_0007,
        "__TEXT",
        0x5,
        true,
        &mixed_macho_code,
    );
    assert_eq!(
        inspect_binary_bytes(&macho_arm64, "arm64.macho").direct_syscall_count,
        1
    );
    assert_eq!(
        inspect_binary_bytes(&macho_x64, "x64.macho").direct_syscall_count,
        1
    );

    // 2-arch Fat Mach-O (256K ARM64 + 256K x86-64) + 3rd slice after 512K budget exhausted
    let mut arm64_256k = Vec::with_capacity(256 * 1024);
    for _ in 0..((256 * 1024) / 8) {
        push_u32(&mut arm64_256k, 0xD280_0770, true);
        push_u32(&mut arm64_256k, 0xD400_1001, true);
    }
    let mut x64_256k = Vec::with_capacity(256 * 1024);
    while x64_256k.len() + 7 <= 256 * 1024 {
        x64_256k.extend_from_slice(&[0xB8, 0x3B, 0x00, 0x00, 0x02, 0x0F, 0x05]);
    }
    let s0 =
        build_synthetic_macho64_with_cputype(true, 0x0100_000C, "__TEXT", 0x5, true, &arm64_256k);
    let s1 =
        build_synthetic_macho64_with_cputype(true, 0x0100_0007, "__TEXT", 0x5, true, &x64_256k);
    let s2_wx = build_synthetic_macho64_with_cputype(
        true,
        0x0100_000C,
        "__TEXT",
        0x7,
        false,
        &mixed_macho_code,
    );

    let off0 = 0x1000u32;
    let off1 = off0 + ((s0.len() as u32 + 0xFFF) & !0xFFF);
    let off2 = off1 + ((s1.len() as u32 + 0xFFF) & !0xFFF);
    let mut fat3 = Vec::new();
    fat3.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes());
    fat3.extend_from_slice(&3u32.to_be_bytes());
    for (cpu, off, sz) in [
        (0x0100_000Cu32, off0, s0.len() as u32),
        (0x0100_0007u32, off1, s1.len() as u32),
        (0x0100_000Cu32, off2, s2_wx.len() as u32),
    ] {
        fat3.extend_from_slice(&cpu.to_be_bytes());
        fat3.extend_from_slice(&0u32.to_be_bytes());
        fat3.extend_from_slice(&off.to_be_bytes());
        fat3.extend_from_slice(&sz.to_be_bytes());
        fat3.extend_from_slice(&12u32.to_be_bytes());
    }
    fat3.resize(off0 as usize, 0);
    fat3.extend_from_slice(&s0);
    fat3.resize(off1 as usize, 0);
    fat3.extend_from_slice(&s1);
    fat3.resize(off2 as usize, 0);
    fat3.extend_from_slice(&s2_wx);

    let v_fat3 = inspect_binary_bytes(&fat3, "fat3_shared_budget.macho");
    assert_eq!(v_fat3.format, BinaryFormat::MachOFat);
    // Slices 0 and 1 consume the entire 512 KiB scan budget, so slice 2's section bytes are not scanned,
    // while slice 2's W^X and unsigned load-command checks still trigger!
    assert_eq!(
        v_fat3.direct_syscall_count,
        ((256 * 1024) / 8 + (256 * 1024) / 7) as u32
    );
    assert!(v_fat3.syscall_stub_details.len() <= 32);
    assert!(v_fat3.has_wx_violation);
    assert!(!v_fat3.is_code_signed);
}

#[test]
fn iter7_pe_overlap_ssn_elf_details_full_and_adversarial_equivalence() {
    let rete = ReteEngine::new();

    // 1. PE overlapping SSN immediates containing [0F, 05] or [CD, 2E] after expired SSN + r10
    let overlap_cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "live_bypass_6a_r10_nops46_b8_0f05",
            [0x6A, 0x01, 0x58, 0x49, 0x89, 0xCA]
                .into_iter()
                .chain(std::iter::repeat_n(0x90u8, 46))
                .chain([0xB8, 0x0F, 0x05, 0x00, 0x00, 0x4C, 0x8B, 0xD1, 0x0F, 0x05])
                .collect(),
        ),
        (
            "r10_6a_nops48_b8_0f05_exhausted",
            [0x4C, 0x8B, 0xD1, 0x6A, 0x01, 0x58]
                .into_iter()
                .chain(std::iter::repeat_n(0x90u8, 48))
                .chain([0xB8, 0x0F, 0x05, 0x00, 0x00, 0x4C, 0x8B, 0xD1, 0x0F, 0x05])
                .collect(),
        ),
        (
            "r10_6a_nops48_b8_0f05_trailing_b8",
            [0x4C, 0x8B, 0xD1, 0x6A, 0x01, 0x58]
                .into_iter()
                .chain(std::iter::repeat_n(0x90u8, 48))
                .chain([
                    0xB8, 0x0F, 0x05, 0x00, 0x00, 0x4C, 0x8B, 0xD1, 0x0F, 0x05, 0x90, 0x90, 0xB8,
                    0x01, 0x00, 0x00, 0x00,
                ])
                .collect(),
        ),
        (
            "r10_6a_nops48_48c7c0_0f05",
            [0x4C, 0x8B, 0xD1, 0x6A, 0x01, 0x58]
                .into_iter()
                .chain(std::iter::repeat_n(0x90u8, 48))
                .chain([
                    0x48, 0xC7, 0xC0, 0x0F, 0x05, 0x00, 0x00, 0x4C, 0x8B, 0xD1, 0x0F, 0x05,
                ])
                .collect(),
        ),
        (
            "r10_6a_nops48_68_0f05_58",
            [0x4C, 0x8B, 0xD1, 0x6A, 0x01, 0x58]
                .into_iter()
                .chain(std::iter::repeat_n(0x90u8, 48))
                .chain([
                    0x68, 0x0F, 0x05, 0x00, 0x00, 0x58, 0x4C, 0x8B, 0xD1, 0x0F, 0x05,
                ])
                .collect(),
        ),
        (
            "r10_6a_nops48_b8_cd2e",
            [0x4C, 0x8B, 0xD1, 0x6A, 0x01, 0x58]
                .into_iter()
                .chain(std::iter::repeat_n(0x90u8, 48))
                .chain([0xB8, 0xCD, 0x2E, 0x00, 0x00, 0x4C, 0x8B, 0xD1, 0xCD, 0x2E])
                .collect(),
        ),
    ];

    for (name, code) in &overlap_cases {
        let pe = build_synthetic_pe(
            true,
            &[PeSectionSpec {
                name: ".text",
                virtual_size: 4096,
                virtual_addr: 0x1000,
                characteristics: 0x6000_0020,
                data: code,
                force_raw_size_zero: false,
            }],
            false,
        );
        let v = inspect_binary_bytes(&pe, name);
        assert_eq!(
            v.direct_syscall_count, 1,
            "overlapping SSN case {} must detect 1 stub, got {}: {:?}",
            name, v.direct_syscall_count, v.syscall_stub_details
        );
        let gate = rete.evaluate_pre_spawn_rea_gate(
            v.to_rea_binary_fact(9100),
            v.has_wx_violation,
            v.has_raw_size_anomaly,
            &v.header_anomalies,
            v.format,
            &PreSpawnReaPolicy::default(),
        );
        assert!(!gate.allowed, "{} must be denied by RETE gate", name);
    }

    // 2. ELF x64 details_full Case C (0xC3 after 32nd stub) and Case D (4C 8B D1 -3 offset)
    let mut case_c = Vec::new();
    for _ in 0..35 {
        case_c.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3]);
    }
    case_c.extend(std::iter::repeat_n(0x90u8, 400));
    case_c.extend_from_slice(&[0xB8, 0x02, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3]);
    case_c.resize(70 * 1024, 0x90);
    let elf_case_c = build_synthetic_elf_with_machine(true, true, 62, 0x5, None, false, &case_c);
    let vc = inspect_binary_bytes(&elf_case_c, "elf_case_c.elf");
    assert_eq!(
        vc.direct_syscall_count, 36,
        "ELF x64 details_full Case C must detect 36 stubs"
    );

    let mut case_d = Vec::new();
    let mut last_b8 = 0usize;
    for _ in 0..33 {
        case_d.extend_from_slice(&[0x4C, 0x8B, 0xD1]);
        last_b8 = case_d.len();
        case_d.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x05]);
    }
    case_d.resize(last_b8 + 255, 0x90);
    case_d.extend_from_slice(&[0xB8, 0x02, 0x00, 0x00, 0x00, 0x0F, 0x05]);
    case_d.resize(70 * 1024, 0x90);
    let elf_case_d = build_synthetic_elf_with_machine(true, true, 62, 0x5, None, false, &case_d);
    let vd = inspect_binary_bytes(&elf_case_d, "elf_case_d.elf");
    assert_eq!(
        vd.direct_syscall_count, 33,
        "ELF x64 details_full Case D must use 4C 8B D1 start (-3) for 256B proximity (expected 33)"
    );

    // SWAR 8-byte chunk-boundary alignment check for ELF x64 and Mach-O x64
    for pad in 0..8usize {
        let mut e_code = vec![0x90u8; pad];
        e_code.extend_from_slice(&[0xB8, 0x3B, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3]);
        let e_bin = build_synthetic_elf_with_machine(true, true, 62, 0x5, None, false, &e_code);
        assert_eq!(
            inspect_binary_bytes(&e_bin, "pad_elf").direct_syscall_count,
            1,
            "ELF x64 SWAR chunk boundary failed at pad={}",
            pad
        );

        let mut m_code = vec![0x90u8; pad];
        m_code.extend_from_slice(&[0xB8, 0x3B, 0x00, 0x00, 0x02, 0x0F, 0x05]);
        let m_bin =
            build_synthetic_macho64_with_cputype(true, 0x0100_0007, "__TEXT", 0x5, true, &m_code);
        assert_eq!(
            inspect_binary_bytes(&m_bin, "pad_macho").direct_syscall_count,
            1,
            "Mach-O x64 SWAR chunk boundary failed at pad={}",
            pad
        );
    }

    // 3. Adversarial fast-skip / gap=17 / ELF & Mach-O x64 & AArch64 equivalence + latency bounds
    let sla_limit_us: u64 = if cfg!(debug_assertions) {
        25_000
    } else {
        2_000
    };
    let measure_p95 = |label: &str, bin: &[u8], expected_stubs: u32| {
        let mut us = Vec::with_capacity(10);
        for i in 0..10 {
            let t0 = Instant::now();
            let v = inspect_binary_bytes(bin, label);
            let dt = t0.elapsed().as_micros() as u64;
            assert_eq!(
                v.direct_syscall_count, expected_stubs,
                "{}: expected {} stubs, got {}",
                label, expected_stubs, v.direct_syscall_count
            );
            assert!(v.syscall_stub_details.len() <= 32);
            if i >= 2 {
                us.push(dt);
            }
        }
        us.sort_unstable();
        let p95 = us[us.len() - 1];
        assert!(
            p95 < sla_limit_us,
            "{}: p95={}us exceeded {}us bound ({:?})",
            label,
            p95,
            sla_limit_us,
            us
        );
    };

    // pe_anti_jump_queue_thrash (512 KiB) & after 32 initial stubs
    let mut p_thrash = Vec::with_capacity(256 * 1024);
    while p_thrash.len() + 114 <= 256 * 1024 {
        p_thrash.extend_from_slice(&[0x4C, 0x8B, 0xD1]);
        for _ in 0..27 {
            p_thrash.extend_from_slice(&[0x0F, 0x05]);
        }
        p_thrash.extend_from_slice(&[0x6A, 0x18, 0x58]);
        for _ in 0..27 {
            p_thrash.extend_from_slice(&[0x0F, 0x05]);
        }
    }
    let pe_thrash = build_synthetic_pe(
        true,
        &[
            PeSectionSpec {
                name: ".text0",
                virtual_size: p_thrash.len() as u32,
                virtual_addr: 0x1000,
                characteristics: 0x6000_0020,
                data: &p_thrash,
                force_raw_size_zero: false,
            },
            PeSectionSpec {
                name: ".text1",
                virtual_size: p_thrash.len() as u32,
                virtual_addr: 0x50000,
                characteristics: 0x6000_0020,
                data: &p_thrash,
                force_raw_size_zero: false,
            },
        ],
        false,
    );
    measure_p95("pe_anti_jump_queue_thrash_512k", &pe_thrash, 0);

    let mut p_thrash_32 = Vec::with_capacity(256 * 1024);
    for _ in 0..32 {
        p_thrash_32.extend_from_slice(&[0x4C, 0x8B, 0xD1, 0x6A, 0x18, 0x58, 0x0F, 0x05]);
    }
    p_thrash_32.extend_from_slice(&p_thrash[..(256 * 1024 - p_thrash_32.len())]);
    let pe_thrash_32 = build_synthetic_pe(
        true,
        &[PeSectionSpec {
            name: ".text",
            virtual_size: p_thrash_32.len() as u32,
            virtual_addr: 0x1000,
            characteristics: 0x6000_0020,
            data: &p_thrash_32,
            force_raw_size_zero: false,
        }],
        false,
    );
    measure_p95("pe_anti_jump_after_32_stubs", &pe_thrash_32, 32);

    // pe_gap17_interleaved (512 KiB) & pe_gap17_halos (512 KiB)
    let mut p_gap17 = Vec::with_capacity(256 * 1024);
    let mut gap17_per_sec = 0u32;
    while p_gap17.len() + 19 <= 256 * 1024 {
        p_gap17.extend_from_slice(&[0x4C, 0x8B, 0xD1]);
        p_gap17.extend(std::iter::repeat_n(0x90u8, 11));
        p_gap17.extend_from_slice(&[0x6A, 0x18, 0x58, 0x0F, 0x05]);
        gap17_per_sec += 1;
    }
    let pe_gap17 = build_synthetic_pe(
        true,
        &[
            PeSectionSpec {
                name: ".text0",
                virtual_size: p_gap17.len() as u32,
                virtual_addr: 0x1000,
                characteristics: 0x6000_0020,
                data: &p_gap17,
                force_raw_size_zero: false,
            },
            PeSectionSpec {
                name: ".text1",
                virtual_size: p_gap17.len() as u32,
                virtual_addr: 0x50000,
                characteristics: 0x6000_0020,
                data: &p_gap17,
                force_raw_size_zero: false,
            },
        ],
        false,
    );
    measure_p95("pe_gap17_interleaved_512k", &pe_gap17, gap17_per_sec * 2);

    // elf64_x64_dense_0f05_decoy (256K), macho64_x64_dense_0f05_decoy (256K), elf64_x64_rax_48c7c0 (256K), elf64_a64 (256K)
    let mut dense_0f05 = Vec::with_capacity(256 * 1024);
    for _ in 0..((256 * 1024) / 2) {
        dense_0f05.extend_from_slice(&[0x0F, 0x05]);
    }
    let elf_0f05 = build_synthetic_elf_with_machine(true, true, 62, 0x5, None, false, &dense_0f05);
    measure_p95("elf64_x64_dense_0f05_decoy", &elf_0f05, 0);
    let macho_0f05 =
        build_synthetic_macho64_with_cputype(true, 0x0100_0007, "__TEXT", 0x5, true, &dense_0f05);
    measure_p95("macho64_x64_dense_0f05_decoy", &macho_0f05, 0);

    let mut e_48c7c0 = Vec::with_capacity(256 * 1024);
    let mut e_48c7c0_count = 0u32;
    while e_48c7c0.len() + 9 <= 256 * 1024 {
        e_48c7c0.extend_from_slice(&[0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x05]);
        e_48c7c0_count += 1;
    }
    let elf_48c7c0 = build_synthetic_elf_with_machine(true, true, 62, 0x5, None, false, &e_48c7c0);
    measure_p95("elf64_x64_rax_48c7c0", &elf_48c7c0, e_48c7c0_count);

    let mut e_a64 = Vec::with_capacity(256 * 1024);
    for _ in 0..((256 * 1024) / 8) {
        push_u32(&mut e_a64, 0xD280_1BA8, true);
        push_u32(&mut e_a64, 0xD400_0001, true);
    }
    let elf_a64 = build_synthetic_elf_with_machine(true, true, 183, 0x5, None, false, &e_a64);
    measure_p95("elf64_a64_256k", &elf_a64, (256 * 1024) / 8);
}

#[test]
fn iter8_pe_post32_anti_jump_thrash_and_overlap_ssn_512k_and_gap_equiv() {
    let sla_limit_us: u64 = if cfg!(debug_assertions) {
        25_000
    } else {
        2_000
    };
    let measure_p95 = |label: &str, bin: &[u8], expected_stubs: u32| {
        let mut us = Vec::with_capacity(10);
        for i in 0..10 {
            let t0 = Instant::now();
            let v = inspect_binary_bytes(bin, label);
            let dt = t0.elapsed().as_micros() as u64;
            assert_eq!(
                v.direct_syscall_count, expected_stubs,
                "{}: expected {} stubs, got {}",
                label, expected_stubs, v.direct_syscall_count
            );
            assert!(v.syscall_stub_details.len() <= 32);
            if i >= 2 {
                us.push(dt);
            }
        }
        us.sort_unstable();
        let p95 = us[us.len() - 1];
        assert!(
            p95 < sla_limit_us,
            "{}: p95={}us exceeded {}us bound ({:?})",
            label,
            p95,
            sla_limit_us,
            us
        );
    };

    // 1. pe_post32_anti_jump_thrash_512k (32 Hell's Gate stubs -> details_full=true, then 2x256 KiB thrash)
    let mut p_thrash = Vec::with_capacity(256 * 1024);
    while p_thrash.len() + 114 <= 256 * 1024 {
        p_thrash.extend_from_slice(&[0x4C, 0x8B, 0xD1]);
        for _ in 0..27 {
            p_thrash.extend_from_slice(&[0x0F, 0x05]);
        }
        p_thrash.extend_from_slice(&[0x6A, 0x18, 0x58]);
        for _ in 0..27 {
            p_thrash.extend_from_slice(&[0x0F, 0x05]);
        }
    }
    let mut s0_post32 = Vec::with_capacity(256 * 1024);
    for _ in 0..32 {
        s0_post32.extend_from_slice(&[0x4C, 0x8B, 0xD1, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x05]);
    }
    s0_post32.extend_from_slice(&p_thrash[..(256 * 1024 - s0_post32.len())]);
    let pe_post32_thrash_512k = build_synthetic_pe(
        true,
        &[
            PeSectionSpec {
                name: ".text0",
                virtual_size: s0_post32.len() as u32,
                virtual_addr: 0x1000,
                characteristics: 0x6000_0020,
                data: &s0_post32,
                force_raw_size_zero: false,
            },
            PeSectionSpec {
                name: ".text1",
                virtual_size: p_thrash.len() as u32,
                virtual_addr: 0x50000,
                characteristics: 0x6000_0020,
                data: &p_thrash,
                force_raw_size_zero: false,
            },
        ],
        false,
    );
    measure_p95(
        "pe_post32_anti_jump_thrash_512k",
        &pe_post32_thrash_512k,
        32,
    );

    // 2. pe_overlap_ssn_512k (gap=5 overlapping 0F 05 inside B8 0F 05 00 00 across 2x256 KiB)
    let mut s_overlap = Vec::with_capacity(256 * 1024);
    let mut overlap_per_sec = 0u32;
    while s_overlap.len() + 46 <= 256 * 1024 {
        s_overlap.extend_from_slice(&[0x6A, 0x01, 0x58, 0x49, 0x89, 0xCA]);
        s_overlap.extend(std::iter::repeat_n(0x90u8, 30));
        s_overlap.extend_from_slice(&[0xB8, 0x0F, 0x05, 0x00, 0x00, 0x4C, 0x8B, 0xD1, 0x0F, 0x05]);
        overlap_per_sec += 1;
    }
    let pe_overlap_512k = build_synthetic_pe(
        true,
        &[
            PeSectionSpec {
                name: ".text0",
                virtual_size: s_overlap.len() as u32,
                virtual_addr: 0x1000,
                characteristics: 0x6000_0020,
                data: &s_overlap,
                force_raw_size_zero: false,
            },
            PeSectionSpec {
                name: ".text1",
                virtual_size: s_overlap.len() as u32,
                virtual_addr: 0x50000,
                characteristics: 0x6000_0020,
                data: &s_overlap,
                force_raw_size_zero: false,
            },
        ],
        false,
    );
    measure_p95("pe_overlap_ssn_512k", &pe_overlap_512k, overlap_per_sec * 2);

    // 3. Gap 0..10 & remainder-tail equivalence with/without 32-stub details_full prefix
    let mut prefix32 = Vec::new();
    for _ in 0..32 {
        prefix32.extend_from_slice(&[0x4C, 0x8B, 0xD1, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x05]);
    }
    prefix32.resize(prefix32.len() + 64, 0x90);

    for gap in 0..=10usize {
        for tail_pad in 0..8usize {
            let mut body = vec![0x90u8; tail_pad];
            body.extend_from_slice(&[0x6A, 0x01, 0x58, 0x49, 0x89, 0xCA, 0x0F, 0x05]);
            // Gap bytes after first terminator before a second candidate
            if gap >= 6 {
                body.resize(body.len() + (gap - 6), 0x90);
                body.extend_from_slice(&[0x4C, 0x8B, 0xD1, 0x6A, 0x02, 0x58, 0x0F, 0x05]);
            } else {
                body.resize(body.len() + gap, 0x90);
                body.extend_from_slice(&[0x0F, 0x05]);
            }
            let pe_no_prefix = build_synthetic_pe(
                true,
                &[PeSectionSpec {
                    name: ".text",
                    virtual_size: 4096,
                    virtual_addr: 0x1000,
                    characteristics: 0x6000_0020,
                    data: &body,
                    force_raw_size_zero: false,
                }],
                false,
            );
            let mut with_prefix = prefix32.clone();
            with_prefix.extend_from_slice(&body);
            let pe_with_prefix = build_synthetic_pe(
                true,
                &[PeSectionSpec {
                    name: ".text",
                    virtual_size: 4096,
                    virtual_addr: 0x1000,
                    characteristics: 0x6000_0020,
                    data: &with_prefix,
                    force_raw_size_zero: false,
                }],
                false,
            );
            let expected = if gap >= 6 { 2 } else { 1 };
            let c1 = inspect_binary_bytes(&pe_no_prefix, "gap_no_prefix").direct_syscall_count;
            let c2 = inspect_binary_bytes(&pe_with_prefix, "gap_with_prefix").direct_syscall_count;
            assert_eq!(c1, expected, "gap={} tail_pad={} mismatch", gap, tail_pad);
            assert_eq!(
                c2,
                32 + expected,
                "gap={} tail_pad={} details_full mismatch",
                gap,
                tail_pad
            );
        }
    }
}

#[test]
fn iter9_pe_prefix_miss_thrash_512k_and_gap_49_55_equivalence() {
    let sla_limit_us: u64 = if cfg!(debug_assertions) {
        25_000
    } else {
        2_000
    };
    let measure_p95 = |label: &str, bin: &[u8], expected_stubs: u32| {
        let mut us = Vec::with_capacity(10);
        for i in 0..10 {
            let t0 = Instant::now();
            let v = inspect_binary_bytes(bin, label);
            let dt = t0.elapsed().as_micros() as u64;
            assert_eq!(
                v.direct_syscall_count, expected_stubs,
                "{}: expected {} stubs, got {}",
                label, expected_stubs, v.direct_syscall_count
            );
            assert!(v.syscall_stub_details.len() <= 32);
            if i >= 2 {
                us.push(dt);
            }
        }
        us.sort_unstable();
        let p95 = us[us.len() - 1];
        assert!(
            p95 < sla_limit_us,
            "{}: p95={}us exceeded {}us bound ({:?})",
            label,
            p95,
            sla_limit_us,
            us
        );
    };

    // 1. pe_no32_prefix_miss_thrash_512k & pe_post32_prefix_miss_thrash_512k
    //    Pattern: [4C 8B D1] + 49x[0x90] + [6A 01 58 0F 05] (57-byte period across 2x256 KiB)
    let mut p_miss = Vec::with_capacity(256 * 1024);
    while p_miss.len() + 57 <= 256 * 1024 {
        p_miss.extend_from_slice(&[0x4C, 0x8B, 0xD1]);
        p_miss.extend(std::iter::repeat_n(0x90u8, 49));
        p_miss.extend_from_slice(&[0x6A, 0x01, 0x58, 0x0F, 0x05]);
    }
    let pe_no32_miss = build_synthetic_pe(
        true,
        &[
            PeSectionSpec {
                name: ".text0",
                virtual_size: p_miss.len() as u32,
                virtual_addr: 0x1000,
                characteristics: 0x6000_0020,
                data: &p_miss,
                force_raw_size_zero: false,
            },
            PeSectionSpec {
                name: ".text1",
                virtual_size: p_miss.len() as u32,
                virtual_addr: 0x50000,
                characteristics: 0x6000_0020,
                data: &p_miss,
                force_raw_size_zero: false,
            },
        ],
        false,
    );
    measure_p95("pe_no32_prefix_miss_thrash_512k", &pe_no32_miss, 0);

    let mut s0_post32_miss = Vec::with_capacity(256 * 1024);
    for _ in 0..32 {
        s0_post32_miss
            .extend_from_slice(&[0x4C, 0x8B, 0xD1, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x05]);
    }
    let rem_miss = 256 * 1024 - s0_post32_miss.len();
    s0_post32_miss.extend_from_slice(&p_miss[..rem_miss]);
    let pe_post32_miss = build_synthetic_pe(
        true,
        &[
            PeSectionSpec {
                name: ".text0",
                virtual_size: s0_post32_miss.len() as u32,
                virtual_addr: 0x1000,
                characteristics: 0x6000_0020,
                data: &s0_post32_miss,
                force_raw_size_zero: false,
            },
            PeSectionSpec {
                name: ".text1",
                virtual_size: p_miss.len() as u32,
                virtual_addr: 0x50000,
                characteristics: 0x6000_0020,
                data: &p_miss,
                force_raw_size_zero: false,
            },
        ],
        false,
    );
    measure_p95("pe_post32_prefix_miss_thrash_512k", &pe_post32_miss, 32);

    // 2. Boundary equivalence for gap=49..=55 (and lookbehind NOPs=43..=55) with details_full=false/true,
    //    plus overlapping-SSN immediates inside trailing SSN (e.g. 6A 58 58, B8 0F 05 00 00).
    let mut prefix32 = Vec::new();
    for _ in 0..32 {
        prefix32.extend_from_slice(&[0x4C, 0x8B, 0xD1, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x05]);
    }
    prefix32.resize(prefix32.len() + 64, 0x90);

    for gap in 49..=55usize {
        for tail_pad in 0..8usize {
            let mut body = vec![0x90u8; tail_pad];
            body.extend_from_slice(&[0x6A, 0x01, 0x58, 0x49, 0x89, 0xCA, 0x0F, 0x05]);
            body.resize(body.len() + (gap - 6), 0x90);
            body.extend_from_slice(&[0x4C, 0x8B, 0xD1, 0x6A, 0x02, 0x58, 0x0F, 0x05]);

            let pe_no = build_synthetic_pe(
                true,
                &[PeSectionSpec {
                    name: ".text",
                    virtual_size: 4096,
                    virtual_addr: 0x1000,
                    characteristics: 0x6000_0020,
                    data: &body,
                    force_raw_size_zero: false,
                }],
                false,
            );
            let mut with_prefix = prefix32.clone();
            with_prefix.extend_from_slice(&body);
            let pe_yes = build_synthetic_pe(
                true,
                &[PeSectionSpec {
                    name: ".text",
                    virtual_size: 4096,
                    virtual_addr: 0x1000,
                    characteristics: 0x6000_0020,
                    data: &with_prefix,
                    force_raw_size_zero: false,
                }],
                false,
            );
            let c1 = inspect_binary_bytes(&pe_no, "gap49_55_no_prefix").direct_syscall_count;
            let c2 = inspect_binary_bytes(&pe_yes, "gap49_55_with_prefix").direct_syscall_count;
            assert_eq!(c1, 2, "gap={} tail_pad={} mismatch", gap, tail_pad);
            assert_eq!(
                c2, 34,
                "gap={} tail_pad={} details_full mismatch",
                gap, tail_pad
            );
        }

        // Lookbehind distance boundary: [4C 8B D1] + gap x [0x90] + [6A 01 58 0F 05]
        // At gap=49..=55, 3 + gap = 52..=58 > 48 => 0 stubs in both details_full=false & true.
        // At gap=45 (48B lookbehind) => 1 stub in both details_full=false & true.
        for lb_nops in [45usize, 46, gap] {
            let mut body = vec![0x4C, 0x8B, 0xD1];
            body.extend(std::iter::repeat_n(0x90u8, lb_nops));
            body.extend_from_slice(&[0x6A, 0x01, 0x58, 0x0F, 0x05]);
            let pe_no = build_synthetic_pe(
                true,
                &[PeSectionSpec {
                    name: ".text",
                    virtual_size: 4096,
                    virtual_addr: 0x1000,
                    characteristics: 0x6000_0020,
                    data: &body,
                    force_raw_size_zero: false,
                }],
                false,
            );
            let mut with_prefix = prefix32.clone();
            with_prefix.extend_from_slice(&body);
            let pe_yes = build_synthetic_pe(
                true,
                &[PeSectionSpec {
                    name: ".text",
                    virtual_size: 4096,
                    virtual_addr: 0x1000,
                    characteristics: 0x6000_0020,
                    data: &with_prefix,
                    force_raw_size_zero: false,
                }],
                false,
            );
            let expected = if lb_nops <= 45 { 1 } else { 0 };
            let c1 = inspect_binary_bytes(&pe_no, "lb_no_prefix").direct_syscall_count;
            let c2 = inspect_binary_bytes(&pe_yes, "lb_with_prefix").direct_syscall_count;
            assert_eq!(c1, expected, "lb_nops={} mismatch", lb_nops);
            assert_eq!(
                c2,
                32 + expected,
                "lb_nops={} details_full mismatch",
                lb_nops
            );
        }
    }

    // Overlapping SSN inside trailing SSN (`[4C 8B D1] + 45x[0x90] + [6A 6A 58 58 0F 05]`):
    // `6A 6A 58` overlaps `6A 58 58` at term_pos-3; must match identically in details_full=false & true.
    let mut overlap_6a = vec![0x4C, 0x8B, 0xD1];
    overlap_6a.extend(std::iter::repeat_n(0x90u8, 45));
    overlap_6a.extend_from_slice(&[0x6A, 0x6A, 0x58, 0x58, 0x0F, 0x05]);
    let pe_ov_no = build_synthetic_pe(
        true,
        &[PeSectionSpec {
            name: ".text",
            virtual_size: 4096,
            virtual_addr: 0x1000,
            characteristics: 0x6000_0020,
            data: &overlap_6a,
            force_raw_size_zero: false,
        }],
        false,
    );
    let mut ov_yes_data = prefix32.clone();
    ov_yes_data.extend_from_slice(&overlap_6a);
    let pe_ov_yes = build_synthetic_pe(
        true,
        &[PeSectionSpec {
            name: ".text",
            virtual_size: 4096,
            virtual_addr: 0x1000,
            characteristics: 0x6000_0020,
            data: &ov_yes_data,
            force_raw_size_zero: false,
        }],
        false,
    );
    assert_eq!(
        inspect_binary_bytes(&pe_ov_no, "ov_6a_no").direct_syscall_count,
        1
    );
    assert_eq!(
        inspect_binary_bytes(&pe_ov_yes, "ov_6a_yes").direct_syscall_count,
        33
    );
}
