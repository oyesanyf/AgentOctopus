//! Fast (`<2ms`) Pure-Rust Pre-Spawn REA PE/ELF/Mach-O Header & Direct-Syscall Gate.
//!
//! Design boundary:
//! - Strictly a zero-panic, bounds-checked, bounded-I/O (`64 KiB` header + `256 KiB` per-section /
//!   `524_288` total executable scan budget) pre-exec containment gate for `octopus run`.
//! - Intentionally excludes heavy EDR disassembly, Capstone/xori/capa/hollows_hunter memory-carving,
//!   or whole-binary scanning.
//! - Uses handle-identity caching (`KernelFileIdentityKey` on Windows, `(dev, ino, mtime, size)` on
//!   Unix) while still holding the TOCTOU-locked `FILE_SHARE_READ` / `O_NOFOLLOW` file handle.

use crate::security::rate_limit_backoff::ReaBinaryFact;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{OnceLock, RwLock};
use std::time::Instant;

const HEADER_WINDOW_BYTES: usize = 65_536;
const MAX_SECTION_ENTROPY_BYTES: usize = 262_144;
const MAX_TOTAL_EXEC_SCAN_BYTES: usize = 524_288;
const MIN_SECTION_SCAN_SLICE: usize = 32_768;
const MAX_PE_SECTIONS: usize = 512;
const MAX_PE_LFANEW_BYTES: usize = 16 * 1024 * 1024;
const MAX_STUB_DETAILS: usize = 32;
const MAX_ELF_PHDRS: usize = 64;
const MAX_ELF_SHDRS: usize = 128;
const MAX_MACHO_CMDS: usize = 256;
const MAX_MACHO_FAT_ARCHS: usize = 16;
const CACHE_CAPACITY_LIMIT: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryFormat {
    Pe32,
    Pe64,
    Elf32,
    Elf64,
    MachO32,
    MachO64,
    MachOFat,
    Wasm,
    ScriptShebang,
    Unknown,
}

impl BinaryFormat {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pe32 => "pe32",
            Self::Pe64 => "pe64",
            Self::Elf32 => "elf32",
            Self::Elf64 => "elf64",
            Self::MachO32 => "macho32",
            Self::MachO64 => "macho64",
            Self::MachOFat => "macho_fat",
            Self::Wasm => "wasm",
            Self::ScriptShebang => "script_shebang",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryIntegrityVerdict {
    pub format: BinaryFormat,
    pub path: String,
    pub is_packed: bool,
    pub has_packer_marker: bool,
    pub packer_markers: Vec<String>,
    pub has_wx_violation: bool,
    pub wx_sections: Vec<String>,
    pub has_raw_size_anomaly: bool,
    pub raw_size_anomalies: Vec<String>,
    pub obfuscation_entropy: f64,
    pub direct_syscall_count: u32,
    pub syscall_stub_details: Vec<String>,
    pub is_authenticode_signed: bool,
    pub is_code_signed: bool,
    pub header_anomalies: Vec<String>,
    pub shebang_interpreter: Option<String>,
    pub inspection_micros: u64,
}

impl BinaryIntegrityVerdict {
    fn clean(format: BinaryFormat, path: impl Into<String>) -> Self {
        Self {
            format,
            path: path.into(),
            is_packed: false,
            has_packer_marker: false,
            packer_markers: Vec::new(),
            has_wx_violation: false,
            wx_sections: Vec::new(),
            has_raw_size_anomaly: false,
            raw_size_anomalies: Vec::new(),
            obfuscation_entropy: 0.0,
            direct_syscall_count: 0,
            syscall_stub_details: Vec::new(),
            is_authenticode_signed: false,
            is_code_signed: false,
            header_anomalies: Vec::new(),
            shebang_interpreter: None,
            inspection_micros: 0,
        }
    }

    pub fn to_rea_binary_fact(&self, pid: u32) -> ReaBinaryFact {
        ReaBinaryFact {
            pid,
            binary_path: self.path.clone(),
            is_packed: self.is_packed,
            direct_syscall_count: self.direct_syscall_count,
            obfuscation_entropy: self.obfuscation_entropy,
            is_authenticode_signed: self.is_authenticode_signed || self.is_code_signed,
            yara_detections: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum FileIdentityCacheKey {
    #[cfg(windows)]
    Windows {
        key: crate::security::executable_identity::KernelFileIdentityKey,
        check_catalog_sig: bool,
    },
    #[cfg(unix)]
    Unix {
        dev: u64,
        ino: u64,
        mtime_sec: i64,
        mtime_nsec: i64,
        size: u64,
        check_catalog_sig: bool,
    },
}

fn verdict_cache() -> &'static RwLock<HashMap<FileIdentityCacheKey, BinaryIntegrityVerdict>> {
    static CACHE: OnceLock<RwLock<HashMap<FileIdentityCacheKey, BinaryIntegrityVerdict>>> =
        OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(HashMap::with_capacity(64)))
}

/// Zero-panic bounds-checked byte cursor. Never indexes raw slices or calls `.unwrap()`.
#[derive(Clone, Copy)]
pub struct ByteCursor<'a> {
    bytes: &'a [u8],
}

impl<'a> ByteCursor<'a> {
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn slice(&self, offset: usize, len: usize) -> Option<&'a [u8]> {
        let end = offset.checked_add(len)?;
        self.bytes.get(offset..end)
    }

    pub fn u8_at(&self, offset: usize) -> Option<u8> {
        self.bytes.get(offset).copied()
    }

    pub fn u16_le(&self, offset: usize) -> Option<u16> {
        let s = self.slice(offset, 2)?;
        let arr: [u8; 2] = s.try_into().ok()?;
        Some(u16::from_le_bytes(arr))
    }

    pub fn u16_be(&self, offset: usize) -> Option<u16> {
        let s = self.slice(offset, 2)?;
        let arr: [u8; 2] = s.try_into().ok()?;
        Some(u16::from_be_bytes(arr))
    }

    pub fn u32_le(&self, offset: usize) -> Option<u32> {
        let s = self.slice(offset, 4)?;
        let arr: [u8; 4] = s.try_into().ok()?;
        Some(u32::from_le_bytes(arr))
    }

    pub fn u32_be(&self, offset: usize) -> Option<u32> {
        let s = self.slice(offset, 4)?;
        let arr: [u8; 4] = s.try_into().ok()?;
        Some(u32::from_be_bytes(arr))
    }

    pub fn u64_le(&self, offset: usize) -> Option<u64> {
        let s = self.slice(offset, 8)?;
        let arr: [u8; 8] = s.try_into().ok()?;
        Some(u64::from_le_bytes(arr))
    }

    pub fn u64_be(&self, offset: usize) -> Option<u64> {
        let s = self.slice(offset, 8)?;
        let arr: [u8; 8] = s.try_into().ok()?;
        Some(u64::from_be_bytes(arr))
    }

    pub fn u16_endian(&self, offset: usize, le: bool) -> Option<u16> {
        if le {
            self.u16_le(offset)
        } else {
            self.u16_be(offset)
        }
    }

    pub fn u32_endian(&self, offset: usize, le: bool) -> Option<u32> {
        if le {
            self.u32_le(offset)
        } else {
            self.u32_be(offset)
        }
    }

    pub fn u64_endian(&self, offset: usize, le: bool) -> Option<u64> {
        if le {
            self.u64_le(offset)
        } else {
            self.u64_be(offset)
        }
    }

    pub fn fixed_cstr(&self, offset: usize, max_len: usize) -> Option<String> {
        let raw = self.slice(offset, max_len)?;
        let nul_pos = memchr::memchr(0, raw).unwrap_or(raw.len());
        let trimmed = raw.get(..nul_pos).unwrap_or(raw);
        Some(String::from_utf8_lossy(trimmed).trim().to_string())
    }
}

enum BinarySource<'a> {
    Slice(&'a [u8]),
    LockedFile {
        file: &'a mut std::fs::File,
        total_len: u64,
        header_buf: Vec<u8>,
    },
}

impl<'a> BinarySource<'a> {
    fn total_len(&self) -> u64 {
        match self {
            Self::Slice(b) => b.len() as u64,
            Self::LockedFile { total_len, .. } => *total_len,
        }
    }

    fn header_slice(&self) -> &[u8] {
        match self {
            Self::Slice(b) => {
                let end = b.len().min(HEADER_WINDOW_BYTES);
                b.get(..end).unwrap_or(&[])
            }
            Self::LockedFile { header_buf, .. } => header_buf.as_slice(),
        }
    }

    fn read_window(&mut self, offset: u64, max_len: usize) -> Cow<'_, [u8]> {
        if max_len == 0 {
            return Cow::Borrowed(&[]);
        }
        match self {
            Self::Slice(b) => {
                let Ok(off_usize) = usize::try_from(offset) else {
                    return Cow::Borrowed(&[]);
                };
                if off_usize >= b.len() {
                    return Cow::Borrowed(&[]);
                }
                let avail = b.len().saturating_sub(off_usize);
                let end = off_usize.saturating_add(avail.min(max_len));
                Cow::Borrowed(b.get(off_usize..end).unwrap_or(&[]))
            }
            Self::LockedFile {
                file,
                total_len,
                header_buf,
            } => {
                if offset >= *total_len {
                    return Cow::Borrowed(&[]);
                }
                let avail_u64 = total_len.saturating_sub(offset);
                let want = (avail_u64.min(max_len as u64)) as usize;
                if want == 0 {
                    return Cow::Borrowed(&[]);
                }
                if let Some(end_u64) = offset.checked_add(want as u64) {
                    if let (Ok(s), Ok(e)) = (usize::try_from(offset), usize::try_from(end_u64)) {
                        if e <= header_buf.len() {
                            return Cow::Borrowed(header_buf.get(s..e).unwrap_or(&[]));
                        }
                    }
                }
                if file.seek(SeekFrom::Start(offset)).is_err() {
                    return Cow::Borrowed(&[]);
                }
                let mut out = vec![0u8; want];
                let mut filled = 0usize;
                while filled < want {
                    let dst = match out.get_mut(filled..want) {
                        Some(d) => d,
                        None => break,
                    };
                    match file.read(dst) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => filled = filled.saturating_add(n),
                    }
                }
                out.truncate(filled);
                Cow::Owned(out)
            }
        }
    }
}

/// Inspects an in-memory binary slice using pure-Rust bounds-checked header and stub scanning.
pub fn inspect_binary_bytes(bytes: &[u8], path_label: &str) -> BinaryIntegrityVerdict {
    let t0 = Instant::now();
    let mut source = BinarySource::Slice(bytes);
    let mut verdict = inspect_source(&mut source, path_label);
    verdict.inspection_micros = t0.elapsed().as_micros() as u64;
    verdict
}

/// Inspects an already-locked OS file handle (`FILE_SHARE_READ` / `O_NOFOLLOW`) using bounded
/// header/section reads and handle-identity caching (`<2ms`).
pub fn inspect_locked_file(
    file: &mut std::fs::File,
    canonical_path: &Path,
    file_size: u64,
    _stem: &str,
    check_catalog_sig: bool,
) -> Result<BinaryIntegrityVerdict, String> {
    let t0 = Instant::now();
    let path_str = canonical_path.to_string_lossy().to_string();

    let cache_key = query_cache_key(file, file_size, check_catalog_sig);
    if let Some(ref key) = cache_key {
        if let Ok(guard) = verdict_cache().read() {
            if let Some(cached) = guard.get(key) {
                let mut hit = cached.clone();
                hit.path = path_str;
                hit.inspection_micros = t0.elapsed().as_micros() as u64;
                return Ok(hit);
            }
        }
    }

    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("failed to seek executable '{}': {}", path_str, e))?;
    let header_cap = file_size.min(HEADER_WINDOW_BYTES as u64) as usize;
    let mut header_buf = vec![0u8; header_cap];
    let mut filled = 0usize;
    while filled < header_cap {
        let dst = match header_buf.get_mut(filled..header_cap) {
            Some(d) => d,
            None => break,
        };
        match file.read(dst) {
            Ok(0) => break,
            Ok(n) => filled = filled.saturating_add(n),
            Err(e) => {
                return Err(format!(
                    "failed to read executable header '{}': {}",
                    path_str, e
                ))
            }
        }
    }
    header_buf.truncate(filled);

    let mut source = BinarySource::LockedFile {
        file,
        total_len: file_size,
        header_buf,
    };
    let mut verdict = inspect_source(&mut source, &path_str);

    #[cfg(windows)]
    if check_catalog_sig && matches!(verdict.format, BinaryFormat::Pe32 | BinaryFormat::Pe64) {
        if let BinarySource::LockedFile { file, .. } = &source {
            let crypto_signed = if verdict.is_authenticode_signed {
                crate::security::executable_identity::is_windows_authenticode_signed_handle(file)
                    || crate::security::executable_identity::is_windows_catalog_signed_handle(file)
            } else {
                crate::security::executable_identity::is_windows_catalog_signed_handle(file)
                    || crate::security::executable_identity::is_windows_authenticode_signed_handle(
                        file,
                    )
            };
            verdict.is_authenticode_signed = crypto_signed;
            verdict.is_code_signed = crypto_signed;
        }
    }

    verdict.inspection_micros = t0.elapsed().as_micros() as u64;

    if let Some(key) = cache_key {
        if let Ok(mut guard) = verdict_cache().write() {
            if guard.len() >= CACHE_CAPACITY_LIMIT {
                guard.clear();
            }
            guard.insert(key, verdict.clone());
        }
    }

    Ok(verdict)
}

fn query_cache_key(
    file: &std::fs::File,
    file_size: u64,
    check_catalog_sig: bool,
) -> Option<FileIdentityCacheKey> {
    #[cfg(windows)]
    {
        crate::security::executable_identity::query_file_identity_key_from_file(file).map(|key| {
            let _ = file_size;
            FileIdentityCacheKey::Windows {
                key,
                check_catalog_sig,
            }
        })
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        file.metadata().ok().map(|meta| FileIdentityCacheKey::Unix {
            dev: meta.dev(),
            ino: meta.ino(),
            mtime_sec: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            size: file_size,
            check_catalog_sig,
        })
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (file, file_size, check_catalog_sig);
        None
    }
}

fn inspect_source(source: &mut BinarySource<'_>, path_label: &str) -> BinaryIntegrityVerdict {
    let hdr = source.header_slice();
    if hdr.len() < 4 {
        let mut v = BinaryIntegrityVerdict::clean(BinaryFormat::Unknown, path_label);
        if !hdr.is_empty() {
            v.header_anomalies
                .push("truncated_magic_header".to_string());
        }
        return v;
    }

    if hdr.get(..4) == Some(b"\x00asm") {
        let mut v = BinaryIntegrityVerdict::clean(BinaryFormat::Wasm, path_label);
        if hdr.len() < 8 || hdr.get(4..8) != Some(&[0x01, 0x00, 0x00, 0x00]) {
            v.header_anomalies
                .push("wasm_truncated_or_invalid_header".to_string());
        }
        return v;
    }

    if hdr.get(..2) == Some(b"#!") {
        let mut v = BinaryIntegrityVerdict::clean(BinaryFormat::ScriptShebang, path_label);
        v.shebang_interpreter = parse_shebang_interpreter(hdr);
        return v;
    }

    if hdr.get(..2) == Some(b"MZ") {
        return inspect_pe(source, path_label);
    }

    if hdr.get(..4) == Some(b"\x7FELF") {
        return inspect_elf(source, path_label);
    }

    let c = ByteCursor::new(hdr);
    if let Some(magic_be) = c.u32_be(0) {
        if matches!(
            magic_be,
            0xCAFE_BABE | 0xBEBA_FECA | 0xCAFE_BABF | 0xBFBA_FECA
        ) {
            if let Some(fat_verdict) = try_inspect_macho_fat(source, path_label, 0) {
                return fat_verdict;
            }
            // Java .class files also begin with 0xCAFEBABE; return Unknown without misparsing.
            return BinaryIntegrityVerdict::clean(BinaryFormat::Unknown, path_label);
        }
        if matches!(
            magic_be,
            0xFEED_FACE | 0xCEFA_EDFE | 0xFEED_FACF | 0xCFFA_EDFE
        ) {
            let total_len = source.total_len();
            let mut remaining_budget = MAX_TOTAL_EXEC_SCAN_BYTES;
            return inspect_macho_slice(source, path_label, 0, total_len, &mut remaining_budget);
        }
    }

    BinaryIntegrityVerdict::clean(BinaryFormat::Unknown, path_label)
}

fn parse_shebang_interpreter(hdr: &[u8]) -> Option<String> {
    let line_end = memchr::memchr(b'\n', hdr).unwrap_or(hdr.len()).min(512);
    let line_bytes = hdr.get(2..line_end)?;
    let line = String::from_utf8_lossy(line_bytes);
    let trimmed = line.trim_end_matches('\r').trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.split_whitespace();
    let first = parts.next()?;
    let first_base = Path::new(first)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(first);
    if first_base == "env" {
        for tok in parts {
            if tok.starts_with('-') || tok.contains('=') {
                continue;
            }
            return Some(tok.to_string());
        }
        None
    } else {
        Some(first.to_string())
    }
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let total = bytes.len() as f64;
    if bytes.len() <= 32_768 {
        let mut counts = [0u32; 256];
        for &b in bytes {
            if let Some(slot) = counts.get_mut(b as usize) {
                *slot = slot.saturating_add(1);
            }
        }
        let mut sum_c_log2 = 0.0f64;
        for &cnt in &counts {
            if cnt > 0 {
                let cf = cnt as f64;
                sum_c_log2 += cf * cf.log2();
            }
        }
        return (total.log2() - sum_c_log2 / total).clamp(0.0, 8.0);
    }
    let mut c0 = [0u32; 256];
    let mut c1 = [0u32; 256];
    let mut c2 = [0u32; 256];
    let mut c3 = [0u32; 256];
    let chunks = bytes.chunks_exact(4);
    let rem = chunks.remainder();
    for ch in chunks {
        if let [b0, b1, b2, b3] = *ch {
            if let Some(slot) = c0.get_mut(b0 as usize) {
                *slot = slot.saturating_add(1);
            }
            if let Some(slot) = c1.get_mut(b1 as usize) {
                *slot = slot.saturating_add(1);
            }
            if let Some(slot) = c2.get_mut(b2 as usize) {
                *slot = slot.saturating_add(1);
            }
            if let Some(slot) = c3.get_mut(b3 as usize) {
                *slot = slot.saturating_add(1);
            }
        }
    }
    for &b in rem {
        if let Some(slot) = c0.get_mut(b as usize) {
            *slot = slot.saturating_add(1);
        }
    }
    let mut sum_c_log2 = 0.0f64;
    for (((&a, &b), &c), &d) in c0.iter().zip(&c1).zip(&c2).zip(&c3) {
        let count = a.saturating_add(b).saturating_add(c).saturating_add(d);
        if count > 0 {
            let cf = count as f64;
            sum_c_log2 += cf * cf.log2();
        }
    }
    (total.log2() - sum_c_log2 / total).clamp(0.0, 8.0)
}

fn find_bytes_needle(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let first = match needle.first() {
        Some(&b) => b,
        None => return None,
    };
    for pos in memchr::memchr_iter(first, haystack) {
        if let Some(end) = pos.checked_add(needle.len()) {
            if haystack.get(pos..end) == Some(needle) {
                return Some(pos);
            }
        }
    }
    None
}

fn contains_bytes_needle(haystack: &[u8], needle: &[u8]) -> bool {
    find_bytes_needle(haystack, needle).is_some()
}

fn compute_suffix_reserves(sizes: &[u64], per_sec_floor: usize) -> Vec<usize> {
    let mut reserves = vec![0usize; sizes.len()];
    let mut acc = 0usize;
    for (idx, &sz) in sizes.iter().enumerate().rev() {
        if let Some(slot) = reserves.get_mut(idx) {
            *slot = acc;
        }
        let r = usize::try_from(sz).unwrap_or(usize::MAX).min(per_sec_floor);
        acc = acc.saturating_add(r);
    }
    reserves
}

fn fair_section_scan_len(
    sizes: &[u64],
    suffix_reserves: &[usize],
    idx: usize,
    remaining_budget: usize,
) -> usize {
    if remaining_budget == 0 {
        return 0;
    }
    let cur_sz = sizes
        .get(idx)
        .copied()
        .map(|s| usize::try_from(s).unwrap_or(usize::MAX))
        .unwrap_or(0);
    if cur_sz == 0 {
        return 0;
    }
    let future_reserve = suffix_reserves.get(idx).copied().unwrap_or(0);
    let avail = remaining_budget.saturating_sub(future_reserve.min(remaining_budget));
    cur_sz.min(MAX_SECTION_ENTROPY_BYTES).min(avail)
}

fn is_packer_section_name(name: &str) -> bool {
    let lower = name.trim_matches('\0').trim().to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }
    matches!(
        lower.as_str(),
        "upx0"
            | "upx1"
            | "upx2"
            | "upx!"
            | ".upx"
            | "upx"
            | "__upx"
            | "mpress"
            | "mpress1"
            | "mpress2"
            | ".vmp0"
            | ".vmp1"
            | ".vmp2"
            | ".themida"
            | ".winlice"
            | ".aspack"
            | ".adata"
            | ".nsp0"
            | ".nsp1"
            | ".nsp2"
            | ".enigma1"
            | ".enigma2"
            | ".petite"
            | ".packed"
    ) || lower.starts_with("upx")
        || lower.starts_with("mpress")
        || lower.starts_with(".vmp")
}

fn push_unique(vec: &mut Vec<String>, item: impl Into<String>) {
    let s = item.into();
    if !vec.iter().any(|existing| existing == &s) {
        vec.push(s);
    }
}

fn finalize_packed_flag(v: &mut BinaryIntegrityVerdict) {
    v.is_packed = v.has_packer_marker
        || (v.obfuscation_entropy >= 6.4 && (v.has_wx_violation || v.has_raw_size_anomaly));
}

// ============================================================================
// PE32 / PE32+ Inspector
// ============================================================================

#[derive(Clone, Copy)]
enum PeSsnEncoding {
    MovEaxImm32,
    MovRaxImm32,
    PushImm8PopRax,
    PushImm32PopRax,
}

fn match_pe_ssn_load(slice: &[u8], pos: usize) -> Option<(usize, PeSsnEncoding)> {
    let b = slice.get(pos).copied()?;
    match b {
        0xB8 => {
            let s = slice.get(pos..pos.checked_add(5)?)?;
            if s.get(3..5) == Some(&[0x00, 0x00]) {
                Some((5, PeSsnEncoding::MovEaxImm32))
            } else {
                None
            }
        }
        0x48 => {
            let s = slice.get(pos..pos.checked_add(7)?)?;
            if s.get(1..3) == Some(&[0xC7, 0xC0]) && s.get(5..7) == Some(&[0x00, 0x00]) {
                Some((7, PeSsnEncoding::MovRaxImm32))
            } else {
                None
            }
        }
        0x6A => {
            let s = slice.get(pos..pos.checked_add(3)?)?;
            if s.get(2) == Some(&0x58) {
                Some((3, PeSsnEncoding::PushImm8PopRax))
            } else {
                None
            }
        }
        0x68 => {
            let s = slice.get(pos..pos.checked_add(6)?)?;
            if s.get(3..6) == Some(&[0x00, 0x00, 0x58]) {
                Some((6, PeSsnEncoding::PushImm32PopRax))
            } else {
                None
            }
        }
        _ => None,
    }
}

#[inline(always)]
fn match_pe_r10_at(slice: &[u8], pos: usize) -> Option<bool> {
    match slice.get(pos..pos.checked_add(3)?) {
        Some([0x4C, 0x8B, 0xD1]) => Some(true),
        Some([0x49, 0x89, 0xCA]) => Some(false),
        _ => None,
    }
}

#[inline(always)]
fn pe_stub_tag(
    encoding: PeSsnEncoding,
    is_pat_a: bool,
    is_int2e: bool,
    is_tail_zero: bool,
    is_reordered_or_interleaved: bool,
) -> &'static str {
    match encoding {
        PeSsnEncoding::MovEaxImm32 => match (
            is_pat_a,
            is_int2e,
            is_tail_zero,
            is_reordered_or_interleaved,
        ) {
            (true, false, true, false) => "pe_hells_gate_stub",
            (false, false, true, false) => "pe_halos_alt_stub",
            (true, false, false, false) => "pe_halos_gate_stub",
            (false, false, false, false) => "pe_halos_alt_nops_stub",
            (true, true, _, false) => "pe_int2e_syscall_stub",
            (false, true, _, false) => "pe_alt_int2e_syscall_stub",
            (true, false, _, true) => "pe_reordered_or_interleaved_syscall_stub",
            (false, false, _, true) => "pe_alt_reordered_or_interleaved_syscall_stub",
            (true, true, _, true) => "pe_reordered_or_interleaved_int2e_stub",
            (false, true, _, true) => "pe_alt_reordered_or_interleaved_int2e_stub",
        },
        PeSsnEncoding::MovRaxImm32 => {
            if is_int2e {
                "pe_mov_rax_int2e_stub"
            } else {
                "pe_mov_rax_syscall_stub"
            }
        }
        PeSsnEncoding::PushImm8PopRax | PeSsnEncoding::PushImm32PopRax => {
            if is_int2e {
                "pe_push_pop_rax_int2e_stub"
            } else {
                "pe_push_pop_rax_syscall_stub"
            }
        }
    }
}

#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn record_pe_stub_detail(
    encoding: PeSsnEncoding,
    is_pat_a: bool,
    is_int2e: bool,
    is_tail_zero: bool,
    is_reordered_or_interleaved: bool,
    section_name: &str,
    stub_start: usize,
    details: &mut Vec<String>,
) -> bool {
    if details.len() < MAX_STUB_DETAILS {
        let tag = pe_stub_tag(
            encoding,
            is_pat_a,
            is_int2e,
            is_tail_zero,
            is_reordered_or_interleaved,
        );
        details.push(format!("{}@{}+0x{:x}", tag, section_name, stub_start));
    }
    details.len() >= MAX_STUB_DETAILS
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PeFastHitOutcome {
    Hit,
    DefinitiveMiss,
    Unknown,
}

#[inline(always)]
fn try_pe_local_fast_hit_count_only(
    slice: &[u8],
    last_matched_end: usize,
    term_pos: usize,
    details_full: bool,
) -> PeFastHitOutcome {
    let gap = term_pos.saturating_sub(last_matched_end);
    if gap < 6 {
        return PeFastHitOutcome::DefinitiveMiss;
    }
    if gap == 6 {
        let is_hit = matches!(
            slice.get(last_matched_end..term_pos),
            Some(
                [0x4C, 0x8B, 0xD1, 0x6A, _, 0x58]
                    | [0x49, 0x89, 0xCA, 0x6A, _, 0x58]
                    | [0x6A, _, 0x58, 0x4C, 0x8B, 0xD1]
                    | [0x6A, _, 0x58, 0x49, 0x89, 0xCA]
            )
        );
        return if is_hit {
            if details_full {
                PeFastHitOutcome::Hit
            } else {
                PeFastHitOutcome::Unknown
            }
        } else {
            PeFastHitOutcome::DefinitiveMiss
        };
    }
    let tail_b = slice.get(term_pos.saturating_sub(1)).copied();
    if details_full {
        match tail_b {
            Some(0x58) => {
                if let Some(s6) = slice.get(term_pos.saturating_sub(6)..term_pos) {
                    if matches!(
                        s6,
                        [0x4C, 0x8B, 0xD1, 0x6A, _, 0x58] | [0x49, 0x89, 0xCA, 0x6A, _, 0x58]
                    ) {
                        return PeFastHitOutcome::Hit;
                    }
                }
                if gap >= 7 {
                    if let Some(s7) = slice.get(term_pos.saturating_sub(7)..term_pos) {
                        if matches!(
                            s7,
                            [0x4C, 0x8B, 0xD1, _, 0x6A, _, 0x58]
                                | [0x49, 0x89, 0xCA, _, 0x6A, _, 0x58]
                        ) {
                            return PeFastHitOutcome::Hit;
                        }
                    }
                }
                if gap >= 9 {
                    if let Some(s9) = slice.get(term_pos.saturating_sub(9)..term_pos) {
                        if matches!(
                            s9,
                            [0x4C, 0x8B, 0xD1, 0x68, _, _, 0x00, 0x00, 0x58]
                                | [0x49, 0x89, 0xCA, 0x68, _, _, 0x00, 0x00, 0x58]
                        ) {
                            return PeFastHitOutcome::Hit;
                        }
                    }
                }
            }
            Some(0x00) => {
                if gap >= 8 {
                    if let Some(s8) = slice.get(term_pos.saturating_sub(8)..term_pos) {
                        if matches!(
                            s8,
                            [0x4C, 0x8B, 0xD1, 0xB8, _, _, 0x00, 0x00]
                                | [0x49, 0x89, 0xCA, 0xB8, _, _, 0x00, 0x00]
                        ) {
                            return PeFastHitOutcome::Hit;
                        }
                    }
                }
                if gap >= 9 {
                    if let Some(s9) = slice.get(term_pos.saturating_sub(9)..term_pos) {
                        if matches!(
                            s9,
                            [0x4C, 0x8B, 0xD1, _, 0xB8, _, _, 0x00, 0x00]
                                | [0x49, 0x89, 0xCA, _, 0xB8, _, _, 0x00, 0x00]
                        ) {
                            return PeFastHitOutcome::Hit;
                        }
                    }
                }
                if gap >= 10 {
                    if let Some(s10) = slice.get(term_pos.saturating_sub(10)..term_pos) {
                        if matches!(
                            s10,
                            [0x4C, 0x8B, 0xD1, 0x48, 0xC7, 0xC0, _, _, 0x00, 0x00]
                                | [0x49, 0x89, 0xCA, 0x48, 0xC7, 0xC0, _, _, 0x00, 0x00]
                        ) {
                            return PeFastHitOutcome::Hit;
                        }
                    }
                }
            }
            Some(0xD1 | 0xCA) => {
                if let Some(r10_pos) = term_pos.checked_sub(3) {
                    if r10_pos >= last_matched_end.saturating_add(3)
                        && match_pe_r10_at(slice, r10_pos).is_some()
                    {
                        let has_ssn_before_r10 = |end_pos: usize| -> bool {
                            match slice.get(end_pos.saturating_sub(1)).copied() {
                                Some(0x58) => {
                                    end_pos.checked_sub(3).is_some_and(|p3| {
                                        p3 >= last_matched_end
                                            && matches!(
                                                slice.get(p3..end_pos),
                                                Some([0x6A, _, 0x58])
                                            )
                                    }) || end_pos.checked_sub(6).is_some_and(|p6| {
                                        p6 >= last_matched_end
                                            && matches!(
                                                slice.get(p6..end_pos),
                                                Some([0x68, _, _, 0x00, 0x00, 0x58])
                                            )
                                    })
                                }
                                Some(0x00) => {
                                    end_pos.checked_sub(5).is_some_and(|p5| {
                                        p5 >= last_matched_end
                                            && matches!(
                                                slice.get(p5..end_pos),
                                                Some([0xB8, _, _, 0x00, 0x00])
                                            )
                                    }) || end_pos.checked_sub(7).is_some_and(|p7| {
                                        p7 >= last_matched_end
                                            && matches!(
                                                slice.get(p7..end_pos),
                                                Some([0x48, 0xC7, 0xC0, _, _, 0x00, 0x00])
                                            )
                                    })
                                }
                                _ => false,
                            }
                        };
                        if has_ssn_before_r10(r10_pos)
                            || has_ssn_before_r10(r10_pos.saturating_sub(1))
                        {
                            return PeFastHitOutcome::Hit;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    let ssn_pos_opt = match tail_b {
        Some(0x58) => {
            let p3_match = term_pos.checked_sub(3).filter(|&p3| {
                p3 >= last_matched_end && matches!(slice.get(p3..term_pos), Some([0x6A, _, 0x58]))
            });
            p3_match.or_else(|| {
                term_pos.checked_sub(6).filter(|&p6| {
                    p6 >= last_matched_end
                        && matches!(
                            slice.get(p6..term_pos),
                            Some([0x68, _, _, 0x00, 0x00, 0x58])
                        )
                })
            })
        }
        Some(0x00) => {
            let p5_match = term_pos.checked_sub(5).filter(|&p5| {
                p5 >= last_matched_end
                    && matches!(slice.get(p5..term_pos), Some([0xB8, _, _, 0x00, 0x00]))
            });
            p5_match.or_else(|| {
                term_pos.checked_sub(7).filter(|&p7| {
                    p7 >= last_matched_end
                        && matches!(
                            slice.get(p7..term_pos),
                            Some([0x48, 0xC7, 0xC0, _, _, 0x00, 0x00])
                        )
                })
            })
        }
        _ => None,
    };
    if let Some(ssn_pos) = ssn_pos_opt {
        let lb_start = ssn_pos.saturating_sub(48).max(last_matched_end);
        let Some(win) = slice.get(lb_start..ssn_pos) else {
            return PeFastHitOutcome::Unknown;
        };
        for rel in memchr::memchr2_iter(0x4C, 0x49, win) {
            if match_pe_r10_at(slice, lb_start.saturating_add(rel)).is_some() {
                return if details_full {
                    PeFastHitOutcome::Hit
                } else {
                    PeFastHitOutcome::Unknown
                };
            }
        }
        if memchr::memchr2(0x58, 0x00, win).is_none() {
            let ssn_len = term_pos.saturating_sub(ssn_pos);
            let no_overlap_ssn = match ssn_len {
                3 => slice.get(ssn_pos.saturating_add(1)) != Some(&0x58),
                5 | 6 => slice
                    .get(ssn_pos.saturating_add(1)..ssn_pos.saturating_add(3))
                    .is_some_and(|imm| memchr::memchr2(0x58, 0x00, imm).is_none()),
                7 => slice
                    .get(ssn_pos.saturating_add(3)..ssn_pos.saturating_add(5))
                    .is_some_and(|imm| memchr::memchr2(0x58, 0x00, imm).is_none()),
                _ => false,
            };
            if no_overlap_ssn {
                return PeFastHitOutcome::DefinitiveMiss;
            }
            return PeFastHitOutcome::Unknown;
        }
        if !details_full {
            return PeFastHitOutcome::Unknown;
        }
        let local_start = term_pos.saturating_sub(55).max(last_matched_end);
        if lb_start <= local_start
            || slice
                .get(local_start..lb_start)
                .is_none_or(|prefix| memchr::memchr2(0x4C, 0x49, prefix).is_none())
        {
            return PeFastHitOutcome::Unknown;
        }
    }
    if details_full
        && try_pe_local_fast_match_scan(slice, last_matched_end, term_pos, true).is_some()
    {
        PeFastHitOutcome::Hit
    } else {
        PeFastHitOutcome::Unknown
    }
}

#[inline(never)]
fn try_pe_local_fast_match_scan(
    slice: &[u8],
    last_matched_end: usize,
    term_pos: usize,
    details_full: bool,
) -> Option<(usize, PeSsnEncoding, bool, bool, bool)> {
    let gap = term_pos.saturating_sub(last_matched_end);
    let local_start = if gap <= 16 {
        last_matched_end
    } else if details_full {
        term_pos.saturating_sub(55).max(last_matched_end)
    } else {
        return None;
    };
    let win = slice.get(local_start..term_pos)?;
    memchr::memchr2(0x4C, 0x49, win)?;
    let min_ssn_end = term_pos.saturating_add(2).saturating_sub(48);
    let mut latest_r10: Option<(usize, bool)> = None;
    let mut first_ssn: Option<(usize, PeSsnEncoding)> = None;
    let mut p = local_start;
    while p < term_pos {
        if let Some((ssn_pos, enc)) = first_ssn {
            if p.saturating_add(3) <= term_pos {
                if let Some(pat_a) = match_pe_r10_at(slice, p) {
                    return Some((ssn_pos, enc, pat_a, true, false));
                }
                p = p.saturating_add(1);
            } else {
                break;
            }
        } else {
            match slice.get(p).copied() {
                Some(0x4C | 0x49) if p.saturating_add(3) <= term_pos => {
                    if let Some(pat_a) = match_pe_r10_at(slice, p) {
                        latest_r10 = Some((p, pat_a));
                        p = p.saturating_add(3);
                        continue;
                    }
                }
                Some(0xB8 | 0x48 | 0x6A | 0x68) => {
                    if let Some((len, enc)) = match_pe_ssn_load(slice, p) {
                        let end = p.saturating_add(len);
                        if end <= term_pos && end >= min_ssn_end {
                            if let Some((r10_pos, pat_a)) = latest_r10 {
                                if r10_pos >= p.saturating_sub(48) {
                                    let is_adj = r10_pos.saturating_add(3) == p;
                                    return Some((r10_pos, enc, pat_a, !is_adj, end == term_pos));
                                }
                            }
                            first_ssn = Some((p, enc));
                            p = end;
                            continue;
                        }
                    }
                }
                _ => {}
            }
            p = p.saturating_add(1);
        }
    }
    None
}

#[inline(always)]
fn try_pe_local_fast_match(
    slice: &[u8],
    last_matched_end: usize,
    term_pos: usize,
    details_full: bool,
) -> Option<(usize, PeSsnEncoding, bool, bool, bool)> {
    let gap = term_pos.saturating_sub(last_matched_end);
    if gap < 6 {
        return None;
    }

    // 1. Contiguous and 1-byte-interleaved `[4C 8B D1 | 49 89 CA] [nop?] + <ssn> + [0F 05 | CD 2E]`
    //    fast path. Active even after secondary SIMD cursors have been initialized.
    if gap <= 9 || details_full {
        let tail_b = slice.get(term_pos.saturating_sub(1)).copied();
        let candidate_lens: &[usize] = match tail_b {
            Some(0x58) => &[3, 6],
            Some(0x00) => &[5, 7],
            _ => &[],
        };
        for &ssn_len in candidate_lens {
            if let Some(ssn_pos) = term_pos.checked_sub(ssn_len) {
                if ssn_pos >= last_matched_end.saturating_add(3) {
                    if let Some((matched_len, enc)) = match_pe_ssn_load(slice, ssn_pos) {
                        if matched_len == ssn_len {
                            if let Some(r10_pos) = ssn_pos.checked_sub(3) {
                                if r10_pos >= last_matched_end
                                    && (r10_pos.saturating_sub(last_matched_end) <= 2
                                        || details_full)
                                {
                                    if let Some(pat_a) = match_pe_r10_at(slice, r10_pos) {
                                        return Some((r10_pos, enc, pat_a, false, true));
                                    }
                                }
                            }
                            if let Some(r10_pos) = ssn_pos.checked_sub(4) {
                                if r10_pos >= last_matched_end
                                    && (r10_pos.saturating_sub(last_matched_end) <= 2
                                        || details_full)
                                {
                                    if let Some(pat_a) = match_pe_r10_at(slice, r10_pos) {
                                        return Some((r10_pos, enc, pat_a, true, true));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Small-gap local scan (`gap <= 16`, or trailing 55 bytes once `details` is capped)
    //    covering multi-NOP interleaved or reordered stubs without touching iterators/queues.
    if gap <= 16 || details_full {
        return try_pe_local_fast_match_scan(slice, last_matched_end, term_pos, details_full);
    }

    None
}

fn find_next_r10(slice: &[u8], from: usize) -> (Option<(usize, bool)>, usize) {
    let Some(sub) = slice.get(from..) else {
        return (None, slice.len());
    };
    for rel in memchr::memchr2_iter(0x4C, 0x49, sub) {
        let pos = from.saturating_add(rel);
        if let Some(pat_a) = match_pe_r10_at(slice, pos) {
            return (Some((pos, pat_a)), pos.saturating_add(3));
        }
    }
    (None, slice.len())
}

fn find_next_ssn3(slice: &[u8], from: usize) -> (Option<(usize, usize, PeSsnEncoding)>, usize) {
    let Some(sub) = slice.get(from..) else {
        return (None, slice.len());
    };
    for rel in memchr::memchr3_iter(0xB8, 0x6A, 0x68, sub) {
        let pos = from.saturating_add(rel);
        if let Some((len, enc)) = match_pe_ssn_load(slice, pos) {
            if let Some(end) = pos.checked_add(len) {
                return (Some((pos, end, enc)), pos.saturating_add(1));
            }
        }
    }
    (None, slice.len())
}

fn find_next_c7(slice: &[u8], from: usize) -> (Option<(usize, usize, PeSsnEncoding)>, usize) {
    let search_from = from.saturating_add(1);
    let Some(sub) = slice.get(search_from..) else {
        return (None, slice.len());
    };
    for rel in memchr::memchr_iter(0xC7, sub) {
        let c7_pos = search_from.saturating_add(rel);
        if let Some(ssn_pos) = c7_pos.checked_sub(1) {
            if slice.get(ssn_pos) == Some(&0x48) {
                if let Some((len, enc)) = match_pe_ssn_load(slice, ssn_pos) {
                    if let Some(end) = ssn_pos.checked_add(len) {
                        return (Some((ssn_pos, end, enc)), ssn_pos.saturating_add(1));
                    }
                }
            }
        }
    }
    (None, slice.len())
}

enum PeTermAction {
    Continue,
    ReturnCount,
    SkipUntil(usize),
    Jump(usize),
}

struct PeScanState {
    r10_scan_from: usize,
    r10_exhausted: bool,
    next_r10: Option<(usize, bool)>,
    r10_queue: VecDeque<(usize, bool)>,
    ssn3_scan_from: usize,
    ssn3_exhausted: bool,
    next_ssn3: Option<(usize, usize, PeSsnEncoding)>,
    c7_scan_from: usize,
    c7_exhausted: bool,
    next_c7: Option<(usize, usize, PeSsnEncoding)>,
    ssn_queue: VecDeque<(usize, usize, PeSsnEncoding)>,
}

impl PeScanState {
    fn new() -> Self {
        Self {
            r10_scan_from: 0,
            r10_exhausted: false,
            next_r10: None,
            r10_queue: VecDeque::new(),
            ssn3_scan_from: 0,
            ssn3_exhausted: false,
            next_ssn3: None,
            c7_scan_from: 0,
            c7_exhausted: false,
            next_c7: None,
            ssn_queue: VecDeque::new(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn process_pe_slow(
    slice: &[u8],
    section_name: &str,
    term_pos: usize,
    term_end: usize,
    is_int2e: bool,
    count: &mut u32,
    last_matched_end: &mut usize,
    details_full: &mut bool,
    state: &mut PeScanState,
    details: &mut Vec<String>,
) -> PeTermAction {
    const HALOS_TAIL_WINDOW_BYTES: usize = 48;
    const LOOKBEHIND_BYTES: usize = 48;
    const MAX_SSN_LOAD_LEN: usize = 7;
    const TERM_JUMP_THRESHOLD: usize = 16;

    let min_ssn_end = term_end.saturating_sub(HALOS_TAIL_WINDOW_BYTES);
    let scan_start = min_ssn_end
        .saturating_sub(MAX_SSN_LOAD_LEN)
        .max(*last_matched_end);
    let min_r10_pos = scan_start
        .saturating_sub(LOOKBEHIND_BYTES)
        .max(*last_matched_end);

    while state
        .r10_queue
        .front()
        .is_some_and(|&(p, _)| p < min_r10_pos)
    {
        state.r10_queue.pop_front();
    }
    if state.next_r10.is_some_and(|(p, _)| p < min_r10_pos) {
        state.next_r10 = None;
    }
    if state.r10_scan_from < min_r10_pos {
        state.r10_scan_from = min_r10_pos;
    }

    while state
        .ssn_queue
        .front()
        .is_some_and(|&(pos, end, _)| pos < scan_start || end < min_ssn_end)
    {
        state.ssn_queue.pop_front();
    }
    if state
        .next_ssn3
        .is_some_and(|(p, e, _)| p < scan_start || e < min_ssn_end)
    {
        state.next_ssn3 = None;
    }
    if state.ssn3_scan_from < scan_start {
        state.ssn3_scan_from = scan_start;
    }
    if state
        .next_c7
        .is_some_and(|(p, e, _)| p < scan_start || e < min_ssn_end)
    {
        state.next_c7 = None;
    }
    if state.c7_scan_from < scan_start {
        state.c7_scan_from = scan_start;
    }

    let r10_limit = term_pos.saturating_sub(2);

    // O(1) peek & skip/jump when r10_queue is empty (avoids touching SSN cursors).
    if state.r10_queue.is_empty() {
        if !state.r10_exhausted && state.next_r10.is_none() {
            let (found, next_from) = find_next_r10(slice, state.r10_scan_from);
            state.r10_scan_from = next_from;
            if found.is_some() {
                state.next_r10 = found;
            } else {
                state.r10_exhausted = true;
            }
        }
        let Some((r10_pos, _)) = state.next_r10 else {
            return PeTermAction::ReturnCount;
        };
        if r10_pos >= r10_limit {
            let jump_to = r10_pos.saturating_add(3);
            if jump_to > term_pos.saturating_add(TERM_JUMP_THRESHOLD) {
                return PeTermAction::Jump(jump_to);
            }
            return PeTermAction::SkipUntil(jump_to);
        }
    }

    // O(1) peek & skip/jump when ssn_queue is empty (avoids draining dense r10_queue).
    if state.ssn_queue.is_empty() {
        if !state.ssn3_exhausted && state.next_ssn3.is_none() {
            let (found, next_from) = find_next_ssn3(slice, state.ssn3_scan_from);
            state.ssn3_scan_from = next_from;
            if found.is_some() {
                state.next_ssn3 = found;
            } else {
                state.ssn3_exhausted = true;
            }
        }
        if !state.c7_exhausted && state.next_c7.is_none() {
            let (found, next_from) = find_next_c7(slice, state.c7_scan_from);
            state.c7_scan_from = next_from;
            if found.is_some() {
                state.next_c7 = found;
            } else {
                state.c7_exhausted = true;
            }
        }
        let earliest_end = match (state.next_ssn3, state.next_c7) {
            (Some((_, e3, _)), Some((_, e7, _))) => Some(e3.min(e7)),
            (Some((_, e3, _)), None) => Some(e3),
            (None, Some((_, e7, _))) => Some(e7),
            (None, None) => None,
        };
        let Some(min_end) = earliest_end else {
            return PeTermAction::ReturnCount;
        };
        if min_end > term_pos {
            if min_end > term_pos.saturating_add(TERM_JUMP_THRESHOLD) {
                return PeTermAction::Jump(min_end);
            }
            return PeTermAction::SkipUntil(min_end);
        }
    }

    // Drain eligible r10 candidates up to `r10_limit`
    while let Some((pos, is_pat_a)) = state.next_r10 {
        if pos >= r10_limit {
            break;
        }
        if pos >= min_r10_pos {
            state.r10_queue.push_back((pos, is_pat_a));
        }
        state.next_r10 = None;
        if !state.r10_exhausted {
            let (found, next_from) = find_next_r10(slice, state.r10_scan_from);
            state.r10_scan_from = next_from;
            if found.is_some() {
                state.next_r10 = found;
            } else {
                state.r10_exhausted = true;
            }
        }
    }

    if state.r10_queue.is_empty() {
        let Some((r10_pos, _)) = state.next_r10 else {
            return PeTermAction::ReturnCount;
        };
        let next_r10_end = r10_pos.saturating_add(3);
        if next_r10_end > term_pos.saturating_add(TERM_JUMP_THRESHOLD) {
            return PeTermAction::Jump(next_r10_end);
        }
        return PeTermAction::SkipUntil(next_r10_end);
    }

    // Drain eligible SSN candidates whose entire instruction ends at or before `term_pos`
    loop {
        let take_ssn3 = match (state.next_ssn3, state.next_c7) {
            (Some((p3, _, _)), Some((p7, _, _))) => p3 <= p7,
            (Some(_), None) => true,
            _ => false,
        };
        if take_ssn3 {
            let Some((pos, end, enc)) = state.next_ssn3 else {
                break;
            };
            if end > term_pos {
                break;
            }
            if pos >= scan_start && end >= min_ssn_end {
                state.ssn_queue.push_back((pos, end, enc));
            }
            state.next_ssn3 = None;
            if !state.ssn3_exhausted {
                let (found, next_from) = find_next_ssn3(slice, state.ssn3_scan_from);
                state.ssn3_scan_from = next_from;
                if found.is_some() {
                    state.next_ssn3 = found;
                } else {
                    state.ssn3_exhausted = true;
                }
            }
        } else if let Some((pos, end, enc)) = state.next_c7 {
            if end > term_pos {
                break;
            }
            if pos >= scan_start && end >= min_ssn_end {
                state.ssn_queue.push_back((pos, end, enc));
            }
            state.next_c7 = None;
            if !state.c7_exhausted {
                let (found, next_from) = find_next_c7(slice, state.c7_scan_from);
                state.c7_scan_from = next_from;
                if found.is_some() {
                    state.next_c7 = found;
                } else {
                    state.c7_exhausted = true;
                }
            }
        } else {
            break;
        }
    }

    // Only scan/loop queues when BOTH r10_queue and ssn_queue are non-empty.
    if state.r10_queue.is_empty() || state.ssn_queue.is_empty() {
        if state.ssn_queue.is_empty()
            && state.ssn3_exhausted
            && state.c7_exhausted
            && state.next_ssn3.is_none()
            && state.next_c7.is_none()
        {
            return PeTermAction::ReturnCount;
        }
        let next_ssn_end = match (state.next_ssn3, state.next_c7) {
            (Some((_, e3, _)), Some((_, e7, _))) => Some(e3.min(e7)),
            (Some((_, e3, _)), None) => Some(e3),
            (None, Some((_, e7, _))) => Some(e7),
            (None, None) => None,
        };
        if let Some(min_end) = next_ssn_end {
            if min_end > term_pos.saturating_add(TERM_JUMP_THRESHOLD) {
                return PeTermAction::Jump(min_end);
            }
            if min_end > term_pos {
                return PeTermAction::SkipUntil(min_end);
            }
        }
        return PeTermAction::Continue;
    }

    let mut found_match = None;
    for &(ssn_pos, ssn_end, encoding) in &state.ssn_queue {
        if ssn_pos < scan_start || ssn_end < min_ssn_end || ssn_end > term_pos {
            continue;
        }

        let lb_start = ssn_pos
            .saturating_sub(LOOKBEHIND_BYTES)
            .max(*last_matched_end);

        let matched = if state.r10_queue.len() == 1 {
            if let Some(&(r10_pos, is_pat_a)) = state.r10_queue.front() {
                if r10_pos >= lb_start && r10_pos.saturating_add(3) <= ssn_pos {
                    let is_adjacent = r10_pos.saturating_add(3) == ssn_pos;
                    Some((r10_pos, is_pat_a, !is_adjacent, ssn_end == term_pos))
                } else if r10_pos >= ssn_end && r10_pos.saturating_add(3) <= term_pos {
                    Some((ssn_pos, is_pat_a, true, false))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            let lb_idx = state
                .r10_queue
                .partition_point(|&(p, _)| p.saturating_add(3) <= ssn_pos);
            let lookbehind_match = lb_idx
                .checked_sub(1)
                .and_then(|i| state.r10_queue.get(i).copied())
                .filter(|&(p, _)| p >= lb_start);

            if let Some((stub_start, is_pat_a)) = lookbehind_match {
                let is_adjacent = stub_start.saturating_add(3) == ssn_pos;
                Some((stub_start, is_pat_a, !is_adjacent, ssn_end == term_pos))
            } else {
                let fw_idx = state.r10_queue.partition_point(|&(p, _)| p < ssn_end);
                state
                    .r10_queue
                    .get(fw_idx)
                    .copied()
                    .filter(|&(p, _)| p.saturating_add(3) <= term_pos)
                    .map(|(_, is_pat_a)| (ssn_pos, is_pat_a, true, false))
            }
        };

        if let Some((stub_start, is_pat_a, is_reordered_or_interleaved, is_tail_zero)) = matched {
            found_match = Some((
                stub_start,
                encoding,
                is_pat_a,
                is_reordered_or_interleaved,
                is_tail_zero,
            ));
            break;
        }
    }

    if let Some((stub_start, encoding, is_pat_a, is_reordered_or_interleaved, is_tail_zero)) =
        found_match
    {
        *count = count.saturating_add(1);
        *last_matched_end = term_end;
        state.r10_queue.clear();
        state.ssn_queue.clear();
        if !*details_full {
            *details_full = record_pe_stub_detail(
                encoding,
                is_pat_a,
                is_int2e,
                is_tail_zero,
                is_reordered_or_interleaved,
                section_name,
                stub_start,
                details,
            );
        }
        return PeTermAction::Continue;
    }

    let next_r10_end = state.next_r10.map(|(p, _)| p.saturating_add(3));
    let next_ssn_end = match (state.next_ssn3, state.next_c7) {
        (Some((_, e3, _)), Some((_, e7, _))) => Some(e3.min(e7)),
        (Some((_, e3, _)), None) => Some(e3),
        (None, Some((_, e7, _))) => Some(e7),
        (None, None) => None,
    };
    let next_event = match (next_r10_end, next_ssn_end) {
        (Some(r), Some(s)) if r < s => {
            let min_surviving_ssn_end = r.saturating_add(2).saturating_sub(HALOS_TAIL_WINDOW_BYTES);
            if state
                .ssn_queue
                .iter()
                .all(|&(_, e, _)| e < min_surviving_ssn_end)
            {
                Some(s)
            } else {
                Some(r)
            }
        }
        (Some(r), None) => {
            let min_surviving_ssn_end = r.saturating_add(2).saturating_sub(HALOS_TAIL_WINDOW_BYTES);
            if state
                .ssn_queue
                .iter()
                .all(|&(_, e, _)| e < min_surviving_ssn_end)
            {
                None
            } else {
                Some(r)
            }
        }
        (Some(r), Some(s)) if s < r => {
            let earliest_next_ssn_pos = match (state.next_ssn3, state.next_c7) {
                (Some((p3, _, _)), Some((p7, _, _))) => Some(p3.min(p7)),
                (Some((p3, _, _)), None) => Some(p3),
                (None, Some((p7, _, _))) => Some(p7),
                (None, None) => None,
            };
            let min_r10_needed = earliest_next_ssn_pos
                .map(|p| p.saturating_sub(LOOKBEHIND_BYTES))
                .unwrap_or(usize::MAX);
            if state
                .r10_queue
                .back()
                .is_none_or(|&(p, _)| p < min_r10_needed)
            {
                Some(r)
            } else {
                Some(s)
            }
        }
        (Some(r), Some(s)) => Some(r.min(s)),
        (None, Some(s)) => {
            let earliest_next_ssn_pos = match (state.next_ssn3, state.next_c7) {
                (Some((p3, _, _)), Some((p7, _, _))) => Some(p3.min(p7)),
                (Some((p3, _, _)), None) => Some(p3),
                (None, Some((p7, _, _))) => Some(p7),
                (None, None) => None,
            };
            let min_r10_needed = earliest_next_ssn_pos
                .map(|p| p.saturating_sub(LOOKBEHIND_BYTES))
                .unwrap_or(usize::MAX);
            if state
                .r10_queue
                .back()
                .is_none_or(|&(p, _)| p < min_r10_needed)
            {
                None
            } else {
                Some(s)
            }
        }
        (None, None) => None,
    };
    match next_event {
        None => PeTermAction::ReturnCount,
        Some(target) if target > term_pos.saturating_add(TERM_JUMP_THRESHOLD) => {
            PeTermAction::Jump(target)
        }
        Some(target) if target > term_pos => PeTermAction::SkipUntil(target),
        Some(_) => PeTermAction::Continue,
    }
}

struct PeMissTracker {
    prev_miss_term_pos: usize,
    has_prev_miss: bool,
    dense_miss_streak: u32,
    sparse_slow_streak: u32,
}

impl PeMissTracker {
    const fn new() -> Self {
        Self {
            prev_miss_term_pos: 0,
            has_prev_miss: false,
            dense_miss_streak: 0,
            sparse_slow_streak: 0,
        }
    }

    #[inline(always)]
    fn reset_on_hit(&mut self) {
        self.dense_miss_streak = 0;
        self.sparse_slow_streak = 0;
    }
}

#[inline]
fn find_earliest_pe_ssn_in_range(
    slice: &[u8],
    start: usize,
    end_inclusive: usize,
    min_ssn_end: usize,
    max_ssn_end: usize,
) -> Option<(usize, usize, PeSsnEncoding)> {
    if start > end_inclusive {
        return None;
    }
    let search_end = end_inclusive.saturating_add(1).min(slice.len());
    let sub3 = slice.get(start..search_end)?;
    let mut best: Option<(usize, usize, PeSsnEncoding)> = None;
    for rel in memchr::memchr3_iter(0xB8, 0x6A, 0x68, sub3) {
        let pos = start.saturating_add(rel);
        if let Some((len, enc)) = match_pe_ssn_load(slice, pos) {
            if let Some(end) = pos.checked_add(len) {
                if end >= min_ssn_end && end <= max_ssn_end {
                    best = Some((pos, end, enc));
                    break;
                }
            }
        }
    }
    let c7_start = start.saturating_add(1);
    let c7_end = best
        .map_or(end_inclusive.saturating_add(2), |(p, _, _)| {
            p.saturating_add(1)
        })
        .min(slice.len());
    if c7_start < c7_end {
        if let Some(sub_c7) = slice.get(c7_start..c7_end) {
            for rel in memchr::memchr_iter(0xC7, sub_c7) {
                let c7_pos = c7_start.saturating_add(rel);
                if let Some(pos) = c7_pos.checked_sub(1) {
                    if slice.get(pos) == Some(&0x48) {
                        if let Some((len, enc)) = match_pe_ssn_load(slice, pos) {
                            if let Some(end) = pos.checked_add(len) {
                                if end >= min_ssn_end
                                    && end <= max_ssn_end
                                    && best.is_none_or(|(bp, _, _)| pos < bp)
                                {
                                    best = Some((pos, end, enc));
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    best
}

fn find_next_pe_ssn3_in_range(
    slice: &[u8],
    from: &mut usize,
    max_start: usize,
    min_ssn_end: usize,
    max_ssn_end: usize,
) -> Option<(usize, usize, PeSsnEncoding)> {
    if *from > max_start {
        return None;
    }
    let search_end = max_start.saturating_add(1).min(slice.len());
    let sub = slice.get(*from..search_end)?;
    for rel in memchr::memchr3_iter(0xB8, 0x6A, 0x68, sub) {
        let pos = from.saturating_add(rel);
        if let Some((len, enc)) = match_pe_ssn_load(slice, pos) {
            if let Some(end) = pos.checked_add(len) {
                if end >= min_ssn_end && end <= max_ssn_end {
                    *from = pos.saturating_add(1);
                    return Some((pos, end, enc));
                }
            }
        }
    }
    *from = max_start.saturating_add(1);
    None
}

fn find_next_pe_c7_in_range(
    slice: &[u8],
    from: &mut usize,
    max_start: usize,
    min_ssn_end: usize,
    max_ssn_end: usize,
) -> Option<(usize, usize, PeSsnEncoding)> {
    if *from > max_start {
        return None;
    }
    let c7_start = from.saturating_add(1);
    let c7_end = max_start.saturating_add(2).min(slice.len());
    let sub = slice.get(c7_start..c7_end)?;
    for rel in memchr::memchr_iter(0xC7, sub) {
        let c7_pos = c7_start.saturating_add(rel);
        if let Some(pos) = c7_pos.checked_sub(1) {
            if slice.get(pos) == Some(&0x48) {
                if let Some((len, enc)) = match_pe_ssn_load(slice, pos) {
                    if let Some(end) = pos.checked_add(len) {
                        if end >= min_ssn_end && end <= max_ssn_end {
                            *from = pos.saturating_add(1);
                            return Some((pos, end, enc));
                        }
                    }
                }
            }
        }
    }
    *from = max_start.saturating_add(1);
    None
}

#[inline]
#[allow(clippy::type_complexity)]
fn try_pe_window_match(
    slice: &[u8],
    last_matched_end: usize,
    term_pos: usize,
) -> Result<Option<(usize, PeSsnEncoding, bool, bool, bool)>, ()> {
    const HALOS_TAIL_WINDOW_BYTES: usize = 48;
    const LOOKBEHIND_BYTES: usize = 48;
    const MAX_SSN_LOAD_LEN: usize = 7;

    let min_ssn_end = term_pos
        .saturating_add(2)
        .saturating_sub(HALOS_TAIL_WINDOW_BYTES);
    let scan_start = min_ssn_end
        .saturating_sub(MAX_SSN_LOAD_LEN)
        .max(last_matched_end);
    let min_r10_pos = scan_start
        .saturating_sub(LOOKBEHIND_BYTES)
        .max(last_matched_end);
    let r10_limit = term_pos.saturating_sub(2);
    if min_r10_pos >= r10_limit {
        return Ok(None);
    }
    let Some(r10_win) = slice.get(min_r10_pos..r10_limit) else {
        return Ok(None);
    };
    let mut r10s = [(0usize, false); 8];
    let mut r10_len = 0usize;
    let mut min_next_r10 = 0usize;
    for rel in memchr::memchr2_iter(0x4C, 0x49, r10_win) {
        let pos = min_r10_pos.saturating_add(rel);
        if pos < min_next_r10 {
            continue;
        }
        if let Some(pat_a) = match_pe_r10_at(slice, pos) {
            if let Some(slot) = r10s.get_mut(r10_len) {
                *slot = (pos, pat_a);
                r10_len += 1;
                min_next_r10 = pos.saturating_add(3);
            } else {
                return Err(());
            }
        }
    }
    if r10_len == 0 {
        return Ok(None);
    }
    if r10_len == 1 {
        let Some(&(r10_pos, is_pat_a)) = r10s.first() else {
            return Ok(None);
        };
        if r10_pos >= min_ssn_end && scan_start <= r10_pos.saturating_sub(3) {
            if let Some((ssn_pos, _, enc)) = find_earliest_pe_ssn_in_range(
                slice,
                scan_start,
                r10_pos.saturating_sub(3),
                min_ssn_end,
                r10_pos,
            ) {
                return Ok(Some((ssn_pos, enc, is_pat_a, true, false)));
            }
        }
        let lb_ssn_start = r10_pos.saturating_add(3).max(scan_start);
        let lb_ssn_end = r10_pos
            .saturating_add(LOOKBEHIND_BYTES)
            .min(term_pos.saturating_sub(3));
        if lb_ssn_start <= lb_ssn_end {
            if let Some((ssn_pos, ssn_end, enc)) = find_earliest_pe_ssn_in_range(
                slice,
                lb_ssn_start,
                lb_ssn_end,
                min_ssn_end,
                term_pos,
            ) {
                let is_adj = r10_pos.saturating_add(3) == ssn_pos;
                return Ok(Some((r10_pos, enc, is_pat_a, !is_adj, ssn_end == term_pos)));
            }
        }
        return Ok(None);
    }

    let max_ssn_start = term_pos.saturating_sub(3);
    if scan_start > max_ssn_start {
        return Ok(None);
    }
    let Some(r10_slice) = r10s.get(..r10_len) else {
        return Err(());
    };
    let mut ssn3_from = scan_start;
    let mut c7_from = scan_start;
    let mut next_ssn3 =
        find_next_pe_ssn3_in_range(slice, &mut ssn3_from, max_ssn_start, min_ssn_end, term_pos);
    let mut next_c7 =
        find_next_pe_c7_in_range(slice, &mut c7_from, max_ssn_start, min_ssn_end, term_pos);

    loop {
        let take_ssn3 = match (next_ssn3, next_c7) {
            (Some((p3, _, _)), Some((p7, _, _))) => p3 <= p7,
            (Some(_), None) => true,
            _ => false,
        };
        let candidate = if take_ssn3 {
            let c = next_ssn3;
            next_ssn3 = find_next_pe_ssn3_in_range(
                slice,
                &mut ssn3_from,
                max_ssn_start,
                min_ssn_end,
                term_pos,
            );
            c
        } else if next_c7.is_some() {
            let c = next_c7;
            next_c7 =
                find_next_pe_c7_in_range(slice, &mut c7_from, max_ssn_start, min_ssn_end, term_pos);
            c
        } else {
            break;
        };
        if let Some((ssn_pos, ssn_end, enc)) = candidate {
            let lb_start = ssn_pos
                .saturating_sub(LOOKBEHIND_BYTES)
                .max(last_matched_end);
            let lb_idx = r10_slice.partition_point(|&(p, _)| p.saturating_add(3) <= ssn_pos);
            let lookbehind_match = lb_idx
                .checked_sub(1)
                .and_then(|i| r10_slice.get(i).copied())
                .filter(|&(p, _)| p >= lb_start);

            if let Some((stub_start, is_pat_a)) = lookbehind_match {
                let is_adj = stub_start.saturating_add(3) == ssn_pos;
                return Ok(Some((
                    stub_start,
                    enc,
                    is_pat_a,
                    !is_adj,
                    ssn_end == term_pos,
                )));
            }
            let fw_idx = r10_slice.partition_point(|&(p, _)| p < ssn_end);
            if let Some(&(_, is_pat_a)) = r10_slice.get(fw_idx) {
                return Ok(Some((ssn_pos, enc, is_pat_a, true, false)));
            }
        }
    }
    Ok(None)
}

#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn handle_pe_slow_or_detail(
    slice: &[u8],
    section_name: &str,
    term_pos: usize,
    term_end: usize,
    is_int2e: bool,
    count: &mut u32,
    last_matched_end: &mut usize,
    details_full: &mut bool,
    queues_dirty: &mut bool,
    state_opt: &mut Option<PeScanState>,
    miss_tracker: &mut PeMissTracker,
    details: &mut Vec<String>,
) -> PeTermAction {
    const DENSE_TERMINATOR_GAP: usize = 24;
    const DENSE_STREAK_ACTIVATE: u32 = 2;
    const SPARSE_STREAK_DEACTIVATE: u32 = 8;

    if !*details_full {
        if let Some((stub_start, encoding, is_pat_a, is_reordered_or_interleaved, is_tail_zero)) =
            try_pe_local_fast_match(slice, *last_matched_end, term_pos, false)
        {
            *count = count.saturating_add(1);
            *last_matched_end = term_end;
            miss_tracker.reset_on_hit();
            if *queues_dirty {
                if let Some(st) = state_opt.as_mut() {
                    st.r10_queue.clear();
                    st.ssn_queue.clear();
                }
                *queues_dirty = false;
            }
            *details_full = record_pe_stub_detail(
                encoding,
                is_pat_a,
                is_int2e,
                is_tail_zero,
                is_reordered_or_interleaved,
                section_name,
                stub_start,
                details,
            );
            return PeTermAction::Continue;
        }
    }

    if state_opt.is_none() {
        match try_pe_window_match(slice, *last_matched_end, term_pos) {
            Ok(Some((
                stub_start,
                encoding,
                is_pat_a,
                is_reordered_or_interleaved,
                is_tail_zero,
            ))) => {
                *count = count.saturating_add(1);
                *last_matched_end = term_end;
                miss_tracker.reset_on_hit();
                if !*details_full {
                    *details_full = record_pe_stub_detail(
                        encoding,
                        is_pat_a,
                        is_int2e,
                        is_tail_zero,
                        is_reordered_or_interleaved,
                        section_name,
                        stub_start,
                        details,
                    );
                }
                return PeTermAction::Continue;
            }
            Ok(None) => {
                if miss_tracker.has_prev_miss
                    && term_pos.saturating_sub(miss_tracker.prev_miss_term_pos)
                        <= DENSE_TERMINATOR_GAP
                {
                    miss_tracker.dense_miss_streak =
                        miss_tracker.dense_miss_streak.saturating_add(1);
                } else {
                    miss_tracker.dense_miss_streak = 0;
                }
                miss_tracker.prev_miss_term_pos = term_pos;
                miss_tracker.has_prev_miss = true;
                if miss_tracker.dense_miss_streak < DENSE_STREAK_ACTIVATE {
                    return PeTermAction::Continue;
                }
            }
            Err(()) => {}
        }
    }

    let prev_matched_end = *last_matched_end;
    let st = state_opt.get_or_insert_with(PeScanState::new);
    let act = process_pe_slow(
        slice,
        section_name,
        term_pos,
        term_end,
        is_int2e,
        count,
        last_matched_end,
        details_full,
        st,
        details,
    );
    *queues_dirty = !st.r10_queue.is_empty() || !st.ssn_queue.is_empty();
    if *last_matched_end != prev_matched_end
        || matches!(act, PeTermAction::Jump(_) | PeTermAction::ReturnCount)
    {
        miss_tracker.reset_on_hit();
    } else {
        if miss_tracker.has_prev_miss
            && term_pos.saturating_sub(miss_tracker.prev_miss_term_pos) > DENSE_TERMINATOR_GAP
        {
            miss_tracker.sparse_slow_streak = miss_tracker.sparse_slow_streak.saturating_add(1);
            if miss_tracker.sparse_slow_streak >= SPARSE_STREAK_DEACTIVATE {
                *state_opt = None;
                *queues_dirty = false;
                miss_tracker.reset_on_hit();
            }
        } else {
            miss_tracker.sparse_slow_streak = 0;
        }
        miss_tracker.prev_miss_term_pos = term_pos;
        miss_tracker.has_prev_miss = true;
    }
    act
}

fn scan_pe_direct_syscalls(slice: &[u8], section_name: &str, details: &mut Vec<String>) -> u32 {
    let mut count = 0u32;
    let mut last_matched_end = 0usize;
    let mut skip_slow_until = 0usize;
    let mut details_full = details.len() >= MAX_STUB_DETAILS;
    let mut queues_dirty = false;
    let mut state_opt: Option<PeScanState> = None;
    let mut miss_tracker = PeMissTracker::new();

    let mut cursor = 0usize;
    'outer: while cursor < slice.len() {
        let Some(sub) = slice.get(cursor..) else {
            break;
        };
        let chunks = sub.chunks_exact(8);
        let rem_len = chunks.remainder().len();
        let mut block_off = cursor;
        for chunk in chunks {
            if let [b0, b1, b2, b3, b4, b5, b6, b7] = *chunk {
                let v = u64::from_le_bytes([b0, b1, b2, b3, b4, b5, b6, b7]);
                let x1 = v ^ 0x0F0F_0F0F_0F0F_0F0Fu64;
                let h1 = x1.wrapping_sub(0x0101_0101_0101_0101u64) & !x1 & 0x8080_8080_8080_8080u64;
                let x2 = v ^ 0xCDCD_CDCD_CDCD_CDCDu64;
                let h2 = x2.wrapping_sub(0x0101_0101_0101_0101u64) & !x2 & 0x8080_8080_8080_8080u64;
                let mut m = h1 | h2;
                while m != 0 {
                    let term_pos = block_off.saturating_add((m.trailing_zeros() as usize) >> 3);
                    m &= m - 1;
                    if term_pos < last_matched_end.saturating_add(6) || term_pos < skip_slow_until {
                        continue;
                    }
                    let Some(term_end) = term_pos.checked_add(2) else {
                        continue;
                    };
                    let is_int2e = match slice.get(term_pos..term_end) {
                        Some([0x0F, 0x05]) => false,
                        Some([0xCD, 0x2E]) => true,
                        _ => continue,
                    };
                    match try_pe_local_fast_hit_count_only(
                        slice,
                        last_matched_end,
                        term_pos,
                        details_full,
                    ) {
                        PeFastHitOutcome::Hit => {
                            count = count.saturating_add(1);
                            last_matched_end = term_end;
                            miss_tracker.reset_on_hit();
                            if queues_dirty {
                                if let Some(st) = state_opt.as_mut() {
                                    st.r10_queue.clear();
                                    st.ssn_queue.clear();
                                }
                                queues_dirty = false;
                            }
                            continue;
                        }
                        PeFastHitOutcome::DefinitiveMiss => continue,
                        PeFastHitOutcome::Unknown => {}
                    }
                    match handle_pe_slow_or_detail(
                        slice,
                        section_name,
                        term_pos,
                        term_end,
                        is_int2e,
                        &mut count,
                        &mut last_matched_end,
                        &mut details_full,
                        &mut queues_dirty,
                        &mut state_opt,
                        &mut miss_tracker,
                        details,
                    ) {
                        PeTermAction::Continue => {}
                        PeTermAction::ReturnCount => return count,
                        PeTermAction::SkipUntil(until) => {
                            skip_slow_until = skip_slow_until.max(until);
                        }
                        PeTermAction::Jump(jump_to) => {
                            if jump_to >= slice.len() {
                                return count;
                            }
                            cursor = jump_to;
                            continue 'outer;
                        }
                    }
                }
            }
            block_off = block_off.saturating_add(8);
        }
        let tail_end = block_off.saturating_add(rem_len);
        let mut term_pos = block_off;
        while term_pos < tail_end {
            if term_pos >= last_matched_end.saturating_add(6) && term_pos >= skip_slow_until {
                if let Some(term_end) = term_pos.checked_add(2) {
                    let is_int2e_opt = match slice.get(term_pos..term_end) {
                        Some([0x0F, 0x05]) => Some(false),
                        Some([0xCD, 0x2E]) => Some(true),
                        _ => None,
                    };
                    if let Some(is_int2e) = is_int2e_opt {
                        match try_pe_local_fast_hit_count_only(
                            slice,
                            last_matched_end,
                            term_pos,
                            details_full,
                        ) {
                            PeFastHitOutcome::Hit => {
                                count = count.saturating_add(1);
                                last_matched_end = term_end;
                                miss_tracker.reset_on_hit();
                                if queues_dirty {
                                    if let Some(st) = state_opt.as_mut() {
                                        st.r10_queue.clear();
                                        st.ssn_queue.clear();
                                    }
                                    queues_dirty = false;
                                }
                                term_pos = term_pos.saturating_add(1);
                                continue;
                            }
                            PeFastHitOutcome::DefinitiveMiss => {
                                term_pos = term_pos.saturating_add(1);
                                continue;
                            }
                            PeFastHitOutcome::Unknown => {}
                        }
                        match handle_pe_slow_or_detail(
                            slice,
                            section_name,
                            term_pos,
                            term_end,
                            is_int2e,
                            &mut count,
                            &mut last_matched_end,
                            &mut details_full,
                            &mut queues_dirty,
                            &mut state_opt,
                            &mut miss_tracker,
                            details,
                        ) {
                            PeTermAction::Continue => {}
                            PeTermAction::ReturnCount => return count,
                            PeTermAction::SkipUntil(until) => {
                                skip_slow_until = skip_slow_until.max(until);
                            }
                            PeTermAction::Jump(jump_to) => {
                                if jump_to >= slice.len() {
                                    return count;
                                }
                                cursor = jump_to;
                                continue 'outer;
                            }
                        }
                    }
                }
            }
            term_pos = term_pos.saturating_add(1);
        }
        break;
    }

    count
}

fn inspect_pe(source: &mut BinarySource<'_>, path_label: &str) -> BinaryIntegrityVerdict {
    let total_len = source.total_len();
    let mut dos_buf = [0u8; 4096];
    let dos_len = {
        let hs = source.header_slice();
        let n = hs.len().min(4096);
        if let (Some(dst), Some(src)) = (dos_buf.get_mut(..n), hs.get(..n)) {
            dst.copy_from_slice(src);
        }
        n
    };
    let dos_slice = dos_buf.get(..dos_len).unwrap_or(&[]);
    let dos_c = ByteCursor::new(dos_slice);
    let mut verdict = BinaryIntegrityVerdict::clean(BinaryFormat::Unknown, path_label);

    let Some(lfanew_u32) = dos_c.u32_le(0x3C) else {
        verdict
            .header_anomalies
            .push("pe_missing_e_lfanew".to_string());
        return verdict;
    };
    let lfanew = lfanew_u32 as usize;
    if lfanew < 0x40
        || lfanew > MAX_PE_LFANEW_BYTES
        || (lfanew as u64)
            .checked_add(24)
            .is_none_or(|end| end > total_len)
    {
        verdict
            .header_anomalies
            .push("pe_invalid_e_lfanew".to_string());
        return verdict;
    }

    // Check first 4 KiB of DOS stub for UPX! magic
    if contains_bytes_needle(dos_slice, b"UPX!") {
        verdict.has_packer_marker = true;
        push_unique(&mut verdict.packer_markers, "UPX!");
    }

    // Read NT signature (4 B) + COFF header (20 B) via read_window so e_lfanew >= 65_536 works
    let nt_coff_win = source.read_window(lfanew as u64, 24).into_owned();
    let nt_c = ByteCursor::new(&nt_coff_win);
    if nt_c.slice(0, 4) != Some(b"PE\0\0") {
        verdict
            .header_anomalies
            .push("pe_missing_nt_signature".to_string());
        return verdict;
    }

    let (Some(raw_num_sections), Some(size_opt_hdr)) = (nt_c.u16_le(6), nt_c.u16_le(20)) else {
        verdict
            .header_anomalies
            .push("pe_truncated_coff_header".to_string());
        return verdict;
    };

    if (raw_num_sections as usize) > MAX_PE_SECTIONS {
        verdict
            .header_anomalies
            .push(format!("pe_excessive_sections({})", raw_num_sections));
    }
    let num_sections = (raw_num_sections as usize).min(MAX_PE_SECTIONS);

    let Some(opt_file_off) = (lfanew as u64).checked_add(24) else {
        verdict
            .header_anomalies
            .push("pe_opt_offset_overflow".to_string());
        return verdict;
    };
    let sec_table_rel = size_opt_hdr as usize;
    let total_opt_and_secs = sec_table_rel.saturating_add(num_sections.saturating_mul(40));
    let opt_sec_win = source
        .read_window(opt_file_off, total_opt_and_secs)
        .into_owned();
    let oc = ByteCursor::new(&opt_sec_win);

    let Some(opt_magic) = (if sec_table_rel >= 2 {
        oc.u16_le(0)
    } else {
        None
    }) else {
        verdict
            .header_anomalies
            .push("pe_truncated_optional_header".to_string());
        return verdict;
    };

    let (format, num_rva_off, sec_dir_off) = match opt_magic {
        0x010B => (BinaryFormat::Pe32, 92usize, 128usize),
        0x020B => (BinaryFormat::Pe64, 108usize, 144usize),
        other => {
            verdict
                .header_anomalies
                .push(format!("pe_unknown_optional_magic(0x{:04x})", other));
            return verdict;
        }
    };
    verdict.format = format;

    let entry_rva = if sec_table_rel >= 20 {
        oc.u32_le(16).unwrap_or(0)
    } else {
        0
    };

    // Check IMAGE_DIRECTORY_ENTRY_SECURITY (index 4)
    if sec_table_rel >= sec_dir_off.saturating_add(8) {
        let num_rva = oc.u32_le(num_rva_off).unwrap_or(0);
        if num_rva > 4 {
            if let (Some(cert_off), Some(cert_sz)) =
                (oc.u32_le(sec_dir_off), oc.u32_le(sec_dir_off + 4))
            {
                if cert_off > 0 && cert_sz >= 8 {
                    let end_ok = (cert_off as u64)
                        .checked_add(cert_sz as u64)
                        .is_some_and(|e| e <= total_len);
                    if end_ok {
                        let cert_hdr = source.read_window(cert_off as u64, 8);
                        let cc = ByteCursor::new(&cert_hdr);
                        if let (Some(dw_len), Some(w_cert_type)) = (cc.u32_le(0), cc.u16_le(6)) {
                            // WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
                            if dw_len >= 8 && dw_len <= cert_sz && w_cert_type == 0x0002 {
                                verdict.is_authenticode_signed = true;
                                verdict.is_code_signed = true;
                            }
                        }
                    } else {
                        verdict
                            .header_anomalies
                            .push("pe_truncated_security_directory".to_string());
                    }
                }
            }
        }
    }

    struct PeScanTarget {
        name: String,
        raw_size: u64,
        raw_ptr: u64,
        is_ep: bool,
    }

    let mut scannable: Vec<PeScanTarget> = Vec::with_capacity(num_sections.min(16));
    let mut max_entropy = 0.0f64;

    for idx in 0..num_sections {
        let Some(sh_off) = idx
            .checked_mul(40)
            .and_then(|d| sec_table_rel.checked_add(d))
        else {
            break;
        };
        if oc.slice(sh_off, 40).is_none() {
            verdict
                .header_anomalies
                .push("pe_truncated_section_table".to_string());
            break;
        }
        let sec_name = oc
            .fixed_cstr(sh_off, 8)
            .unwrap_or_else(|| format!("sec_{}", idx));
        let virt_size = oc.u32_le(sh_off + 8).unwrap_or(0);
        let virt_addr = oc.u32_le(sh_off + 12).unwrap_or(0);
        let raw_size = oc.u32_le(sh_off + 16).unwrap_or(0);
        let raw_ptr = oc.u32_le(sh_off + 20).unwrap_or(0);
        let chars = oc.u32_le(sh_off + 36).unwrap_or(0);

        if is_packer_section_name(&sec_name) {
            verdict.has_packer_marker = true;
            push_unique(&mut verdict.packer_markers, sec_name.clone());
        }

        let is_write = (chars & 0x8000_0000) != 0;
        let is_exec = (chars & 0x2000_0000) != 0;
        let is_code = (chars & 0x0000_0020) != 0;

        if is_write && is_exec {
            verdict.has_wx_violation = true;
            push_unique(&mut verdict.wx_sections, sec_name.clone());
        }

        let ep_in_section = entry_rva != 0 && {
            let span = virt_size.max(raw_size);
            entry_rva >= virt_addr && entry_rva < virt_addr.saturating_add(span)
        };
        if ep_in_section && is_write {
            verdict.has_raw_size_anomaly = true;
            push_unique(
                &mut verdict.raw_size_anomalies,
                format!("ep_in_writable_section({})", sec_name),
            );
        }

        if (is_exec || is_code) && raw_size == 0 && virt_size > 4096 {
            verdict.has_raw_size_anomaly = true;
            push_unique(
                &mut verdict.raw_size_anomalies,
                format!("hollow_exec_section({})", sec_name),
            );
        }
        if (is_exec || is_code)
            && raw_size > 0
            && (virt_size as u64) > (raw_size as u64).saturating_mul(4)
            && virt_size > 8192
        {
            verdict.has_raw_size_anomaly = true;
            push_unique(
                &mut verdict.raw_size_anomalies,
                format!("expanded_virtual_exec_section({})", sec_name),
            );
        }
        if raw_size > 0
            && (raw_ptr as u64)
                .checked_add(raw_size as u64)
                .is_none_or(|e| e > total_len)
        {
            verdict.has_raw_size_anomaly = true;
            push_unique(
                &mut verdict.raw_size_anomalies,
                format!("out_of_bounds_raw_section({})", sec_name),
            );
        }

        if (is_exec || is_code || ep_in_section) && raw_size > 0 && raw_ptr > 0 {
            scannable.push(PeScanTarget {
                name: sec_name,
                raw_size: raw_size as u64,
                raw_ptr: raw_ptr as u64,
                is_ep: ep_in_section,
            });
        }
    }

    // Prioritize section containing AddressOfEntryPoint first, then allocate fair per-section budget
    scannable.sort_by_key(|t| !t.is_ep);
    let scan_sizes: Vec<u64> = scannable.iter().map(|t| t.raw_size).collect();
    let per_sec_floor =
        (MAX_TOTAL_EXEC_SCAN_BYTES / scannable.len().max(1)).clamp(1, MIN_SECTION_SCAN_SLICE);
    let suffix_reserves = compute_suffix_reserves(&scan_sizes, per_sec_floor);
    let mut remaining_exec_budget = MAX_TOTAL_EXEC_SCAN_BYTES;

    for (idx, target) in scannable.iter().enumerate() {
        let want = fair_section_scan_len(&scan_sizes, &suffix_reserves, idx, remaining_exec_budget);
        if want == 0 {
            break;
        }
        let sec_bytes = source.read_window(target.raw_ptr, want);
        if !sec_bytes.is_empty() {
            let ent = shannon_entropy(&sec_bytes);
            if ent > max_entropy {
                max_entropy = ent;
            }
            if contains_bytes_needle(&sec_bytes, b"UPX!") {
                verdict.has_packer_marker = true;
                push_unique(&mut verdict.packer_markers, "UPX!".to_string());
            }
            let stubs = scan_pe_direct_syscalls(
                &sec_bytes,
                &target.name,
                &mut verdict.syscall_stub_details,
            );
            verdict.direct_syscall_count = verdict.direct_syscall_count.saturating_add(stubs);
            remaining_exec_budget = remaining_exec_budget.saturating_sub(sec_bytes.len());
        }
    }

    verdict.obfuscation_entropy = max_entropy;
    finalize_packed_flag(&mut verdict);
    verdict
}

// ============================================================================
// ELF (32/64-bit LE/BE) Inspector
// ============================================================================

#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn push_sled_stub(
    pos: usize,
    kind: &'static str,
    aggressive_single: bool,
    seg_label: &str,
    pending: &mut Option<(usize, &'static str)>,
    last_pos: &mut Option<usize>,
    count: &mut u32,
    details: &mut Vec<String>,
) {
    let is_explicit =
        kind == "elf_x64_hells_gate_stub" || kind == "elf_x64_mov_eax_syscall_ret_stub";
    if aggressive_single || is_explicit {
        if let Some((p_pos, p_kind)) = *pending {
            if pos.saturating_sub(p_pos) <= 256 {
                *count = count.saturating_add(1);
                if details.len() < MAX_STUB_DETAILS {
                    details.push(format!("{}@{}+0x{:x}", p_kind, seg_label, p_pos));
                }
                *pending = None;
            }
        }
        *count = count.saturating_add(1);
        if details.len() < MAX_STUB_DETAILS {
            details.push(format!("{}@{}+0x{:x}", kind, seg_label, pos));
        }
    } else if last_pos.is_some_and(|lp| pos.saturating_sub(lp) <= 256) {
        if let Some((p_pos, p_kind)) = *pending {
            *count = count.saturating_add(1);
            if details.len() < MAX_STUB_DETAILS {
                details.push(format!("{}@{}+0x{:x}", p_kind, seg_label, p_pos));
            }
            *pending = None;
        }
        *count = count.saturating_add(1);
        if details.len() < MAX_STUB_DETAILS {
            details.push(format!("{}@{}+0x{:x}", kind, seg_label, pos));
        }
    } else {
        *pending = Some((pos, kind));
    }
    *last_pos = Some(pos);
}

#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn check_elf_x64_term(
    slice: &[u8],
    term_pos: usize,
    seg_label: &str,
    aggressive_single: bool,
    x64_pending: &mut Option<(usize, &'static str)>,
    x64_last_pos: &mut Option<usize>,
    count: &mut u32,
    details_full: &mut bool,
    details: &mut Vec<String>,
) {
    if slice.get(term_pos..term_pos.saturating_add(2)) != Some(&[0x0F, 0x05]) {
        return;
    }
    let mut matched: Option<(usize, &'static str)> = None;
    if let Some(b8_pos) = term_pos.checked_sub(5) {
        if let Some([0xB8, _, mid, 0x00, 0x00]) = slice.get(b8_pos..term_pos) {
            if *mid <= 0x02 {
                let has_hells_prefix = b8_pos >= 3
                    && slice.get(b8_pos.saturating_sub(3)..b8_pos) == Some(&[0x4C, 0x8B, 0xD1]);
                if has_hells_prefix {
                    matched = Some((b8_pos.saturating_sub(3), "elf_x64_hells_gate_stub"));
                } else if slice.get(term_pos.saturating_add(2)) == Some(&0xC3) {
                    matched = Some((b8_pos, "elf_x64_mov_eax_syscall_ret_stub"));
                } else {
                    matched = Some((b8_pos, "elf_x64_mov_eax_syscall_stub"));
                }
            }
        }
    }
    if matched.is_none() {
        if let Some(rax_pos) = term_pos.checked_sub(7) {
            if let Some([0x48, 0xC7, 0xC0, _, mid, 0x00, 0x00]) = slice.get(rax_pos..term_pos) {
                if *mid <= 0x02 {
                    matched = Some((rax_pos, "elf_x64_mov_rax_syscall_stub"));
                }
            }
        }
    }
    if let Some((pos, kind)) = matched {
        if x64_last_pos.is_none_or(|lp| pos > lp) {
            push_sled_stub(
                pos,
                kind,
                aggressive_single,
                seg_label,
                x64_pending,
                x64_last_pos,
                count,
                details,
            );
            *details_full = details.len() >= MAX_STUB_DETAILS;
        }
    }
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn check_elf_a64_d4(
    c: &ByteCursor<'_>,
    le: bool,
    d4_pos: usize,
    seg_label: &str,
    aggressive_single: bool,
    a64_pending: &mut Option<(usize, &'static str)>,
    a64_last_pos: &mut Option<usize>,
    count: &mut u32,
    details_full: &mut bool,
    details: &mut Vec<String>,
) {
    let svc_off = if le {
        if (d4_pos & 3) != 3 {
            return;
        }
        d4_pos.saturating_sub(3)
    } else {
        if (d4_pos & 3) != 0 {
            return;
        }
        d4_pos
    };
    if c.u32_endian(svc_off, le) != Some(0xD400_0001) {
        return;
    }
    for look in 1..=3usize {
        if let Some(mov_off) = svc_off.checked_sub(look * 4) {
            if a64_last_pos.is_some_and(|lp| mov_off <= lp) {
                break;
            }
            if let Some(insn) = c.u32_endian(mov_off, le) {
                if (insn & 0xFFE0_001F) == 0xD280_0008 {
                    if *details_full {
                        if aggressive_single
                            || a64_last_pos.is_some_and(|lp| mov_off.saturating_sub(lp) <= 256)
                        {
                            if let Some((p_pos, _)) = *a64_pending {
                                if !aggressive_single || mov_off.saturating_sub(p_pos) <= 256 {
                                    *count = count.saturating_add(1);
                                    *a64_pending = None;
                                }
                            }
                            *count = count.saturating_add(1);
                        } else {
                            *a64_pending = Some((mov_off, "elf_aarch64_mov_x8_svc0_stub"));
                        }
                        *a64_last_pos = Some(mov_off);
                    } else {
                        push_sled_stub(
                            mov_off,
                            "elf_aarch64_mov_x8_svc0_stub",
                            aggressive_single,
                            seg_label,
                            a64_pending,
                            a64_last_pos,
                            count,
                            details,
                        );
                        *details_full = details.len() >= MAX_STUB_DETAILS;
                    }
                    break;
                }
            }
        }
    }
}

fn scan_elf_x64_direct_syscalls(
    slice: &[u8],
    seg_label: &str,
    aggressive_single: bool,
    details: &mut Vec<String>,
) -> u32 {
    let mut count = 0u32;
    let mut x64_pending: Option<(usize, &'static str)> = None;
    let mut x64_last_pos: Option<usize> = None;
    let mut details_full = details.len() >= MAX_STUB_DETAILS;
    let chunks = slice.chunks_exact(8);
    let rem_len = chunks.remainder().len();
    let mut off = 0usize;
    let mut prev_mask = 0u64;
    for chunk in chunks {
        if let [b0, b1, b2, b3, b4, b5, b6, b7] = *chunk {
            let v = u64::from_le_bytes([b0, b1, b2, b3, b4, b5, b6, b7]);
            let x_0f = v ^ 0x0F0F_0F0F_0F0F_0F0Fu64;
            let m_0f =
                x_0f.wrapping_sub(0x0101_0101_0101_0101u64) & !x_0f & 0x8080_8080_8080_8080u64;
            let m_00 = v.wrapping_sub(0x0101_0101_0101_0101u64) & !v & 0x8080_8080_8080_8080u64;
            let x_05 = v ^ 0x0505_0505_0505_0505u64;
            let m_05 =
                x_05.wrapping_sub(0x0101_0101_0101_0101u64) & !x_05 & 0x8080_8080_8080_8080u64;
            let mut m = m_0f & ((m_00 << 8) | prev_mask) & ((m_05 >> 8) | 0x8000_0000_0000_0000u64);
            prev_mask = m_00 >> 56;
            while m != 0 {
                let term_pos = off.saturating_add((m.trailing_zeros() as usize) >> 3);
                m &= m - 1;
                if slice.get(term_pos.saturating_add(1)) != Some(&0x05) {
                    continue;
                }
                let b8_match = term_pos.checked_sub(5).filter(|&b8_pos| {
                    matches!(
                        slice.get(b8_pos..term_pos),
                        Some([0xB8, _, mid, 0x00, 0x00]) if *mid <= 0x02
                    )
                });
                let rax_match = if b8_match.is_none() {
                    term_pos.checked_sub(7).filter(|&rax_pos| {
                        matches!(
                            slice.get(rax_pos..term_pos),
                            Some([0x48, 0xC7, 0xC0, _, mid, 0x00, 0x00]) if *mid <= 0x02
                        )
                    })
                } else {
                    None
                };
                if b8_match.is_none() && rax_match.is_none() {
                    continue;
                }
                if details_full {
                    if let Some(b8_pos) = b8_match {
                        if x64_pending.is_none()
                            && (aggressive_single
                                || x64_last_pos.is_some_and(|lp| b8_pos.saturating_sub(lp) <= 256))
                            && slice.get(b8_pos.wrapping_sub(3)) != Some(&0x4C)
                        {
                            if x64_last_pos.is_none_or(|lp| b8_pos > lp) {
                                count = count.saturating_add(1);
                                x64_last_pos = Some(b8_pos);
                            }
                            continue;
                        }
                    } else if let Some(rax_pos) = rax_match {
                        if x64_pending.is_none()
                            && (aggressive_single
                                || x64_last_pos.is_some_and(|lp| rax_pos.saturating_sub(lp) <= 256))
                        {
                            if x64_last_pos.is_none_or(|lp| rax_pos > lp) {
                                count = count.saturating_add(1);
                                x64_last_pos = Some(rax_pos);
                            }
                            continue;
                        }
                    }
                    let (pos, is_explicit) = if let Some(b8_pos) = b8_match {
                        let has_hells_prefix = b8_pos >= 3
                            && slice.get(b8_pos.saturating_sub(3)..b8_pos)
                                == Some(&[0x4C, 0x8B, 0xD1]);
                        if has_hells_prefix {
                            (b8_pos.saturating_sub(3), true)
                        } else {
                            let has_ret = slice.get(term_pos.saturating_add(2)) == Some(&0xC3);
                            (b8_pos, has_ret)
                        }
                    } else if let Some(rax_pos) = rax_match {
                        (rax_pos, false)
                    } else {
                        continue;
                    };
                    if x64_last_pos.is_none_or(|lp| pos > lp) {
                        if aggressive_single || is_explicit {
                            if let Some((p_pos, _)) = x64_pending {
                                if pos.saturating_sub(p_pos) <= 256 {
                                    count = count.saturating_add(1);
                                    x64_pending = None;
                                }
                            }
                            count = count.saturating_add(1);
                        } else if x64_last_pos.is_some_and(|lp| pos.saturating_sub(lp) <= 256) {
                            if x64_pending.is_some() {
                                count = count.saturating_add(1);
                                x64_pending = None;
                            }
                            count = count.saturating_add(1);
                        } else {
                            x64_pending = Some((pos, "elf_x64_mov_eax_syscall_stub"));
                        }
                        x64_last_pos = Some(pos);
                    }
                    continue;
                }
                check_elf_x64_term(
                    slice,
                    term_pos,
                    seg_label,
                    aggressive_single,
                    &mut x64_pending,
                    &mut x64_last_pos,
                    &mut count,
                    &mut details_full,
                    details,
                );
            }
        }
        off = off.saturating_add(8);
    }
    for term_pos in off..off.saturating_add(rem_len) {
        if slice.get(term_pos) == Some(&0x0F) {
            check_elf_x64_term(
                slice,
                term_pos,
                seg_label,
                aggressive_single,
                &mut x64_pending,
                &mut x64_last_pos,
                &mut count,
                &mut details_full,
                details,
            );
        }
    }
    count
}

fn scan_elf_arm64_direct_syscalls(
    slice: &[u8],
    le: bool,
    seg_label: &str,
    aggressive_single: bool,
    details: &mut Vec<String>,
) -> u32 {
    let mut count = 0u32;
    let mut a64_pending: Option<(usize, &'static str)> = None;
    let mut a64_last_pos: Option<usize> = None;
    let mut details_full = details.len() >= MAX_STUB_DETAILS;
    let c = ByteCursor::new(slice);
    let chunks = slice.chunks_exact(8);
    let rem_len = chunks.remainder().len();
    let mut off = 0usize;
    for chunk in chunks {
        if let [b0, b1, b2, b3, b4, b5, b6, b7] = *chunk {
            let v = u64::from_le_bytes([b0, b1, b2, b3, b4, b5, b6, b7]);
            let x = v ^ 0xD4D4_D4D4_D4D4_D4D4u64;
            let mut m = x.wrapping_sub(0x0101_0101_0101_0101u64) & !x & 0x8080_8080_8080_8080u64;
            if le {
                m &= 0x8000_0000_8000_0000u64;
            }
            while m != 0 {
                let d4_pos = off.saturating_add((m.trailing_zeros() as usize) >> 3);
                m &= m - 1;
                if details_full && le && a64_pending.is_none() && d4_pos >= 7 {
                    let mov_off = d4_pos.saturating_sub(7);
                    if a64_last_pos.is_none_or(|lp| mov_off > lp) {
                        if let Some([m0, m1, m2, m3, 0x01, 0x00, 0x00, 0xD4]) =
                            slice.get(mov_off..d4_pos.saturating_add(1))
                        {
                            let insn = u32::from_le_bytes([*m0, *m1, *m2, *m3]);
                            if (insn & 0xFFE0_001F) == 0xD280_0008
                                && (aggressive_single
                                    || a64_last_pos
                                        .is_some_and(|lp| mov_off.saturating_sub(lp) <= 256))
                            {
                                count = count.saturating_add(1);
                                a64_last_pos = Some(mov_off);
                                continue;
                            }
                        }
                    }
                }
                check_elf_a64_d4(
                    &c,
                    le,
                    d4_pos,
                    seg_label,
                    aggressive_single,
                    &mut a64_pending,
                    &mut a64_last_pos,
                    &mut count,
                    &mut details_full,
                    details,
                );
            }
        }
        off = off.saturating_add(8);
    }
    for d4_pos in off..off.saturating_add(rem_len) {
        if slice.get(d4_pos) == Some(&0xD4) {
            check_elf_a64_d4(
                &c,
                le,
                d4_pos,
                seg_label,
                aggressive_single,
                &mut a64_pending,
                &mut a64_last_pos,
                &mut count,
                &mut details_full,
                details,
            );
        }
    }
    count
}

fn scan_elf_direct_syscalls(
    slice: &[u8],
    le: bool,
    e_machine: u16,
    seg_label: &str,
    aggressive_single: bool,
    details: &mut Vec<String>,
) -> u32 {
    const EM_X86_64: u16 = 62;
    const EM_AARCH64: u16 = 183;

    let is_x64 = e_machine == EM_X86_64;
    let is_arm64 = e_machine == EM_AARCH64;
    let scan_x64 = is_x64 || !is_arm64;
    let scan_arm64 = is_arm64 || !is_x64;

    let mut count = 0u32;
    if scan_x64 {
        count = count.saturating_add(scan_elf_x64_direct_syscalls(
            slice,
            seg_label,
            aggressive_single,
            details,
        ));
    }
    if scan_arm64 {
        count = count.saturating_add(scan_elf_arm64_direct_syscalls(
            slice,
            le,
            seg_label,
            aggressive_single,
            details,
        ));
    }
    count
}

fn inspect_elf(source: &mut BinarySource<'_>, path_label: &str) -> BinaryIntegrityVerdict {
    let total_len = source.total_len();
    let mut hdr_buf = [0u8; 4096];
    let hdr_len = {
        let hs = source.header_slice();
        let n = hs.len().min(4096);
        if let (Some(dst), Some(src)) = (hdr_buf.get_mut(..n), hs.get(..n)) {
            dst.copy_from_slice(src);
        }
        n
    };
    let hdr_slice = hdr_buf.get(..hdr_len).unwrap_or(&[]);
    let c = ByteCursor::new(hdr_slice);
    let mut verdict = BinaryIntegrityVerdict::clean(BinaryFormat::Unknown, path_label);

    let Some(ei_class) = c.u8_at(4) else {
        verdict
            .header_anomalies
            .push("elf_truncated_ident".to_string());
        return verdict;
    };
    let Some(ei_data) = c.u8_at(5) else {
        verdict
            .header_anomalies
            .push("elf_truncated_ident".to_string());
        return verdict;
    };

    let is_64 = match ei_class {
        1 => false,
        2 => true,
        other => {
            verdict
                .header_anomalies
                .push(format!("elf_invalid_class({})", other));
            return verdict;
        }
    };
    let le = match ei_data {
        1 => true,
        2 => false,
        other => {
            verdict
                .header_anomalies
                .push(format!("elf_invalid_endian({})", other));
            return verdict;
        }
    };
    verdict.format = if is_64 {
        BinaryFormat::Elf64
    } else {
        BinaryFormat::Elf32
    };
    let e_machine = c.u16_endian(18, le).unwrap_or(0);

    let (e_entry, e_phoff, e_shoff, e_phentsize, e_phnum_raw, e_shentsize, e_shnum_raw, e_shstrndx) =
        if is_64 {
            let (
                Some(entry),
                Some(phoff),
                Some(shoff),
                Some(phent),
                Some(phnum),
                Some(shent),
                Some(shnum),
                Some(shstr),
            ) = (
                c.u64_endian(24, le),
                c.u64_endian(32, le),
                c.u64_endian(40, le),
                c.u16_endian(54, le),
                c.u16_endian(56, le),
                c.u16_endian(58, le),
                c.u16_endian(60, le),
                c.u16_endian(62, le),
            )
            else {
                verdict
                    .header_anomalies
                    .push("elf64_truncated_ehdr".to_string());
                return verdict;
            };
            (entry, phoff, shoff, phent, phnum, shent, shnum, shstr)
        } else {
            let (
                Some(entry),
                Some(phoff),
                Some(shoff),
                Some(phent),
                Some(phnum),
                Some(shent),
                Some(shnum),
                Some(shstr),
            ) = (
                c.u32_endian(24, le).map(u64::from),
                c.u32_endian(28, le).map(u64::from),
                c.u32_endian(32, le).map(u64::from),
                c.u16_endian(42, le),
                c.u16_endian(44, le),
                c.u16_endian(46, le),
                c.u16_endian(48, le),
                c.u16_endian(50, le),
            )
            else {
                verdict
                    .header_anomalies
                    .push("elf32_truncated_ehdr".to_string());
                return verdict;
            };
            (entry, phoff, shoff, phent, phnum, shent, shnum, shstr)
        };

    if contains_bytes_needle(hdr_slice, b"UPX!") {
        verdict.has_packer_marker = true;
        push_unique(&mut verdict.packer_markers, "UPX!");
    }

    if (e_phnum_raw as usize) > MAX_ELF_PHDRS {
        verdict
            .header_anomalies
            .push(format!("elf_excessive_phdrs({})", e_phnum_raw));
    }
    let phnum = (e_phnum_raw as usize).min(MAX_ELF_PHDRS);
    let min_phent = if is_64 { 56usize } else { 32usize };

    struct ElfScanTarget {
        seg_label: String,
        p_offset: u64,
        p_filesz: u64,
        is_write: bool,
        is_ep: bool,
    }

    let mut scannable: Vec<ElfScanTarget> = Vec::with_capacity(phnum.min(8));
    let mut max_entropy = 0.0f64;

    if phnum > 0 && e_phoff > 0 && (e_phentsize as usize) >= min_phent {
        let ph_bytes_len = phnum.saturating_mul(e_phentsize as usize);
        let ph_win = source.read_window(e_phoff, ph_bytes_len).into_owned();
        let pc = ByteCursor::new(&ph_win);

        for i in 0..phnum {
            let Some(off) = i.checked_mul(e_phentsize as usize) else {
                break;
            };
            if pc.slice(off, min_phent).is_none() {
                verdict
                    .header_anomalies
                    .push("elf_truncated_phdr".to_string());
                break;
            }
            let (p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz) = if is_64 {
                (
                    pc.u32_endian(off, le).unwrap_or(0),
                    pc.u32_endian(off + 4, le).unwrap_or(0),
                    pc.u64_endian(off + 8, le).unwrap_or(0),
                    pc.u64_endian(off + 16, le).unwrap_or(0),
                    pc.u64_endian(off + 32, le).unwrap_or(0),
                    pc.u64_endian(off + 40, le).unwrap_or(0),
                )
            } else {
                (
                    pc.u32_endian(off, le).unwrap_or(0),
                    pc.u32_endian(off + 24, le).unwrap_or(0),
                    pc.u32_endian(off + 4, le).unwrap_or(0) as u64,
                    pc.u32_endian(off + 8, le).unwrap_or(0) as u64,
                    pc.u32_endian(off + 16, le).unwrap_or(0) as u64,
                    pc.u32_endian(off + 20, le).unwrap_or(0) as u64,
                )
            };

            // PT_LOAD = 1
            if p_type != 1 {
                continue;
            }
            let seg_label = format!("PT_LOAD[{}]", i);
            let is_exec = (p_flags & 0x1) != 0;
            let is_write = (p_flags & 0x2) != 0;
            let is_ep = e_entry != 0
                && e_entry >= p_vaddr
                && e_entry < p_vaddr.saturating_add(p_memsz.max(p_filesz));

            if is_exec && is_write {
                verdict.has_wx_violation = true;
                push_unique(&mut verdict.wx_sections, seg_label.clone());
            }

            if is_exec && p_filesz == 0 && p_memsz > 4096 {
                verdict.has_raw_size_anomaly = true;
                push_unique(
                    &mut verdict.raw_size_anomalies,
                    format!("hollow_exec_segment({})", seg_label),
                );
            }
            if is_exec && p_filesz > 0 && p_memsz > p_filesz.saturating_mul(4) && p_memsz > 8192 {
                verdict.has_raw_size_anomaly = true;
                push_unique(
                    &mut verdict.raw_size_anomalies,
                    format!("expanded_virtual_exec_segment({})", seg_label),
                );
            }
            if p_filesz > 0 && p_offset.checked_add(p_filesz).is_none_or(|e| e > total_len) {
                verdict.has_raw_size_anomaly = true;
                push_unique(
                    &mut verdict.raw_size_anomalies,
                    format!("out_of_bounds_segment({})", seg_label),
                );
            }

            if (is_exec || is_ep) && p_filesz > 0 {
                scannable.push(ElfScanTarget {
                    seg_label,
                    p_offset,
                    p_filesz,
                    is_write,
                    is_ep,
                });
            }
        }
    }

    scannable.sort_by_key(|t| !t.is_ep);
    let scan_sizes: Vec<u64> = scannable.iter().map(|t| t.p_filesz).collect();
    let per_seg_floor =
        (MAX_TOTAL_EXEC_SCAN_BYTES / scannable.len().max(1)).clamp(1, MIN_SECTION_SCAN_SLICE);
    let suffix_reserves = compute_suffix_reserves(&scan_sizes, per_seg_floor);
    let mut remaining_exec_budget = MAX_TOTAL_EXEC_SCAN_BYTES;

    for (idx, target) in scannable.iter().enumerate() {
        let want = fair_section_scan_len(&scan_sizes, &suffix_reserves, idx, remaining_exec_budget);
        if want == 0 {
            break;
        }
        let seg_bytes = source.read_window(target.p_offset, want);
        if !seg_bytes.is_empty() {
            let ent = shannon_entropy(&seg_bytes);
            if ent > max_entropy {
                max_entropy = ent;
            }
            for u_pos in memchr::memchr_iter(b'U', &seg_bytes) {
                if let Some(win) = seg_bytes.get(u_pos..u_pos.saturating_add(4)) {
                    if matches!(win, b"UPX!" | b"UPX0" | b"UPX1") {
                        verdict.has_packer_marker = true;
                        push_unique(
                            &mut verdict.packer_markers,
                            String::from_utf8_lossy(win).to_string(),
                        );
                    }
                }
            }
            let aggressive_single = target.is_write || target.p_filesz < 65_536;
            let stubs = scan_elf_direct_syscalls(
                &seg_bytes,
                le,
                e_machine,
                &target.seg_label,
                aggressive_single,
                &mut verdict.syscall_stub_details,
            );
            verdict.direct_syscall_count = verdict.direct_syscall_count.saturating_add(stubs);
            remaining_exec_budget = remaining_exec_budget.saturating_sub(seg_bytes.len());
        }
    }

    // Optional bounded inspection of ELF section headers for packer section names & SHF_WRITE|SHF_EXECINSTR
    let shnum = (e_shnum_raw as usize).min(MAX_ELF_SHDRS);
    let min_shent = if is_64 { 64usize } else { 40usize };
    if shnum > 0 && e_shoff > 0 && (e_shentsize as usize) >= min_shent && e_shoff < total_len {
        let sh_bytes_len = shnum.saturating_mul(e_shentsize as usize);
        let sh_win = source.read_window(e_shoff, sh_bytes_len).into_owned();
        let sc = ByteCursor::new(&sh_win);

        // Read bounded shstrtab if valid
        let shstrtab: Vec<u8> = if (e_shstrndx as usize) < shnum {
            let str_off_in_sh = (e_shstrndx as usize).saturating_mul(e_shentsize as usize);
            let (str_file_off, str_size) = if is_64 {
                (
                    sc.u64_endian(str_off_in_sh + 24, le).unwrap_or(0),
                    sc.u64_endian(str_off_in_sh + 32, le).unwrap_or(0),
                )
            } else {
                (
                    sc.u32_endian(str_off_in_sh + 16, le).unwrap_or(0) as u64,
                    sc.u32_endian(str_off_in_sh + 20, le).unwrap_or(0) as u64,
                )
            };
            if str_file_off > 0 && str_size > 0 && str_size <= 65_536 {
                source
                    .read_window(str_file_off, str_size as usize)
                    .into_owned()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        let str_cursor = ByteCursor::new(&shstrtab);

        for i in 0..shnum {
            let Some(off) = i.checked_mul(e_shentsize as usize) else {
                break;
            };
            if sc.slice(off, min_shent).is_none() {
                break;
            }
            let sh_name_idx = sc.u32_endian(off, le).unwrap_or(0) as usize;
            let sh_flags = if is_64 {
                sc.u64_endian(off + 8, le).unwrap_or(0)
            } else {
                sc.u32_endian(off + 8, le).unwrap_or(0) as u64
            };
            let sec_name = str_cursor
                .fixed_cstr(sh_name_idx, 64)
                .unwrap_or_else(|| format!("shdr_{}", i));
            if is_packer_section_name(&sec_name) {
                verdict.has_packer_marker = true;
                push_unique(&mut verdict.packer_markers, sec_name.clone());
            }
            // SHF_WRITE = 0x1, SHF_EXECINSTR = 0x4
            if (sh_flags & 0x5) == 0x5 {
                verdict.has_wx_violation = true;
                push_unique(&mut verdict.wx_sections, sec_name);
            }
        }
    }

    verdict.obfuscation_entropy = max_entropy;
    finalize_packed_flag(&mut verdict);
    verdict
}

// ============================================================================
// Mach-O (32/64-bit LE/BE & Universal Fat) Inspector
// ============================================================================

fn is_macho_thin_magic_be(magic_be: u32) -> bool {
    matches!(
        magic_be,
        0xFEED_FACE | 0xCEFA_EDFE | 0xFEED_FACF | 0xCFFA_EDFE
    )
}

fn try_inspect_macho_fat(
    source: &mut BinarySource<'_>,
    path_label: &str,
    base_offset: u64,
) -> Option<BinaryIntegrityVerdict> {
    let total_len = source.total_len();
    let hdr_win = source.read_window(base_offset, 512).into_owned();
    let c = ByteCursor::new(&hdr_win);
    let magic_be = c.u32_be(0)?;
    let (fat_le, is_fat64) = match magic_be {
        0xCAFE_BABE => (false, false),
        0xBEBA_FECA => (true, false),
        0xCAFE_BABF => (false, true),
        0xBFBA_FECA => (true, true),
        _ => return None,
    };

    let nfat_arch = c.u32_endian(4, fat_le)? as usize;
    if !(1..=MAX_MACHO_FAT_ARCHS).contains(&nfat_arch) {
        return None;
    }
    let entry_size = if is_fat64 { 32usize } else { 20usize };
    let table_end = 8usize.checked_add(nfat_arch.checked_mul(entry_size)?)?;
    if (table_end as u64) > total_len || table_end > hdr_win.len() {
        return None;
    }

    let mut slices: Vec<(u64, u64)> = Vec::with_capacity(nfat_arch);
    for i in 0..nfat_arch {
        let off = 8usize.checked_add(i.checked_mul(entry_size)?)?;
        let (slice_off, slice_size) = if is_fat64 {
            (
                c.u64_endian(off + 8, fat_le)?,
                c.u64_endian(off + 16, fat_le)?,
            )
        } else {
            (
                c.u32_endian(off + 8, fat_le)? as u64,
                c.u32_endian(off + 12, fat_le)? as u64,
            )
        };
        if slice_off < table_end as u64 || slice_size < 28 {
            return None;
        }
        let slice_end = slice_off.checked_add(slice_size)?;
        if slice_end > total_len {
            return None;
        }
        // Confirm slice actually begins with a valid Mach-O thin magic (rejects Java .class)
        let magic_bytes = source.read_window(slice_off, 4);
        let slice_magic_be = ByteCursor::new(&magic_bytes).u32_be(0)?;
        if !is_macho_thin_magic_be(slice_magic_be) {
            return None;
        }
        slices.push((slice_off, slice_size));
    }

    let mut agg = BinaryIntegrityVerdict::clean(BinaryFormat::MachOFat, path_label);
    let mut all_signed = true;
    let mut remaining_budget = MAX_TOTAL_EXEC_SCAN_BYTES;

    for (idx, (slice_off, slice_size)) in slices.into_iter().enumerate() {
        let slice_label = format!("{}[slice_{}]", path_label, idx);
        let sv = inspect_macho_slice(
            source,
            &slice_label,
            slice_off,
            slice_size,
            &mut remaining_budget,
        );
        agg.is_packed |= sv.is_packed;
        agg.has_packer_marker |= sv.has_packer_marker;
        for m in sv.packer_markers {
            push_unique(&mut agg.packer_markers, m);
        }
        agg.has_wx_violation |= sv.has_wx_violation;
        for wx in sv.wx_sections {
            push_unique(&mut agg.wx_sections, wx);
        }
        agg.has_raw_size_anomaly |= sv.has_raw_size_anomaly;
        for ra in sv.raw_size_anomalies {
            push_unique(&mut agg.raw_size_anomalies, ra);
        }
        if sv.obfuscation_entropy > agg.obfuscation_entropy {
            agg.obfuscation_entropy = sv.obfuscation_entropy;
        }
        agg.direct_syscall_count = agg
            .direct_syscall_count
            .saturating_add(sv.direct_syscall_count);
        for d in sv.syscall_stub_details {
            if agg.syscall_stub_details.len() >= MAX_STUB_DETAILS {
                break;
            }
            agg.syscall_stub_details.push(d);
        }
        agg.header_anomalies.extend(sv.header_anomalies);
        all_signed &= sv.is_code_signed;
    }

    agg.is_code_signed = all_signed;
    agg.is_authenticode_signed = all_signed;
    finalize_packed_flag(&mut agg);
    Some(agg)
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn check_macho_a64_d4(
    c: &ByteCursor<'_>,
    le: bool,
    d4_pos: usize,
    seg_label: &str,
    aggressive_single: bool,
    a64_pending: &mut Option<(usize, &'static str)>,
    a64_last_pos: &mut Option<usize>,
    count: &mut u32,
    details_full: &mut bool,
    details: &mut Vec<String>,
) {
    let svc_off = if le {
        if (d4_pos & 3) != 3 {
            return;
        }
        d4_pos.saturating_sub(3)
    } else {
        if (d4_pos & 3) != 0 {
            return;
        }
        d4_pos
    };
    if c.u32_endian(svc_off, le) != Some(0xD400_1001) {
        return;
    }
    for look in 1..=3usize {
        if let Some(mov_off) = svc_off.checked_sub(look * 4) {
            if a64_last_pos.is_some_and(|lp| mov_off <= lp) {
                break;
            }
            if let Some(insn) = c.u32_endian(mov_off, le) {
                if (insn & 0xFFE0_001F) == 0xD280_0010 {
                    if *details_full {
                        if aggressive_single
                            || a64_last_pos.is_some_and(|lp| mov_off.saturating_sub(lp) <= 256)
                        {
                            if let Some((p_pos, _)) = *a64_pending {
                                if !aggressive_single || mov_off.saturating_sub(p_pos) <= 256 {
                                    *count = count.saturating_add(1);
                                    *a64_pending = None;
                                }
                            }
                            *count = count.saturating_add(1);
                        } else {
                            *a64_pending = Some((mov_off, "macho_arm64_mov_x16_svc80_stub"));
                        }
                        *a64_last_pos = Some(mov_off);
                    } else {
                        push_sled_stub(
                            mov_off,
                            "macho_arm64_mov_x16_svc80_stub",
                            aggressive_single,
                            seg_label,
                            a64_pending,
                            a64_last_pos,
                            count,
                            details,
                        );
                        *details_full = details.len() >= MAX_STUB_DETAILS;
                    }
                    break;
                }
            }
        }
    }
}

#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn check_macho_x64_term(
    slice: &[u8],
    term_pos: usize,
    seg_label: &str,
    aggressive_single: bool,
    x64_pending: &mut Option<(usize, &'static str)>,
    x64_last_pos: &mut Option<usize>,
    count: &mut u32,
    details_full: &mut bool,
    details: &mut Vec<String>,
) {
    if slice.get(term_pos..term_pos.saturating_add(2)) != Some(&[0x0F, 0x05]) {
        return;
    }
    let mut matched: Option<(usize, &'static str)> = None;
    if let Some(b8_pos) = term_pos.checked_sub(5) {
        if let Some([0xB8, _, _, 0x00, 0x02]) = slice.get(b8_pos..term_pos) {
            matched = Some((b8_pos, "macho_x64_darwin_syscall_stub"));
        }
    }
    if matched.is_none() {
        if let Some(rax_pos) = term_pos.checked_sub(7) {
            if let Some([0x48, 0xC7, 0xC0, _, _, 0x00, 0x02]) = slice.get(rax_pos..term_pos) {
                matched = Some((rax_pos, "macho_x64_rax_darwin_syscall_stub"));
            }
        }
    }
    if let Some((pos, kind)) = matched {
        if x64_last_pos.is_none_or(|lp| pos > lp) {
            push_sled_stub(
                pos,
                kind,
                aggressive_single,
                seg_label,
                x64_pending,
                x64_last_pos,
                count,
                details,
            );
            *details_full = details.len() >= MAX_STUB_DETAILS;
        }
    }
}

fn scan_macho_arm64_direct_syscalls(
    slice: &[u8],
    le: bool,
    seg_label: &str,
    aggressive_single: bool,
    details: &mut Vec<String>,
) -> u32 {
    let mut count = 0u32;
    let mut a64_pending: Option<(usize, &'static str)> = None;
    let mut a64_last_pos: Option<usize> = None;
    let mut details_full = details.len() >= MAX_STUB_DETAILS;
    let c = ByteCursor::new(slice);
    let chunks = slice.chunks_exact(8);
    let rem_len = chunks.remainder().len();
    let mut off = 0usize;
    for chunk in chunks {
        if let [b0, b1, b2, b3, b4, b5, b6, b7] = *chunk {
            let v = u64::from_le_bytes([b0, b1, b2, b3, b4, b5, b6, b7]);
            let x = v ^ 0xD4D4_D4D4_D4D4_D4D4u64;
            let mut m = x.wrapping_sub(0x0101_0101_0101_0101u64) & !x & 0x8080_8080_8080_8080u64;
            if le {
                m &= 0x8000_0000_8000_0000u64;
            }
            while m != 0 {
                let d4_pos = off.saturating_add((m.trailing_zeros() as usize) >> 3);
                m &= m - 1;
                if details_full && le && a64_pending.is_none() && d4_pos >= 7 {
                    let mov_off = d4_pos.saturating_sub(7);
                    if a64_last_pos.is_none_or(|lp| mov_off > lp) {
                        if let Some([m0, m1, m2, m3, 0x01, 0x10, 0x00, 0xD4]) =
                            slice.get(mov_off..d4_pos.saturating_add(1))
                        {
                            let insn = u32::from_le_bytes([*m0, *m1, *m2, *m3]);
                            if (insn & 0xFFE0_001F) == 0xD280_0010
                                && (aggressive_single
                                    || a64_last_pos
                                        .is_some_and(|lp| mov_off.saturating_sub(lp) <= 256))
                            {
                                count = count.saturating_add(1);
                                a64_last_pos = Some(mov_off);
                                continue;
                            }
                        }
                    }
                }
                check_macho_a64_d4(
                    &c,
                    le,
                    d4_pos,
                    seg_label,
                    aggressive_single,
                    &mut a64_pending,
                    &mut a64_last_pos,
                    &mut count,
                    &mut details_full,
                    details,
                );
            }
        }
        off = off.saturating_add(8);
    }
    for d4_pos in off..off.saturating_add(rem_len) {
        if slice.get(d4_pos) == Some(&0xD4) {
            check_macho_a64_d4(
                &c,
                le,
                d4_pos,
                seg_label,
                aggressive_single,
                &mut a64_pending,
                &mut a64_last_pos,
                &mut count,
                &mut details_full,
                details,
            );
        }
    }
    count
}

fn scan_macho_x64_direct_syscalls(
    slice: &[u8],
    seg_label: &str,
    aggressive_single: bool,
    details: &mut Vec<String>,
) -> u32 {
    let mut count = 0u32;
    let mut x64_pending: Option<(usize, &'static str)> = None;
    let mut x64_last_pos: Option<usize> = None;
    let mut details_full = details.len() >= MAX_STUB_DETAILS;
    let chunks = slice.chunks_exact(8);
    let rem_len = chunks.remainder().len();
    let mut off = 0usize;
    let mut prev_mask = 0u64;
    for chunk in chunks {
        if let [b0, b1, b2, b3, b4, b5, b6, b7] = *chunk {
            let v = u64::from_le_bytes([b0, b1, b2, b3, b4, b5, b6, b7]);
            let x_0f = v ^ 0x0F0F_0F0F_0F0F_0F0Fu64;
            let m_0f =
                x_0f.wrapping_sub(0x0101_0101_0101_0101u64) & !x_0f & 0x8080_8080_8080_8080u64;
            let x_02 = v ^ 0x0202_0202_0202_0202u64;
            let m_02 =
                x_02.wrapping_sub(0x0101_0101_0101_0101u64) & !x_02 & 0x8080_8080_8080_8080u64;
            let x_05 = v ^ 0x0505_0505_0505_0505u64;
            let m_05 =
                x_05.wrapping_sub(0x0101_0101_0101_0101u64) & !x_05 & 0x8080_8080_8080_8080u64;
            let mut m = m_0f & ((m_02 << 8) | prev_mask) & ((m_05 >> 8) | 0x8000_0000_0000_0000u64);
            prev_mask = m_02 >> 56;
            while m != 0 {
                let term_pos = off.saturating_add((m.trailing_zeros() as usize) >> 3);
                m &= m - 1;
                if slice.get(term_pos.saturating_add(1)) != Some(&0x05) {
                    continue;
                }
                let b8_match = term_pos.checked_sub(5).filter(|&b8_pos| {
                    matches!(slice.get(b8_pos..term_pos), Some([0xB8, _, _, 0x00, 0x02]))
                });
                let rax_match = if b8_match.is_none() {
                    term_pos.checked_sub(7).filter(|&rax_pos| {
                        matches!(
                            slice.get(rax_pos..term_pos),
                            Some([0x48, 0xC7, 0xC0, _, _, 0x00, 0x02])
                        )
                    })
                } else {
                    None
                };
                if b8_match.is_none() && rax_match.is_none() {
                    continue;
                }
                if details_full {
                    if let Some(pos) = b8_match.or(rax_match) {
                        if x64_last_pos.is_none_or(|lp| pos > lp) {
                            if aggressive_single
                                || x64_last_pos.is_some_and(|lp| pos.saturating_sub(lp) <= 256)
                            {
                                if x64_pending.is_some() {
                                    count = count.saturating_add(1);
                                    x64_pending = None;
                                }
                                count = count.saturating_add(1);
                            } else {
                                x64_pending = Some((pos, "macho_x64_darwin_syscall_stub"));
                            }
                            x64_last_pos = Some(pos);
                        }
                        continue;
                    }
                }
                check_macho_x64_term(
                    slice,
                    term_pos,
                    seg_label,
                    aggressive_single,
                    &mut x64_pending,
                    &mut x64_last_pos,
                    &mut count,
                    &mut details_full,
                    details,
                );
            }
        }
        off = off.saturating_add(8);
    }
    for term_pos in off..off.saturating_add(rem_len) {
        if slice.get(term_pos) == Some(&0x0F) {
            check_macho_x64_term(
                slice,
                term_pos,
                seg_label,
                aggressive_single,
                &mut x64_pending,
                &mut x64_last_pos,
                &mut count,
                &mut details_full,
                details,
            );
        }
    }
    count
}

fn scan_macho_direct_syscalls(
    slice: &[u8],
    le: bool,
    cputype: u32,
    seg_label: &str,
    aggressive_single: bool,
    details: &mut Vec<String>,
) -> u32 {
    const CPU_TYPE_X86_64: u32 = 0x0100_0007;
    const CPU_TYPE_ARM64: u32 = 0x0100_000C;
    const CPU_TYPE_ARM64_32: u32 = 0x0200_000C;

    let is_x64 = cputype == CPU_TYPE_X86_64;
    let is_arm64 = matches!(cputype, CPU_TYPE_ARM64 | CPU_TYPE_ARM64_32);
    let scan_x64 = is_x64 || !is_arm64;
    let scan_arm64 = is_arm64 || !is_x64;

    let mut count = 0u32;
    if scan_arm64 {
        count = count.saturating_add(scan_macho_arm64_direct_syscalls(
            slice,
            le,
            seg_label,
            aggressive_single,
            details,
        ));
    }
    if scan_x64 {
        count = count.saturating_add(scan_macho_x64_direct_syscalls(
            slice,
            seg_label,
            aggressive_single,
            details,
        ));
    }
    count
}

fn inspect_macho_slice(
    source: &mut BinarySource<'_>,
    path_label: &str,
    slice_offset: u64,
    slice_len: u64,
    remaining_budget: &mut usize,
) -> BinaryIntegrityVerdict {
    let slice_len_usize = usize::try_from(slice_len).unwrap_or(usize::MAX);
    let mut fixed_buf = [0u8; 32];
    let fixed_len = {
        let win = source.read_window(slice_offset, 32.min(slice_len_usize));
        let n = win.len().min(32);
        if let (Some(dst), Some(src)) = (fixed_buf.get_mut(..n), win.get(..n)) {
            dst.copy_from_slice(src);
        }
        n
    };
    let fc = ByteCursor::new(fixed_buf.get(..fixed_len).unwrap_or(&[]));
    let mut verdict = BinaryIntegrityVerdict::clean(BinaryFormat::Unknown, path_label);

    let Some(magic_be) = fc.u32_be(0) else {
        verdict
            .header_anomalies
            .push("macho_truncated_header".to_string());
        return verdict;
    };
    let (le, is_64) = match magic_be {
        0xCFFA_EDFE => (true, true),
        0xFEED_FACF => (false, true),
        0xCEFA_EDFE => (true, false),
        0xFEED_FACE => (false, false),
        _ => {
            verdict
                .header_anomalies
                .push("macho_invalid_magic".to_string());
            return verdict;
        }
    };
    verdict.format = if is_64 {
        BinaryFormat::MachO64
    } else {
        BinaryFormat::MachO32
    };

    let cputype = fc.u32_endian(4, le).unwrap_or(0);
    let hdr_size = if is_64 { 32usize } else { 28usize };
    let (Some(ncmds_raw), Some(sizeofcmds_raw)) = (fc.u32_endian(16, le), fc.u32_endian(20, le))
    else {
        verdict
            .header_anomalies
            .push("macho_truncated_header".to_string());
        return verdict;
    };

    let want_hdr = hdr_size
        .saturating_add(sizeofcmds_raw as usize)
        .clamp(4096, HEADER_WINDOW_BYTES)
        .min(slice_len_usize);
    let hdr_win = source.read_window(slice_offset, want_hdr).into_owned();
    let c = ByteCursor::new(&hdr_win);

    if (ncmds_raw as usize) > MAX_MACHO_CMDS {
        verdict
            .header_anomalies
            .push(format!("macho_excessive_ncmds({})", ncmds_raw));
    }
    let ncmds = (ncmds_raw as usize).min(MAX_MACHO_CMDS);

    let first_4k = hdr_win.get(..hdr_win.len().min(4096)).unwrap_or(&[]);
    if contains_bytes_needle(first_4k, b"UPX!") {
        verdict.has_packer_marker = true;
        push_unique(&mut verdict.packer_markers, "UPX!");
    }

    let cmds_end = hdr_size
        .saturating_add(sizeofcmds_raw as usize)
        .min(hdr_win.len())
        .min(slice_len_usize);

    struct MachoScanTarget {
        segname: String,
        fileoff: u64,
        filesize: u64,
        is_write: bool,
    }

    let mut scannable: Vec<MachoScanTarget> = Vec::with_capacity(ncmds.min(8));
    let mut cmd_off = hdr_size;
    let mut max_entropy = 0.0f64;

    for _ in 0..ncmds {
        if cmd_off >= cmds_end {
            break;
        }
        let (Some(cmd), Some(cmdsize_u32)) =
            (c.u32_endian(cmd_off, le), c.u32_endian(cmd_off + 4, le))
        else {
            verdict
                .header_anomalies
                .push("macho_truncated_load_command".to_string());
            break;
        };
        let cmdsize = cmdsize_u32 as usize;
        if cmdsize < 8 || cmd_off.checked_add(cmdsize).is_none_or(|e| e > cmds_end) {
            verdict
                .header_anomalies
                .push("macho_invalid_load_command_size".to_string());
            break;
        }

        match cmd {
            // LC_SEGMENT_64 (0x19) / LC_SEGMENT (0x01)
            0x19 | 0x01 => {
                let min_seg = if cmd == 0x19 { 72usize } else { 56usize };
                if cmdsize >= min_seg {
                    let segname = c
                        .fixed_cstr(cmd_off + 8, 16)
                        .unwrap_or_else(|| "__UNKNOWN".to_string());
                    let (vmsize, fileoff, filesize, initprot) = if cmd == 0x19 {
                        (
                            c.u64_endian(cmd_off + 32, le).unwrap_or(0),
                            c.u64_endian(cmd_off + 40, le).unwrap_or(0),
                            c.u64_endian(cmd_off + 48, le).unwrap_or(0),
                            c.u32_endian(cmd_off + 60, le).unwrap_or(0),
                        )
                    } else {
                        (
                            c.u32_endian(cmd_off + 28, le).unwrap_or(0) as u64,
                            c.u32_endian(cmd_off + 32, le).unwrap_or(0) as u64,
                            c.u32_endian(cmd_off + 36, le).unwrap_or(0) as u64,
                            c.u32_endian(cmd_off + 44, le).unwrap_or(0),
                        )
                    };

                    if is_packer_section_name(&segname) {
                        verdict.has_packer_marker = true;
                        push_unique(&mut verdict.packer_markers, segname.clone());
                    }

                    // VM_PROT_WRITE = 0x02, VM_PROT_EXECUTE = 0x04
                    let is_write = (initprot & 0x02) != 0;
                    let is_exec = (initprot & 0x04) != 0;
                    if is_write && is_exec {
                        verdict.has_wx_violation = true;
                        push_unique(&mut verdict.wx_sections, segname.clone());
                    }

                    if is_exec && filesize == 0 && vmsize > 4096 {
                        verdict.has_raw_size_anomaly = true;
                        push_unique(
                            &mut verdict.raw_size_anomalies,
                            format!("hollow_exec_segment({})", segname),
                        );
                    }
                    if is_exec
                        && filesize > 0
                        && vmsize > filesize.saturating_mul(4)
                        && vmsize > 8192
                    {
                        verdict.has_raw_size_anomaly = true;
                        push_unique(
                            &mut verdict.raw_size_anomalies,
                            format!("expanded_virtual_exec_segment({})", segname),
                        );
                    }
                    if filesize > 0 && fileoff.checked_add(filesize).is_none_or(|e| e > slice_len) {
                        verdict.has_raw_size_anomaly = true;
                        push_unique(
                            &mut verdict.raw_size_anomalies,
                            format!("out_of_bounds_segment({})", segname),
                        );
                    }

                    if is_exec && filesize > 0 {
                        scannable.push(MachoScanTarget {
                            segname,
                            fileoff,
                            filesize,
                            is_write,
                        });
                    }
                }
            }
            // LC_CODE_SIGNATURE (0x1D)
            0x1D => {
                if cmdsize >= 16 {
                    let dataoff = c.u32_endian(cmd_off + 8, le).unwrap_or(0) as u64;
                    let datasize = c.u32_endian(cmd_off + 12, le).unwrap_or(0) as u64;
                    if datasize >= 12
                        && dataoff
                            .checked_add(datasize)
                            .is_some_and(|e| e <= slice_len)
                    {
                        if let Some(abs_off) = slice_offset.checked_add(dataoff) {
                            let sig_hdr = source.read_window(abs_off, 12);
                            // CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0 (big-endian)
                            if ByteCursor::new(&sig_hdr).u32_be(0) == Some(0xFADE_0CC0) {
                                verdict.is_code_signed = true;
                                verdict.is_authenticode_signed = true;
                            }
                        }
                    } else {
                        verdict
                            .header_anomalies
                            .push("macho_truncated_code_signature".to_string());
                    }
                }
            }
            _ => {}
        }

        cmd_off = cmd_off.saturating_add(cmdsize);
    }

    let scan_sizes: Vec<u64> = scannable.iter().map(|t| t.filesize).collect();
    let per_seg_floor =
        ((*remaining_budget) / scannable.len().max(1)).clamp(1, MIN_SECTION_SCAN_SLICE);
    let suffix_reserves = compute_suffix_reserves(&scan_sizes, per_seg_floor);

    for (idx, target) in scannable.iter().enumerate() {
        let want = fair_section_scan_len(&scan_sizes, &suffix_reserves, idx, *remaining_budget);
        if want == 0 {
            break;
        }
        if let Some(abs_off) = slice_offset.checked_add(target.fileoff) {
            let seg_bytes = source.read_window(abs_off, want);
            if !seg_bytes.is_empty() {
                let ent = shannon_entropy(&seg_bytes);
                if ent > max_entropy {
                    max_entropy = ent;
                }
                if contains_bytes_needle(&seg_bytes, b"UPX!") {
                    verdict.has_packer_marker = true;
                    push_unique(&mut verdict.packer_markers, "UPX!".to_string());
                }
                let aggressive_single = target.is_write || target.filesize < 65_536;
                let stubs = scan_macho_direct_syscalls(
                    &seg_bytes,
                    le,
                    cputype,
                    &target.segname,
                    aggressive_single,
                    &mut verdict.syscall_stub_details,
                );
                verdict.direct_syscall_count = verdict.direct_syscall_count.saturating_add(stubs);
                *remaining_budget = remaining_budget.saturating_sub(seg_bytes.len());
            }
        }
    }

    verdict.obfuscation_entropy = max_entropy;
    finalize_packed_flag(&mut verdict);
    verdict
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_cursor_never_panics_on_bounds_or_overflow() {
        let data = [1u8, 2, 3];
        let c = ByteCursor::new(&data);
        assert_eq!(c.len(), 3);
        assert!(!c.is_empty());
        assert_eq!(c.u32_le(0), None);
        assert_eq!(c.u64_le(usize::MAX), None);
        assert_eq!(c.slice(2, usize::MAX), None);
        assert_eq!(c.fixed_cstr(0, 10), None);
        assert_eq!(c.u16_le(1), Some(0x0302));
        assert_eq!(c.u16_be(1), Some(0x0203));
    }

    #[test]
    fn wasm_and_shebang_formats_handled_cleanly() {
        let wasm_v = inspect_binary_bytes(b"\x00asm\x01\x00\x00\x00", "mod.wasm");
        assert_eq!(wasm_v.format, BinaryFormat::Wasm);
        assert!(!wasm_v.is_packed);

        let sh_v = inspect_binary_bytes(b"#!/usr/bin/env -S python3 -u\nprint(1)\n", "run.py");
        assert_eq!(sh_v.format, BinaryFormat::ScriptShebang);
        assert_eq!(sh_v.shebang_interpreter.as_deref(), Some("python3"));
    }

    #[test]
    fn java_class_cafebabe_not_misparsed_as_macho_fat() {
        // Java class magic 0xCAFEBABE, minor=0, major=61 (0x003D) -> 61 > MAX_MACHO_FAT_ARCHS
        let mut class_bytes = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x3D];
        class_bytes.resize(128, 0);
        let v = inspect_binary_bytes(&class_bytes, "Main.class");
        assert_eq!(v.format, BinaryFormat::Unknown);
        assert!(!v.is_packed);
        assert!(!v.has_wx_violation);

        // Even with major=2 (1<=2<=16) and arbitrary class bytes, slice magics won't match Mach-O
        let mut class_v2 = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02];
        class_v2.resize(256, 0x11);
        let v2 = inspect_binary_bytes(&class_v2, "Old.class");
        assert_eq!(v2.format, BinaryFormat::Unknown);
    }

    #[test]
    fn shannon_entropy_bounds() {
        let flat = vec![0x90u8; 4096];
        assert!(shannon_entropy(&flat) < 0.01);
        let full: Vec<u8> = (0..=255).cycle().take(4096).collect();
        assert!((shannon_entropy(&full) - 8.0).abs() < 0.01);
    }
}
