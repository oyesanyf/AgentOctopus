//! Z.ai General Language Model (GLM) Hardware Calibration & Resource-Gated ModelFusion Engine
//!
//! Calibrates computers to include Z.ai GLM models as part of the multimodal ModelFusion
//! consensus panel **strictly when runtime hardware resources (free VRAM, unified memory,
//! or free system RAM) are available**.
//!
//! ### Strict Runtime Available Memory Law (Anti-OOM)
//! All sizing evaluations inspect **live runtime available memory** (`free_ram_gb` and
//! `free_vram_gb`), NEVER total physical RAM alone. If a machine has `< 6.0 GB` free VRAM
//! AND `< 8.0 GB` free system RAM, `resources_available` and `glm_activated_in_fusion`
//! evaluate to `false`, preventing GLM from being injected into the fusion panel.
//!
//! ### Z.ai Open-Weight Lineup & Memory Calibration Matrix
//! 1. **Unavailable (`free_vram_gb < 6.0 && free_ram_gb < 8.0`)**:
//!    - GLM is excluded from ModelFusion (`glm_activated_in_fusion = false`).
//! 2. **Tier 1A — 8 GB to 16 GB VRAM or Unified/Free Memory (`free_vram_gb >= 6.0 || free_ram_gb >= 8.0`)**:
//!    - Primary family: **GLM-4 9B** (`glm4:9b`, `glm-4v:9b`, `glm-4.6v-flash`) at 4-bit quantization (`Q4_K_M`),
//!      using ~5.5 GB to 8 GB of memory.
//! 3. **Tier 1B — 16 GB to 20 GB VRAM or Unified/Free Memory (`free_vram_gb >= 16.0 || free_ram_gb >= 16.0`)**:
//!    - Primary options: **GLM-4 9B** at 8-bit (`glm4:9b-chat-q8_0`) or 16-bit (`glm4:9b-chat-fp16`) precision,
//!      or a compressed 2-bit quantization of **GLM-4.7-Flash** (`glm-4.7-flash:q2_K`).
//! 4. **Tier 2 — 24 GB VRAM (RTX 3090/4090/5090) or 24 GB to 36 GB Unified/Free Memory (`free_vram_gb >= 20.0 || free_ram_gb >= 24.0`)**:
//!    - Sweet spot: **GLM-4.7-Flash** (`glm-4.7-flash:q4_K_M` / `glm-4.7-flash:latest`), MoE with 30B total
//!      parameters and ~3.6B active parameters per token (~19 GB at 4-bit quantization).
//! 5. **Tier 3 — 36 GB to 64 GB Memory (`free_vram_gb >= 36.0 || free_ram_gb >= 36.0`)**:
//!    - High-accuracy MoE: **GLM-4.7-Flash** at 8-bit (`glm-4.7-flash:q8_0`) or full 16-bit (`glm-4.7-flash:bf16`)
//!      precision for maximum coding and reasoning accuracy.
//! 6. **Tier 4 — 128 GB to 210 GB Workstation Offload (`combined_free_gb >= 128.0 || free_ram_gb >= 128.0`)**:
//!    - Supports **GLM-4.7** (355B total) at 2-bit dynamic quantization (`GLM-4.7-UD-Q2_K_XL` ~128 GB) and
//!      multimodal **GLM-5.3-Flash** (320B total / 18B active) at 1-bit quantization (`GLM-5.3-Flash-UD-IQ1_M` ~128 GB),
//!      while pairing **GLM-4.7-Flash** (`glm-4.7-flash:q8_0` / `glm-4.7-flash:q4_K_M`, 30B/3.6B active MoE) and
//!      in-VRAM **GLM-4 9B** (`glm4:9b`) for low-latency interactive fusion.
//! 7. **Tier 5 — 210 GB to 245 GB Heavy Workstation (`combined_free_gb >= 210.0 || free_ram_gb >= 210.0`)**:
//!    - Supports full **GLM-4.7** (355B total) at standard 4-bit quantization (`GLM-4.7-Q4_K_M` ~210 GB).
//! 8. **Tier 6 — 245 GB to 256+ GB Frontier Workstation / Cluster (`combined_free_gb >= 245.0 || free_ram_gb >= 245.0`)**:
//!    - Supports frontier **GLM-5.1 / GLM-5.2 / GLM-5.3** (744B–753B total / 40B active per token) at 1-bit/2-bit
//!      Unsloth dynamic quantization (`GLM-5.3-UD-Q2_K_XL` ~245–256 GB) and **GLM-5.3-Flash** (320B total / 18B active)
//!      at reliable 4-bit quantization (`GLM-5.3-Flash-Q4_K_M`).

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::Command;
use std::time::Duration;

/// Live hardware and memory telemetry used for GLM calibration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlmHardwareSpec {
    pub cpu_name: String,
    pub cpu_cores: usize,
    pub logical_processors: usize,
    pub total_ram_gb: f64,
    pub free_ram_gb: f64,
    pub gpu_name: Option<String>,
    pub total_vram_gb: f64,
    pub free_vram_gb: f64,
    pub free_vram_mb: u64,
    pub installed_ollama_models: Vec<String>,
}

impl GlmHardwareSpec {
    /// Combined runtime available memory across system RAM and dedicated GPU VRAM.
    pub fn combined_free_memory_gb(&self) -> f64 {
        self.free_ram_gb + self.free_vram_gb
    }

    /// Probes live system CPU, runtime free/total RAM, GPU VRAM, and installed Ollama tags.
    pub fn detect_live() -> Self {
        let (total_ram_gb, free_ram_gb) = detect_system_memory_gb();
        let (cpu_name, cpu_cores, logical_processors) = detect_cpu_topology();
        let (gpu_name, total_vram_gb, free_vram_gb, free_vram_mb) = detect_gpu_vram();
        let installed_ollama_models = probe_ollama_installed_tags_fast();

        Self {
            cpu_name,
            cpu_cores,
            logical_processors,
            total_ram_gb,
            free_ram_gb,
            gpu_name,
            total_vram_gb,
            free_vram_gb,
            free_vram_mb,
            installed_ollama_models,
        }
    }
}

/// Z.ai GLM hardware capability tiers calibrated strictly by runtime available memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GlmModelTier {
    /// `< 6.0 GB` free VRAM and `< 8.0 GB` free RAM: GLM disabled to prevent OOM.
    Unavailable,
    /// 8–16 GB VRAM or Unified/Free Memory: `GLM-4-9B` / `GLM-4V-9B` / `GLM-4.6V-Flash` (4-bit Q4_K_M).
    Tier1AGlm4_9bQ4,
    /// 16–20 GB VRAM or Unified/Free Memory: `GLM-4-9B` (8-bit/16-bit) or `GLM-4.7-Flash` (2-bit Q2_K).
    Tier1BGlm4_9bQ8OrGlm47FlashQ2,
    /// 24 GB VRAM (RTX 3090/4090/5090) or 24–36 GB Unified/Free Memory: `GLM-4.7-Flash` (30B/3.6B MoE 4-bit Q4_K_M).
    Tier2Glm47FlashQ4,
    /// 36–64 GB Memory: `GLM-4.7-Flash` (30B/3.6B MoE at 8-bit Q8_0 or full 16-bit BF16/FP16).
    Tier3Glm47FlashQ8OrFp16,
    /// 128–210 GB Workstation Offload: `GLM-4.7` (355B 2-bit ~128GB) / `GLM-5.3-Flash` (320B/18B 1-bit ~128GB) + `GLM-4.7-Flash` & `GLM-4-9B`.
    Tier4Workstation128GbOffload,
    /// 210–245 GB Heavy Workstation: `GLM-4.7` (355B 4-bit Q4_K_M ~210GB).
    Tier5Workstation210GbGlm47Q4,
    /// 245–256+ GB Frontier Workstation/Cluster: `GLM-5.1` / `GLM-5.2` / `GLM-5.3` (744B–753B/40B 1-bit/2-bit) & `GLM-5.3-Flash` (4-bit).
    Tier6Frontier256GbGlm5,
}

/// Complete calibration verdict for Z.ai GLM integration inside ModelFusion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlmFusionCalibrationReport {
    pub resources_available: bool,
    pub glm_activated_in_fusion: bool,
    pub tier: GlmModelTier,
    pub tier_label: String,
    pub active_fusion_glm_model: Option<String>,
    pub recommended_vram_sweet_spot_tag: Option<String>,
    pub recommended_moe_offload_tag: Option<String>,
    pub max_workstation_flagship_build: Option<String>,
    pub recommended_gguf_quantization: Option<String>,
    pub multimodal_variant_tag: Option<String>,
    pub total_params_b: f64,
    pub active_params_b: f64,
    pub estimated_memory_gb: f64,
    pub fusion_panel_models: Vec<String>,
    pub hardware: GlmHardwareSpec,
    pub rationale: String,
}

/// Calibrates the optimal Z.ai GLM model build, quantization file, and ModelFusion panel
/// participation based strictly on live runtime free VRAM and free system RAM.
pub fn calibrate_glm_for_hardware(hw: &GlmHardwareSpec) -> GlmFusionCalibrationReport {
    let free_vram = hw.free_vram_gb;
    let free_ram = hw.free_ram_gb;
    let combined_free = hw.combined_free_memory_gb();

    // Strict Anti-OOM Gate: GLM requires at least 6.0 GB of free VRAM (for 5.5 GB Q4_K_M 9B)
    // or 8.0 GB of free system/unified RAM.
    let resources_available = free_vram >= 6.0 || free_ram >= 8.0;
    if !resources_available {
        return GlmFusionCalibrationReport {
            resources_available: false,
            glm_activated_in_fusion: false,
            tier: GlmModelTier::Unavailable,
            tier_label: "Tier 0: Insufficient Runtime Memory (< 6 GB Free VRAM & < 8 GB Free RAM — GLM Disabled)".to_string(),
            active_fusion_glm_model: None,
            recommended_vram_sweet_spot_tag: None,
            recommended_moe_offload_tag: None,
            max_workstation_flagship_build: None,
            recommended_gguf_quantization: None,
            multimodal_variant_tag: None,
            total_params_b: 0.0,
            active_params_b: 0.0,
            estimated_memory_gb: 0.0,
            fusion_panel_models: vec!["qwen2.5:1.5b".to_string(), "deepseek-r1:1.5b".to_string()],
            hardware: hw.clone(),
            rationale: format!(
                "GLM fusion is disabled because runtime available memory (Free RAM: {:.2} GB, Free VRAM: {:.2} GB) is below the 8 GB RAM / 6 GB VRAM minimum required for GLM-4 9B Q4.",
                free_ram, free_vram
            ),
        };
    }

    // Determine the pure-VRAM sweet spot when a dedicated GPU is present
    let vram_sweet_spot = if free_vram >= 36.0 {
        Some("glm-4.7-flash:q8_0".to_string())
    } else if free_vram >= 20.0 {
        Some("glm-4.7-flash:q4_K_M".to_string())
    } else if free_vram >= 16.0 {
        Some("glm4:9b-chat-q8_0".to_string())
    } else if free_vram >= 6.0 {
        Some("glm4:9b".to_string())
    } else {
        None
    };

    // Determine tier by evaluating combined/free memory and VRAM
    let (
        tier,
        tier_label,
        recommended_moe_offload_tag,
        max_workstation_flagship_build,
        recommended_gguf_quantization,
        multimodal_variant_tag,
        total_params_b,
        active_params_b,
        estimated_memory_gb,
        rationale,
    ) = if combined_free >= 245.0 || free_ram >= 245.0 {
        (
            GlmModelTier::Tier6Frontier256GbGlm5,
            "Tier 6: Frontier 256 GB+ Workstation/Cluster (GLM-5.3 / GLM-5.2 / GLM-5.1 744B-753B MoE & GLM-5.3-Flash 4-bit)".to_string(),
            Some("glm-4.7-flash:bf16".to_string()),
            Some("zai-org/GLM-5.3 (Unsloth UD-Q2_K_XL) & zai-org/GLM-5.3-Flash (Q4_K_M)".to_string()),
            Some("GLM-5.3-UD-Q2_K_XL.gguf (245 GB) / GLM-5.3-Flash-Q4_K_M.gguf (190 GB)".to_string()),
            Some("glm-5.3-flash".to_string()),
            753.0,
            40.0,
            245.0,
            format!(
                "Detected {:.2} GB combined free memory ({:.2} GB free RAM + {:.2} GB free VRAM): capable of running frontier GLM-5.1/5.2/5.3 (744B-753B total / 40B active) at 1-bit/2-bit dynamic quantization and GLM-5.3-Flash (320B total / 18B active) at 4-bit quantization.",
                combined_free, free_ram, free_vram
            ),
        )
    } else if combined_free >= 210.0 || free_ram >= 210.0 {
        (
            GlmModelTier::Tier5Workstation210GbGlm47Q4,
            "Tier 5: Heavy 210 GB+ Workstation (GLM-4.7 355B 4-bit + GLM-4.7-Flash 30B-A3.6B MoE)".to_string(),
            Some("glm-4.7-flash:bf16".to_string()),
            Some("zai-org/GLM-4.7 (355B 4-bit Q4_K_M ~210 GB)".to_string()),
            Some("GLM-4.7-Q4_K_M.gguf (~210 GB) / GLM-4.7-Flash-Q8_0.gguf (~32 GB)".to_string()),
            Some("glm-5.3-flash:iq1_m".to_string()),
            355.0,
            32.0,
            210.0,
            format!(
                "Detected {:.2} GB combined free memory ({:.2} GB free RAM + {:.2} GB free VRAM): supports full GLM-4.7 (355B) at 4-bit quantization (~210 GB) and GLM-4.7-Flash (30B/3.6B active MoE) at full precision.",
                combined_free, free_ram, free_vram
            ),
        )
    } else if combined_free >= 128.0 || free_ram >= 128.0 {
        // Workstation 128GB+ Tier (Matches Dell Precision 7920 Tower: Dual Xeon Gold 6154 36C/72T + 223.65 GB RAM / ~176 GB Free RAM + Quadro RTX 4000 8 GB VRAM)
        (
            GlmModelTier::Tier4Workstation128GbOffload,
            "Tier 4: 128 GB+ Workstation CPU+GPU Offload (GLM-4.7-Flash 30B-A3.6B MoE + In-VRAM GLM-4 9B + GLM-4.7 355B Q2_K / GLM-5.3-Flash IQ1_M)".to_string(),
            Some("glm-4.7-flash:q8_0".to_string()),
            Some("zai-org/GLM-4.7 (355B 2-bit UD-Q2_K_XL ~128 GB) / zai-org/GLM-5.3-Flash (320B/18B 1-bit UD-IQ1_M ~128 GB)".to_string()),
            Some(if free_vram >= 6.0 && free_vram < 16.0 {
                "glm4:9b (5.5 GB 100% in-VRAM Q4_K_M) + glm-4.7-flash:q4_K_M (19 GB MoE 3.6B active CPU+GPU offload) + GLM-4.7-UD-Q2_K_XL.gguf (~128 GB)".to_string()
            } else {
                "glm-4.7-flash:q8_0 (32 GB MoE 3.6B active) + GLM-4.7-UD-Q2_K_XL.gguf (~128 GB)".to_string()
            }),
            Some("glm-4v:9b / glm-5.3-flash:iq1_m".to_string()),
            30.0,
            3.6,
            19.0,
            format!(
                "Workstation calibration ({:.2} GB free RAM + {:.2} GB free VRAM on {}): \
                (1) 100% In-VRAM Fast Specialist: `glm4:9b` (5.5 GB Q4_K_M fits completely inside {:.1} GB VRAM); \
                (2) High-Speed MoE Sweet Spot: `glm-4.7-flash` (30B total / 3.6B active per token at Q4_K_M 19 GB or Q8_0 32 GB via Xeon + GPU offload); \
                (3) Maximum Workstation Capacity: `GLM-4.7` (355B 2-bit dynamic quantization ~128 GB) or `GLM-5.3-Flash` (320B/18B 1-bit quantization ~128 GB).",
                free_ram, free_vram, hw.cpu_name, hw.total_vram_gb.max(free_vram)
            ),
        )
    } else if free_vram >= 36.0 || free_ram >= 36.0 {
        (
            GlmModelTier::Tier3Glm47FlashQ8OrFp16,
            "Tier 3: 36 GB to 64 GB Memory (GLM-4.7-Flash 30B-A3.6B MoE at 8-bit Q8_0 / 16-bit BF16)".to_string(),
            Some("glm-4.7-flash:q8_0".to_string()),
            Some("zai-org/GLM-4.7-Flash (Q8_0 / BF16)".to_string()),
            Some("GLM-4.7-Flash-Q8_0.gguf (~32 GB) / glm-4.7-flash:q8_0".to_string()),
            Some("glm-4v:9b".to_string()),
            30.0,
            3.6,
            32.0,
            format!(
                "Detected {:.2} GB free RAM / {:.2} GB free VRAM (36-64 GB tier): calibrated for GLM-4.7-Flash (30B total / 3.6B active MoE) at 8-bit (Q8_0) or full precision for maximum coding and reasoning accuracy.",
                free_ram, free_vram
            ),
        )
    } else if free_vram >= 20.0 || free_ram >= 24.0 {
        (
            GlmModelTier::Tier2Glm47FlashQ4,
            "Tier 2: 24 GB VRAM / 24-36 GB Memory Sweet Spot (GLM-4.7-Flash 30B-A3.6B MoE 4-bit Q4_K_M)".to_string(),
            Some("glm-4.7-flash:q4_K_M".to_string()),
            Some("zai-org/GLM-4.7-Flash (4-bit Q4_K_M ~19 GB)".to_string()),
            Some("GLM-4.7-Flash-Q4_K_M.gguf (19 GB) / glm-4.7-flash:latest".to_string()),
            Some("glm-4v:9b".to_string()),
            30.0,
            3.6,
            19.0,
            format!(
                "Detected {:.2} GB free RAM / {:.2} GB free VRAM (24-36 GB tier): sweet spot is GLM-4.7-Flash (30B total / 3.6B active MoE at 4-bit Q4_K_M, ~19 GB).",
                free_ram, free_vram
            ),
        )
    } else if free_vram >= 16.0 || free_ram >= 16.0 {
        (
            GlmModelTier::Tier1BGlm4_9bQ8OrGlm47FlashQ2,
            "Tier 1B: 16 GB to 20 GB Memory (GLM-4 9B at 8-bit/16-bit or GLM-4.7-Flash 2-bit Q2_K)".to_string(),
            Some("glm-4.7-flash:q2_K".to_string()),
            Some("zai-org/GLM-4-9B-0414 (Q8_0 / FP16) or zai-org/GLM-4.7-Flash (Q2_K)".to_string()),
            Some("glm4:9b-chat-q8_0 (~10 GB) / GLM-4.7-Flash-Q2_K.gguf (~12 GB)".to_string()),
            Some("glm-4v:9b".to_string()),
            9.0,
            9.0,
            10.0,
            format!(
                "Detected {:.2} GB free RAM / {:.2} GB free VRAM (16-20 GB tier): calibrated for GLM-4 9B at 8-bit/16-bit precision or 2-bit GLM-4.7-Flash.",
                free_ram, free_vram
            ),
        )
    } else {
        (
            GlmModelTier::Tier1AGlm4_9bQ4,
            "Tier 1A: 8 GB to 16 GB Memory (GLM-4 9B / GLM-4V 9B / GLM-4.6V-Flash 4-bit Q4_K_M)".to_string(),
            Some("glm4:9b".to_string()),
            Some("zai-org/GLM-4-9B-0414 (4-bit Q4_K_M ~5.5-8 GB)".to_string()),
            Some("glm4:9b / glm4:9b-chat-q4_K_M (5.5 GB)".to_string()),
            Some("glm-4.6v-flash / glm-4v:9b".to_string()),
            9.0,
            9.0,
            6.5,
            format!(
                "Detected {:.2} GB free RAM / {:.2} GB free VRAM (8-16 GB tier): calibrated for GLM-4 9B family (glm4:9b, glm-4v:9b, glm-4.6v-flash) at 4-bit quantization (~5.5-8 GB).",
                free_ram, free_vram
            ),
        )
    };

    // Select the active GLM tag for immediate ModelFusion execution:
    // Prefer an already-installed Ollama GLM tag that fits runtime memory, otherwise use the calibrated tag.
    let active_fusion_glm_model = select_active_installed_or_calibrated_glm(
        &hw.installed_ollama_models,
        &vram_sweet_spot,
        &recommended_moe_offload_tag,
    );

    let mut fusion_panel_models = Vec::new();
    fusion_panel_models.push("flint:latest".to_string());
    if let Some(ref glm_tag) = active_fusion_glm_model {
        fusion_panel_models.push(glm_tag.clone());
    }
    if free_ram >= 48.0 || free_vram >= 22.0 {
        fusion_panel_models.push("qwen2.5:32b".to_string());
        fusion_panel_models.push("deepseek-r1:32b".to_string());
        fusion_panel_models.push("gemma2:9b".to_string());
    } else if free_ram >= 12.0 || free_vram >= 5.0 {
        fusion_panel_models.push("qwen2.5:7b".to_string());
        fusion_panel_models.push("gemma2:9b".to_string());
        fusion_panel_models.push("deepseek-r1:1.5b".to_string());
    } else {
        fusion_panel_models.push("qwen2.5:3b".to_string());
        fusion_panel_models.push("deepseek-r1:1.5b".to_string());
    }

    GlmFusionCalibrationReport {
        resources_available: true,
        glm_activated_in_fusion: true,
        tier,
        tier_label,
        active_fusion_glm_model,
        recommended_vram_sweet_spot_tag: vram_sweet_spot,
        recommended_moe_offload_tag,
        max_workstation_flagship_build,
        recommended_gguf_quantization,
        multimodal_variant_tag,
        total_params_b,
        active_params_b,
        estimated_memory_gb,
        fusion_panel_models,
        hardware: hw.clone(),
        rationale,
    }
}

fn select_active_installed_or_calibrated_glm(
    installed: &[String],
    vram_sweet_spot: &Option<String>,
    moe_offload_tag: &Option<String>,
) -> Option<String> {
    // 1. Check if any GLM model is already installed in Ollama
    let preferred_order = [
        "glm-4.7-flash:q8_0",
        "glm-4.7-flash:q4_K_M",
        "glm-4.7-flash:latest",
        "glm4:9b",
        "glm4:latest",
        "glm-4v:9b",
    ];
    for pref in preferred_order {
        if let Some(found) = installed.iter().find(|t| t.eq_ignore_ascii_case(pref)) {
            return Some(found.clone());
        }
    }
    if let Some(any_glm) = installed
        .iter()
        .find(|t| t.to_ascii_lowercase().starts_with("glm"))
    {
        return Some(any_glm.clone());
    }

    // 2. Otherwise prefer VRAM sweet spot (e.g., glm4:9b for 8GB GPU) or MoE offload tag
    if let Some(ref vram_tag) = vram_sweet_spot {
        return Some(vram_tag.clone());
    }
    if let Some(ref moe_tag) = moe_offload_tag {
        return Some(moe_tag.clone());
    }
    Some("glm4:9b".to_string())
}

fn create_no_window_cmd(program: &str) -> Command {
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    cmd
}

fn detect_system_memory_gb() -> (f64, f64) {
    #[cfg(windows)]
    {
        #[repr(C)]
        struct MemoryStatusEx {
            dw_length: u32,
            dw_memory_load: u32,
            ull_total_phys: u64,
            ull_avail_phys: u64,
            ull_total_page_file: u64,
            ull_avail_page_file: u64,
            ull_total_virtual: u64,
            ull_avail_virtual: u64,
            ull_avail_extended_virtual: u64,
        }
        extern "system" {
            fn GlobalMemoryStatusEx(lp_buffer: *mut MemoryStatusEx) -> i32;
        }
        let mut status = MemoryStatusEx {
            dw_length: std::mem::size_of::<MemoryStatusEx>() as u32,
            dw_memory_load: 0,
            ull_total_phys: 0,
            ull_avail_phys: 0,
            ull_total_page_file: 0,
            ull_avail_page_file: 0,
            ull_total_virtual: 0,
            ull_avail_virtual: 0,
            ull_avail_extended_virtual: 0,
        };
        // SAFETY: `status` is properly initialized with `dw_length = sizeof(MEMORYSTATUSEX)`.
        let ok = unsafe { GlobalMemoryStatusEx(&mut status) };
        if ok != 0 && status.ull_total_phys > 0 {
            let total_gb = status.ull_total_phys as f64 / 1_073_741_824.0;
            let free_gb = status.ull_avail_phys as f64 / 1_073_741_824.0;
            return (total_gb, free_gb);
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
            let mut total_kb = 0u64;
            let mut avail_kb = 0u64;
            for line in meminfo.lines() {
                if line.starts_with("MemTotal:") {
                    total_kb = line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                } else if line.starts_with("MemAvailable:") {
                    avail_kb = line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                }
            }
            if total_kb > 0 {
                return (
                    total_kb as f64 / 1_048_576.0,
                    avail_kb as f64 / 1_048_576.0,
                );
            }
        }
    }
    (16.0, 8.0)
}

fn detect_cpu_topology() -> (String, usize, usize) {
    let logical = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    #[cfg(windows)]
    {
        if let Ok(out) = create_no_window_cmd("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "$p = @(Get-CimInstance Win32_Processor); $name = ($p | Select-Object -First 1).Name; $cores = ($p | Measure-Object -Property NumberOfCores -Sum).Sum; Write-Output \"$name|$cores\"",
            ])
            .output()
        {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                let line = s.trim();
                if let Some((name, cores_str)) = line.split_once('|') {
                    let cores = cores_str.trim().parse::<usize>().unwrap_or(logical / 2).max(1);
                    let count_sockets = line.matches("Xeon").count().max(1);
                    let _ = count_sockets;
                    return (name.trim().to_string(), cores, logical);
                }
            }
        }
    }
    ("x86_64 Processor".to_string(), (logical / 2).max(1), logical)
}

fn detect_gpu_vram() -> (Option<String>, f64, f64, u64) {
    if let Ok(out) = create_no_window_cmd("nvidia-smi")
        .args([
            "--query-gpu=name,memory.total,memory.free",
            "--format=csv,noheader,nounits",
        ])
        .output()
    {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if let Some(first_line) = stdout.lines().next() {
                let parts: Vec<&str> = first_line.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 3 {
                    let name = parts[0].to_string();
                    let total_mb: f64 = parts[1].parse().unwrap_or(0.0);
                    let free_mb: f64 = parts[2].parse().unwrap_or(0.0);
                    return (
                        Some(name),
                        total_mb / 1024.0,
                        free_mb / 1024.0,
                        free_mb.max(0.0) as u64,
                    );
                }
            }
        }
    }
    (None, 0.0, 0.0, 0)
}

/// Probes `http://127.0.0.1:11434/api/tags` with a strict 400ms timeout in compliance
/// with the Computer Use & Ollama Lifecycle Resilience rule.
pub fn probe_ollama_installed_tags_fast() -> Vec<String> {
    let addr: SocketAddr = match "127.0.0.1:11434".parse() {
        Ok(a) => a,
        Err(_) => return Vec::new(),
    };
    let timeout = Duration::from_millis(400);
    let mut stream = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let req = b"GET /api/tags HTTP/1.1\r\nHost: 127.0.0.1:11434\r\nConnection: close\r\n\r\n";
    if stream.write_all(req).is_err() {
        return Vec::new();
    }
    let mut buf = Vec::with_capacity(8192);
    let _ = stream.read_to_end(&mut buf);
    let raw = String::from_utf8_lossy(&buf);
    let body = match raw.split_once("\r\n\r\n") {
        Some((_, b)) => b.trim(),
        None => return Vec::new(),
    };
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(models) = val.get("models").and_then(|m| m.as_array()) {
            return models
                .iter()
                .filter_map(|m| m.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()))
                .collect();
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glm_disabled_when_runtime_resources_insufficient() {
        // Anti-OOM Law: Even if total RAM is 64 GB and total VRAM is 16 GB,
        // if runtime FREE RAM is 4.5 GB and FREE VRAM is 2.0 GB, GLM must NOT activate in fusion.
        let low_free_hw = GlmHardwareSpec {
            cpu_name: "Test Laptop CPU".to_string(),
            cpu_cores: 8,
            logical_processors: 16,
            total_ram_gb: 64.0,
            free_ram_gb: 4.5,
            gpu_name: Some("Busy GPU".to_string()),
            total_vram_gb: 16.0,
            free_vram_gb: 2.0,
            free_vram_mb: 2048,
            installed_ollama_models: vec!["glm4:9b".to_string(), "qwen2.5:1.5b".to_string()],
        };
        let report = calibrate_glm_for_hardware(&low_free_hw);
        assert!(!report.resources_available);
        assert!(!report.glm_activated_in_fusion);
        assert_eq!(report.tier, GlmModelTier::Unavailable);
        assert!(report.active_fusion_glm_model.is_none());
        assert!(!report.fusion_panel_models.iter().any(|m| m.contains("glm")));
    }

    #[test]
    fn test_glm_tier_1a_8_to_16gb_laptop() {
        let hw = GlmHardwareSpec {
            cpu_name: "Core i7".to_string(),
            cpu_cores: 8,
            logical_processors: 16,
            total_ram_gb: 16.0,
            free_ram_gb: 10.5,
            gpu_name: Some("RTX 4060".to_string()),
            total_vram_gb: 8.0,
            free_vram_gb: 6.8,
            free_vram_mb: 6963,
            installed_ollama_models: vec!["glm4:9b".to_string()],
        };
        let report = calibrate_glm_for_hardware(&hw);
        assert!(report.resources_available);
        assert!(report.glm_activated_in_fusion);
        assert_eq!(report.tier, GlmModelTier::Tier1AGlm4_9bQ4);
        assert_eq!(report.active_fusion_glm_model.as_deref(), Some("glm4:9b"));
    }

    #[test]
    fn test_glm_tier_2_24gb_rtx_sweet_spot() {
        let hw = GlmHardwareSpec {
            cpu_name: "Ryzen 9".to_string(),
            cpu_cores: 16,
            logical_processors: 32,
            total_ram_gb: 32.0,
            free_ram_gb: 26.0,
            gpu_name: Some("NVIDIA GeForce RTX 4090".to_string()),
            total_vram_gb: 24.0,
            free_vram_gb: 22.5,
            free_vram_mb: 23040,
            installed_ollama_models: vec!["glm-4.7-flash:q4_K_M".to_string()],
        };
        let report = calibrate_glm_for_hardware(&hw);
        assert!(report.resources_available);
        assert!(report.glm_activated_in_fusion);
        assert_eq!(report.tier, GlmModelTier::Tier2Glm47FlashQ4);
        assert_eq!(
            report.active_fusion_glm_model.as_deref(),
            Some("glm-4.7-flash:q4_K_M")
        );
        assert_eq!(report.total_params_b, 30.0);
        assert_eq!(report.active_params_b, 3.6);
    }

    #[test]
    fn test_glm_tier_4_this_workstation_precision_7920() {
        // Exact profile of this machine: Dual Intel Xeon Gold 6154 (36C/72T),
        // 223.65 GB Total RAM (~176 GB Free RAM), Quadro RTX 4000 (8 GB VRAM, ~6.6 GB Free VRAM).
        let hw = GlmHardwareSpec {
            cpu_name: "Intel(R) Xeon(R) Gold 6154 CPU @ 3.00GHz".to_string(),
            cpu_cores: 36,
            logical_processors: 72,
            total_ram_gb: 223.65,
            free_ram_gb: 176.4,
            gpu_name: Some("Quadro RTX 4000".to_string()),
            total_vram_gb: 8.0,
            free_vram_gb: 6.6,
            free_vram_mb: 6754,
            installed_ollama_models: vec!["glm4:9b".to_string(), "qwen2.5:32b".to_string()],
        };
        let report = calibrate_glm_for_hardware(&hw);
        assert!(report.resources_available);
        assert!(report.glm_activated_in_fusion);
        assert_eq!(report.tier, GlmModelTier::Tier4Workstation128GbOffload);
        assert_eq!(
            report.recommended_vram_sweet_spot_tag.as_deref(),
            Some("glm4:9b")
        );
        assert_eq!(
            report.recommended_moe_offload_tag.as_deref(),
            Some("glm-4.7-flash:q8_0")
        );
        assert!(report
            .max_workstation_flagship_build
            .as_deref()
            .unwrap_or("")
            .contains("GLM-4.7"));
        assert!(report
            .fusion_panel_models
            .contains(&"glm4:9b".to_string()));
    }

    #[test]
    fn test_glm_tier_6_frontier_256gb_workstation() {
        let hw = GlmHardwareSpec {
            cpu_name: "Threadripper PRO".to_string(),
            cpu_cores: 64,
            logical_processors: 128,
            total_ram_gb: 512.0,
            free_ram_gb: 320.0,
            gpu_name: Some("RTX 5090".to_string()),
            total_vram_gb: 32.0,
            free_vram_gb: 30.0,
            free_vram_mb: 30720,
            installed_ollama_models: vec![],
        };
        let report = calibrate_glm_for_hardware(&hw);
        assert!(report.resources_available);
        assert!(report.glm_activated_in_fusion);
        assert_eq!(report.tier, GlmModelTier::Tier6Frontier256GbGlm5);
        assert_eq!(report.total_params_b, 753.0);
        assert_eq!(report.active_params_b, 40.0);
    }
}
