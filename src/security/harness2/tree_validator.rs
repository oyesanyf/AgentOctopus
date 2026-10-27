use super::types::{HarnessSurfaceSpec, HarnessTreeValidationReport};
use crate::security::evolution::{SecurityAuditResult, SecurityInvariantGuard};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Grader verdict tripwire markers from Google Research Harness² (`core/context.py`).
pub const GRADER_VERDICT_MARKERS: &[&str] = &[
    "deterministic_eval_summary",
    "deterministic_eval_result",
    "judge_scope_and_deterministic_status",
    "Judge findings on the rendered result",
    "\"passed_count\"",
    "\"pass_rate\"",
    "\"test_pass_rate\"",
];

pub struct HarnessTreeValidator;

impl HarnessTreeValidator {
    /// Normalizes a relative path, strictly rejecting escapes, drive letters, and percent-encoded traversals.
    pub fn normalize_rel(rel: &str) -> Result<String, String> {
        let trimmed = rel.trim();
        if trimmed.is_empty() {
            return Err("empty relative path".to_string());
        }
        let lower = trimmed.to_ascii_lowercase();
        if trimmed.contains(':')
            || trimmed.starts_with('/')
            || trimmed.starts_with('\\')
            || lower.contains("%2e")
            || lower.contains("%2f")
            || lower.contains("%5c")
            || lower.contains("%00")
        {
            return Err(format!("path escapes the harness: {:?}", rel));
        }

        let mut normalized = trimmed.replace('\\', "/");
        while normalized.starts_with("./") {
            normalized = normalized[2..].to_string();
        }
        normalized = normalized.trim_matches('/').to_string();
        if normalized
            .split('/')
            .any(|seg| seg == ".." || seg.is_empty())
        {
            return Err(format!("path escapes the harness: {:?}", rel));
        }
        Ok(normalized)
    }

    fn is_valid_slug(name: &str) -> bool {
        let mut chars = name.chars();
        match chars.next() {
            Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
            _ => return false,
        }
        chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    }

    /// Checks whether a normalized relative path belongs to the c1..c8 editable surface.
    pub fn is_allowed(surface: &HarnessSurfaceSpec, rel: &str) -> bool {
        let norm = match Self::normalize_rel(rel) {
            Ok(n) => n,
            Err(_) => return false,
        };
        if surface.always_on.iter().any(|a| a == &norm) {
            return true;
        }
        let parts: Vec<&str> = norm.split('/').collect();
        // c6: skills/<name>/SKILL.md or skills/<name>/scripts/<file>
        if parts.len() == 3 && parts[0] == surface.skill_dir && parts[2] == "SKILL.md" {
            return Self::is_valid_slug(parts[1]);
        }
        if parts.len() == 4 && parts[0] == surface.skill_dir && parts[2] == "scripts" {
            let fname = parts[3];
            return Self::is_valid_slug(parts[1])
                && !fname.is_empty()
                && !fname.starts_with('.')
                && fname
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.');
        }
        // c5: sub_agents/<name>/AGENT.md
        if parts.len() == 3 && parts[0] == "sub_agents" && parts[2] == "AGENT.md" {
            return Self::is_valid_slug(parts[1]);
        }
        // c7: scripts/<name>.py
        if parts.len() == 2 && parts[0] == "scripts" && parts[1].ends_with(".py") {
            let stem = &parts[1][..parts[1].len() - 3];
            return !stem.is_empty()
                && stem
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        }
        // c8: plugin/<name>.ts
        if let Some(ref pdir) = surface.plugin_dir {
            if parts.len() == 2 && parts[0] == pdir && parts[1].ends_with(".ts") {
                let stem = &parts[1][..parts[1].len() - 3];
                return Self::is_valid_slug(stem);
            }
        }
        false
    }

    /// Extracts skill names present in the tree (`skills/<name>/SKILL.md`).
    pub fn skill_names(
        surface: &HarnessSurfaceSpec,
        tree: &BTreeMap<String, String>,
    ) -> Vec<String> {
        let mut names = Vec::new();
        for key in tree.keys() {
            let parts: Vec<&str> = key.split('/').collect();
            if parts.len() == 3
                && parts[0] == surface.skill_dir
                && parts[2] == "SKILL.md"
                && Self::is_valid_slug(parts[1])
            {
                names.push(parts[1].to_string());
            }
        }
        names.sort();
        names.dedup();
        names
    }

    /// Concatenates the always-on c1..c4 files.
    pub fn always_on_text(surface: &HarnessSurfaceSpec, tree: &BTreeMap<String, String>) -> String {
        surface
            .always_on
            .iter()
            .map(|a| tree.get(a).map(|s| s.as_str()).unwrap_or(""))
            .collect::<Vec<&str>>()
            .join("\n\n")
    }

    /// Automatically repairs missing skill trigger lines in `guardrails.md` without exceeding `always_on_max`.
    pub fn autotrigger(
        surface: &HarnessSurfaceSpec,
        tree: &mut BTreeMap<String, String>,
    ) -> Vec<String> {
        let mut fixed = Vec::new();
        let skills = Self::skill_names(surface, tree);
        let mut body = Self::always_on_text(surface, tree);

        for name in skills {
            if body.contains(&name) {
                continue;
            }
            let skill_path = format!("{}/{}/SKILL.md", surface.skill_dir, name);
            let fm = tree.get(&skill_path).cloned().unwrap_or_default();
            let desc = fm
                .lines()
                .find_map(|line| {
                    line.strip_prefix("description:")
                        .map(|d| d.trim().trim_end_matches('.'))
                })
                .unwrap_or("the workflow applies");
            let trigger_line = format!("- When {}, load the `{}` skill.", desc, name);
            let cur = tree
                .get(&surface.autotrigger_file)
                .cloned()
                .unwrap_or_default();
            if body.len() + trigger_line.len() + 2 > surface.always_on_max {
                continue;
            }
            let updated = if cur.trim().is_empty() {
                trigger_line
            } else {
                format!("{}\n{}", cur.trim_end(), trigger_line)
            };
            tree.insert(surface.autotrigger_file.clone(), updated);
            body = Self::always_on_text(surface, tree);
            fixed.push(name);
        }
        fixed
    }

    /// Enforces the Jinja safety invariant for `home_dir_jinja` templates (`opencode.py`).
    pub fn check_jinja_safe(composed: &str) -> bool {
        if !composed.contains("{{ instruction }}") {
            // If not using a home_dir_jinja template, ensure no raw Jinja injection blocks exist
            return !composed.contains("{%") && !composed.contains("{#");
        }
        let count = composed.matches("{{ instruction }}").count();
        if count != 1 {
            return false;
        }
        let without = composed.replacen("{{ instruction }}", "", 1);
        !without.contains("{{")
            && !without.contains("{%")
            && !without.contains("{#")
            && composed.trim_end().ends_with("{{ instruction }}")
    }

    /// Validates a candidate c1..c8 harness tree against all Harness² surface rules and Ring-2 AST guards.
    pub fn validate_tree(
        surface: &HarnessSurfaceSpec,
        tree: &mut BTreeMap<String, String>,
    ) -> HarnessTreeValidationReport {
        let mut errors = Vec::new();
        let mut rejected_off_surface = Vec::new();

        // 1. Check surface membership & reserved scripts
        let keys: Vec<String> = tree.keys().cloned().collect();
        for key in &keys {
            if !Self::is_allowed(surface, key) {
                rejected_off_surface.push(key.clone());
                errors.push(format!("Off-surface file rejected: '{}'", key));
            }
            if let Some(script_name) = key.strip_prefix("scripts/") {
                if surface.reserved_scripts.iter().any(|r| r == script_name) {
                    errors.push(format!(
                        "scripts/{} is reserved by the benchmark runner",
                        script_name
                    ));
                }
            }
        }

        // 2. Autotrigger repair for skills
        let auto_triggered_skills = Self::autotrigger(surface, tree);

        // 3. Check always-on character cap
        let always_on = Self::always_on_text(surface, tree);
        let always_on_chars = always_on.len();
        if always_on_chars > surface.always_on_max {
            errors.push(format!(
                "Always-on text is {} chars > {} max ({})",
                always_on_chars, surface.always_on_max, surface.always_on_cap_reason
            ));
        }

        // 4. Check Grader Verdict leak tripwire
        let mut grader_leak_detected = false;
        for (rel, content) in tree.iter() {
            for &marker in GRADER_VERDICT_MARKERS {
                if rel.contains(marker) || content.contains(marker) {
                    grader_leak_detected = true;
                    errors.push(format!(
                        "Grader verdict marker '{}' detected in '{}'",
                        marker, rel
                    ));
                }
            }
        }

        // 5. Check Jinja safety
        let jinja_safe = Self::check_jinja_safe(&always_on);
        if !jinja_safe {
            errors.push("Unsafe Jinja brace sequence detected in always-on text".to_string());
        }

        // 6. Audit all Python scripts (c7 & c6 skill scripts) via Ring-2 SecurityInvariantGuard
        let mut combined_violations = Vec::new();
        let mut total_tokens = 0usize;
        for (rel, content) in tree.iter() {
            if rel.ends_with(".py") {
                let audit = SecurityInvariantGuard::audit_code(content);
                total_tokens += audit.audited_tokens;
                if !audit.passed {
                    for v in audit.violations {
                        let msg = format!("{}: {}", rel, v);
                        combined_violations.push(msg.clone());
                        errors.push(msg);
                    }
                }
            }
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let security_audit = SecurityAuditResult {
            passed: combined_violations.is_empty(),
            violations: combined_violations,
            audited_tokens: total_tokens,
            audit_timestamp: now,
        };

        HarnessTreeValidationReport {
            valid: errors.is_empty(),
            surface_name: surface.name.clone(),
            always_on_chars,
            always_on_max: surface.always_on_max,
            auto_triggered_skills,
            rejected_off_surface,
            grader_leak_detected,
            jinja_safe,
            security_audit,
            errors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_surface_validation_and_autotrigger() {
        let surface = HarnessSurfaceSpec::default();
        let mut tree = BTreeMap::new();
        tree.insert(
            "systemprompt.md".to_string(),
            "You are a secure Agent Octopus ledger reconciler.".to_string(),
        );
        tree.insert("guardrails.md".to_string(), String::new());
        tree.insert(
            "skills/ledger_audit/SKILL.md".to_string(),
            "---\nname: ledger_audit\ndescription: reconciling signed amounts in a ledger\n---\nCheck both credits and debits.".to_string(),
        );
        tree.insert(
            "scripts/summarize.py".to_string(),
            "def summarize(rows):\n    return sum(rows)\n".to_string(),
        );

        let report = HarnessTreeValidator::validate_tree(&surface, &mut tree);
        assert!(
            report.valid,
            "Expected valid tree, got errors: {:?}",
            report.errors
        );
        assert_eq!(
            report.auto_triggered_skills,
            vec!["ledger_audit".to_string()]
        );
        assert!(tree["guardrails.md"].contains("load the `ledger_audit` skill"));
    }

    #[test]
    fn test_grader_verdict_tripwire_and_off_surface_rejection() {
        let surface = HarnessSurfaceSpec::default();
        let mut tree = BTreeMap::new();
        tree.insert(
            "systemprompt.md".to_string(),
            "Leaked deterministic_eval_summary marker".to_string(),
        );
        tree.insert("../escape.py".to_string(), "pass".to_string());

        let report = HarnessTreeValidator::validate_tree(&surface, &mut tree);
        assert!(!report.valid);
        assert!(report.grader_leak_detected);
        assert!(!report.rejected_off_surface.is_empty());
    }
}
