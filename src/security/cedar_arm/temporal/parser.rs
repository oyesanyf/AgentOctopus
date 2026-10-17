use super::types::*;
use std::collections::HashMap;

/// Result of parsing a Dogwood policy clause
#[derive(Debug, Clone)]
pub struct ParsedTemporalClause {
    pub is_unless: bool, // false for `when temporal`, true for `unless temporal`
    pub expr: TemporalExpr,
}

/// Helper parser for Dogwood temporal expressions
pub struct DogwoodParser;

impl DogwoodParser {
    /// Parses a standard preset pattern or structured Dogwood expression
    pub fn parse(input: &str) -> Result<ParsedTemporalClause, String> {
        let trimmed = input.trim();
        let is_unless = trimmed.starts_with("unless temporal");
        let body = if let Some(pos) = trimmed.find('{') {
            if let Some(end) = trimmed.rfind('}') {
                &trimmed[pos + 1..end]
            } else {
                trimmed
            }
        } else {
            trimmed
        };

        let expr = Self::parse_expression(body.trim())?;
        Ok(ParsedTemporalClause { is_unless, expr })
    }

    /// High-level expression parser supporting Dogwood operators
    pub fn parse_expression(input: &str) -> Result<TemporalExpr, String> {
        let s = input.trim();

        // 1. Conjunction A && B (at top level)
        if let Some((left_str, right_str)) = Self::find_top_level_split(s, "&&") {
            let left = Self::parse_expression(left_str.trim())?;
            let right = Self::parse_expression(right_str.trim())?;
            return Ok(TemporalExpr::And(Box::new(left), Box::new(right)));
        }

        // 2. Infix Since: <left> since within <window> <right>
        if let Some(since_idx) = Self::find_top_level_keyword(s, "since") {
            let left_str = s[..since_idx].trim();
            let remainder = s[since_idx + 5..].trim();
            if !remainder.starts_with("within") {
                return Err("Expected 'within <interval>' after 'since'".to_string());
            }
            let rem2 = remainder[6..].trim();
            let mut parts = rem2.split_whitespace();
            let win_str = parts.next().ok_or("Missing interval in since clause")?;
            let window = Self::parse_window(win_str)?;
            let right_str = rem2[win_str.len()..].trim();

            let left = Self::parse_expression(left_str)?;
            let right = Self::parse_expression(right_str)?;
            return Ok(TemporalExpr::Since {
                left: Box::new(left),
                window,
                right: Box::new(right),
            });
        }

        // 3. Negation !A
        if s.starts_with('!') {
            let sub = Self::parse_expression(s[1..].trim())?;
            return Ok(TemporalExpr::Not(Box::new(sub)));
        }

        // 4. Formerly: formerly within <window> <atom>
        if s.starts_with("formerly") {
            let rem = s["formerly".len()..].trim();
            if !rem.starts_with("within") {
                return Err("Expected 'within <interval>' after 'formerly'".to_string());
            }
            let rem2 = rem["within".len()..].trim();
            let mut parts = rem2.split_whitespace();
            let win_str = parts.next().ok_or("Missing window interval")?;
            let window = Self::parse_window(win_str)?;
            let body_str = rem2[win_str.len()..].trim();
            let body = Self::parse_expression(body_str)?;
            return Ok(TemporalExpr::Formerly {
                window,
                body: Box::new(body),
            });
        }

        // 5. Previous: previous within <window> <atom>
        if s.starts_with("previous") {
            let rem = s["previous".len()..].trim();
            if !rem.starts_with("within") {
                return Err("Expected 'within <interval>' after 'previous'".to_string());
            }
            let rem2 = rem["within".len()..].trim();
            let mut parts = rem2.split_whitespace();
            let win_str = parts.next().ok_or("Missing window interval")?;
            let window = Self::parse_window(win_str)?;
            let body_str = rem2[win_str.len()..].trim();
            let body = Self::parse_expression(body_str)?;
            return Ok(TemporalExpr::Previous {
                window,
                body: Box::new(body),
            });
        }

        // 6. Exists binder: exists (x: Type). phi
        if s.starts_with("exists") {
            if let Some(open_p) = s.find('(') {
                if let Some(close_p) = s.find(')') {
                    if let Some(dot_p) = s[close_p..].find('.') {
                        let bind_spec = &s[open_p + 1..close_p];
                        let parts: Vec<&str> = bind_spec.split(':').collect();
                        let var_name = parts[0].trim().to_string();
                        let var_type = parts.get(1).map(|t| t.trim().to_string()).unwrap_or_else(|| "Any".to_string());
                        let body_str = s[close_p + dot_p + 1..].trim();
                        let body = Self::parse_expression(body_str)?;
                        return Ok(TemporalExpr::Exists {
                            var: var_name,
                            var_type,
                            body: Box::new(body),
                        });
                    }
                }
            }
        }

        // 7. Timepoint binder: tp(t)
        if s.starts_with("tp(") && s.ends_with(')') {
            let t_var = s[3..s.len() - 1].trim().to_string();
            return Ok(TemporalExpr::TimepointBind(t_var));
        }

        // 8. Parenthesized atom ( ... )
        if s.starts_with('(') && s.ends_with(')') {
            return Self::parse_expression(&s[1..s.len() - 1]);
        }

        // 9. Comparisons (e.g. (count ...) > 3, n == 2, total > 1000)
        for (op_str, op) in [
            ("==", CmpOp::Eq),
            ("!=", CmpOp::Neq),
            ("<=", CmpOp::Lte),
            (">=", CmpOp::Gte),
            ("<", CmpOp::Lt),
            (">", CmpOp::Gt),
        ] {
            if let Some(idx) = Self::find_comparison_split(s, op_str) {
                let left_str = s[..idx].trim();
                let right_str = s[idx + op_str.len()..].trim();
                let left = Self::parse_term(left_str)?;
                let right = Self::parse_term(right_str)?;
                return Ok(TemporalExpr::Comparison { left, op, right });
            }
        }

        // 10. Predicate matching: Namespace::...::Action::"ActionId"::kind { field: pattern }
        Self::parse_predicate(s)
    }

    pub fn parse_window(s: &str) -> Result<TemporalWindow, String> {
        let clean = s.trim().trim_end_matches(';');
        if clean.ends_with('s') {
            let n = clean[..clean.len() - 1].parse().map_err(|e| format!("Invalid seconds window: {}", e))?;
            Ok(TemporalWindow::new(n, TimeUnit::Seconds))
        } else if clean.ends_with('m') {
            let n = clean[..clean.len() - 1].parse().map_err(|e| format!("Invalid minutes window: {}", e))?;
            Ok(TemporalWindow::new(n, TimeUnit::Minutes))
        } else if clean.ends_with('h') {
            let n = clean[..clean.len() - 1].parse().map_err(|e| format!("Invalid hours window: {}", e))?;
            Ok(TemporalWindow::new(n, TimeUnit::Hours))
        } else if clean.ends_with('d') {
            let n = clean[..clean.len() - 1].parse().map_err(|e| format!("Invalid days window: {}", e))?;
            Ok(TemporalWindow::new(n, TimeUnit::Days))
        } else {
            Err(format!("Unknown time unit in interval: {}", s))
        }
    }

    fn parse_predicate(s: &str) -> Result<TemporalExpr, String> {
        let open_brace = s.find('{').ok_or_else(|| format!("Expected '{{' in predicate: {}", s))?;
        let close_brace = s.rfind('}').ok_or_else(|| format!("Expected '}}' in predicate: {}", s))?;
        let header = s[..open_brace].trim();
        let body = &s[open_brace + 1..close_brace].trim();

        // Header shape: Namespace::Action::"Id"::kind
        let parts: Vec<&str> = header.split("::").collect();
        if parts.len() < 2 {
            return Err(format!("Malformed predicate header: {}", header));
        }

        let last_part = parts
            .last()
            .copied()
            .ok_or_else(|| format!("Malformed predicate header: {}", header))?;
        let kind = EventKind::from(last_part);
        let action = if parts.len() >= 2 {
            parts[parts.len() - 2].to_string()
        } else {
            header.to_string()
        };
        let namespace = if parts.len() > 2 {
            parts[..parts.len() - 2].join("::")
        } else {
            "".to_string()
        };

        let mut patterns = HashMap::new();
        if !body.is_empty() {
            for field_pair in body.split(',') {
                let pair = field_pair.trim();
                if pair.is_empty() {
                    continue;
                }
                if let Some(col) = pair.find(':') {
                    let field_name = pair[..col].trim().to_string();
                    let pattern_val = pair[col + 1..].trim();
                    let pattern = Self::parse_pattern(pattern_val)?;
                    patterns.insert(field_name, pattern);
                }
            }
        }

        Ok(TemporalExpr::Predicate {
            namespace,
            action,
            kind,
            patterns,
        })
    }

    fn parse_pattern(s: &str) -> Result<TermPattern, String> {
        match s {
            "*" | "_" => Ok(TermPattern::Wildcard),
            "principal" => Ok(TermPattern::ScopePrincipal),
            "resource" => Ok(TermPattern::ScopeResource),
            other if other.starts_with("context.") => Ok(TermPattern::PinnedContext(other.to_string())),
            "true" => Ok(TermPattern::Literal(serde_json::Value::Bool(true))),
            "false" => Ok(TermPattern::Literal(serde_json::Value::Bool(false))),
            other if other.starts_with('"') && other.ends_with('"') => {
                Ok(TermPattern::Literal(serde_json::Value::String(other[1..other.len() - 1].to_string())))
            }
            other => {
                if let Ok(n) = other.parse::<i64>() {
                    Ok(TermPattern::Literal(serde_json::json!(n)))
                } else {
                    Ok(TermPattern::Variable(other.to_string()))
                }
            }
        }
    }

    fn parse_term(s: &str) -> Result<TermExpr, String> {
        let clean = s.trim();
        if clean.starts_with("count") {
            let agg = Self::parse_count_agg(clean)?;
            return Ok(TermExpr::Aggregate(Box::new(agg)));
        }
        if clean.starts_with("sum") {
            let agg = Self::parse_sum_agg(clean)?;
            return Ok(TermExpr::Aggregate(Box::new(agg)));
        }
        if clean.starts_with('(') && clean.ends_with(')') {
            return Self::parse_term(&clean[1..clean.len() - 1]);
        }
        if clean == "principal" {
            return Ok(TermExpr::ScopePrincipal);
        }
        if clean == "resource" {
            return Ok(TermExpr::ScopeResource);
        }
        if clean.starts_with("context.") {
            return Ok(TermExpr::ContextField(clean.to_string()));
        }
        if let Ok(n) = clean.parse::<i64>() {
            return Ok(TermExpr::Literal(serde_json::json!(n)));
        }
        if clean == "true" {
            return Ok(TermExpr::Literal(serde_json::Value::Bool(true)));
        }
        if clean == "false" {
            return Ok(TermExpr::Literal(serde_json::Value::Bool(false)));
        }
        if clean.starts_with('"') && clean.ends_with('"') {
            return Ok(TermExpr::Literal(serde_json::Value::String(clean[1..clean.len() - 1].to_string())));
        }
        Ok(TermExpr::Variable(clean.to_string()))
    }

    fn parse_count_agg(s: &str) -> Result<AggregateExpr, String> {
        // Form: count for (t: Timepoint). where phi
        let where_pos = s.find("where").ok_or("Expected 'where' in count aggregate")?;
        let body_str = s[where_pos + 5..].trim();
        let where_body = Box::new(Self::parse_expression(body_str)?);
        Ok(AggregateExpr::Count {
            for_vars: vec![("t".to_string(), "Timepoint".to_string())],
            where_body,
        })
    }

    fn parse_sum_agg(s: &str) -> Result<AggregateExpr, String> {
        // Form: sum v for (v: Long), (t: Timepoint). where phi
        let parts: Vec<&str> = s.split_whitespace().collect();
        let sum_var = parts.get(1).unwrap_or(&"a").to_string();
        let where_pos = s.find("where").ok_or("Expected 'where' in sum aggregate")?;
        let body_str = s[where_pos + 5..].trim();
        let where_body = Box::new(Self::parse_expression(body_str)?);
        Ok(AggregateExpr::Sum {
            sum_var: sum_var.clone(),
            for_vars: vec![
                (sum_var, "Long".to_string()),
                ("t".to_string(), "Timepoint".to_string()),
            ],
            where_body,
        })
    }

    fn find_top_level_split<'a>(s: &'a str, op: &str) -> Option<(&'a str, &'a str)> {
        let mut depth = 0;
        let bytes = s.as_bytes();
        let op_bytes = op.as_bytes();
        for i in 0..bytes.len() {
            match bytes[i] {
                b'(' | b'{' | b'[' => depth += 1,
                b')' | b'}' | b']' => depth -= 1,
                _ => {
                    if depth == 0 && i + op_bytes.len() <= bytes.len() && &bytes[i..i + op_bytes.len()] == op_bytes {
                        return Some((&s[..i], &s[i + op_bytes.len()..]));
                    }
                }
            }
        }
        None
    }

    fn find_top_level_keyword(s: &str, keyword: &str) -> Option<usize> {
        let mut depth = 0;
        let bytes = s.as_bytes();
        let kw_len = keyword.len();
        for i in 0..bytes.len() {
            match bytes[i] {
                b'(' | b'{' | b'[' => depth += 1,
                b')' | b'}' | b']' => depth -= 1,
                _ => {
                    if depth == 0 && i + kw_len <= bytes.len() && &s[i..i + kw_len] == keyword {
                        let prev_ok = i == 0 || bytes[i - 1].is_ascii_whitespace();
                        let next_ok = i + kw_len >= bytes.len() || bytes[i + kw_len].is_ascii_whitespace();
                        if prev_ok && next_ok {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn find_comparison_split(s: &str, op: &str) -> Option<usize> {
        let mut depth = 0;
        let bytes = s.as_bytes();
        let op_bytes = op.as_bytes();
        for i in 0..bytes.len() {
            match bytes[i] {
                b'(' | b'{' | b'[' => depth += 1,
                b')' | b'}' | b']' => depth -= 1,
                _ => {
                    if depth == 0 && i + op_bytes.len() <= bytes.len() && &bytes[i..i + op_bytes.len()] == op_bytes {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_formerly_write_after_read() {
        let code = r#"when temporal { formerly within 1h Drupe::Action::"Read"::response{ input.user: context.input.user, input.document: context.input.document } };"#;
        let clause = DogwoodParser::parse(code).expect("Should parse");
        assert!(!clause.is_unless);
        match clause.expr {
            TemporalExpr::Formerly { window, body: _ } => {
                assert_eq!(window.amount, 1);
                assert_eq!(window.unit, TimeUnit::Hours);
            }
            _ => panic!("Expected Formerly expression"),
        }
    }

    #[test]
    fn test_parse_open_session_since_revocation() {
        let code = r#"when temporal { !Drupe::Action::"Revoke"::request{ input.user: context.input.user } since within 24h Drupe::Action::"Grant"::request{ input.user: context.input.user } };"#;
        let clause = DogwoodParser::parse(code).expect("Should parse since");
        match clause.expr {
            TemporalExpr::Since { left: _, window, right: _ } => {
                assert_eq!(window.amount, 24);
                assert_eq!(window.unit, TimeUnit::Hours);
            }
            _ => panic!("Expected Since expression"),
        }
    }
}
