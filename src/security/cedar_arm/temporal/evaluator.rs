use super::types::*;
use std::collections::HashMap;

/// Evaluation context at decision timepoint i
#[derive(Debug, Clone)]
pub struct DecisionContext {
    pub current_time_secs: u64,
    pub principal: String,
    pub resource: String,
    pub context_fields: HashMap<String, serde_json::Value>,
}

/// Variable bindings in evaluation
pub type BindingEnv = HashMap<String, serde_json::Value>;

/// Metric First-Order Temporal Logic (MFOTL) past-only evaluator for Dogwood
pub struct DogwoodEvaluator<'a> {
    history: &'a [TemporalEvent],
    decision_ctx: &'a DecisionContext,
}

impl<'a> DogwoodEvaluator<'a> {
    pub fn new(history: &'a [TemporalEvent], decision_ctx: &'a DecisionContext) -> Self {
        Self {
            history,
            decision_ctx,
        }
    }

    /// Evaluates a Dogwood temporal expression at decision timepoint i (the candidate request point).
    pub fn evaluate(&self, expr: &TemporalExpr) -> bool {
        let env = BindingEnv::new();
        // The decision point is the candidate request timepoint at index self.history.len()
        let target_i = self.history.len();
        let results = self.eval_expr(expr, target_i, &env);
        !results.is_empty()
    }

    fn eval_expr(&self, expr: &TemporalExpr, curr_idx: usize, env: &BindingEnv) -> Vec<BindingEnv> {
        match expr {
            TemporalExpr::Formerly { window, body } => {
                let curr_time = self.get_timepoint_time(curr_idx);
                let w_secs = window.as_seconds();
                let mut accumulated = Vec::new();

                for j in 0..self.history.len() {
                    let past_time = self.history[j].timestamp_secs;
                    if past_time <= curr_time && (curr_time - past_time) <= w_secs {
                        let res = self.eval_expr(body, j, env);
                        accumulated.extend(res);
                    }
                }
                accumulated
            }

            TemporalExpr::Previous { window, body } => {
                if curr_idx == 0 || self.history.is_empty() {
                    return Vec::new();
                }
                let prev_idx = curr_idx - 1;
                let curr_time = self.get_timepoint_time(curr_idx);
                let prev_time = self.history[prev_idx].timestamp_secs;
                if prev_time <= curr_time && (curr_time - prev_time) <= window.as_seconds() {
                    self.eval_expr(body, prev_idx, env)
                } else {
                    Vec::new()
                }
            }

            TemporalExpr::Since {
                left,
                window,
                right,
            } => {
                let curr_time = self.get_timepoint_time(curr_idx);
                let w_secs = window.as_seconds();
                let mut valid_envs = Vec::new();

                // Find anchor j where right held within window
                for j in 0..self.history.len() {
                    let anchor_time = self.history[j].timestamp_secs;
                    if anchor_time <= curr_time && (curr_time - anchor_time) <= w_secs {
                        let right_matches = self.eval_expr(right, j, env);
                        for r_env in right_matches {
                            // Check if left held at every intervening step k in (j+1)..history.len()
                            let mut continuous = true;
                            for k in (j + 1)..self.history.len() {
                                let left_matches = self.eval_expr(left, k, &r_env);
                                if left_matches.is_empty() {
                                    continuous = false;
                                    break;
                                }
                            }
                            if continuous {
                                valid_envs.push(r_env);
                            }
                        }
                    }
                }
                valid_envs
            }

            TemporalExpr::And(a, b) => {
                let left_matches = self.eval_expr(a, curr_idx, env);
                let mut combined = Vec::new();
                for l_env in left_matches {
                    let right_matches = self.eval_expr(b, curr_idx, &l_env);
                    combined.extend(right_matches);
                }
                combined
            }

            TemporalExpr::Not(sub) => {
                let matches = self.eval_expr(sub, curr_idx, env);
                if matches.is_empty() {
                    vec![env.clone()]
                } else {
                    Vec::new()
                }
            }

            TemporalExpr::Exists {
                var,
                var_type: _,
                body,
            } => {
                let matches = self.eval_expr(body, curr_idx, env);
                if matches.is_empty() {
                    Vec::new()
                } else {
                    // Filter or keep distinct envs
                    let mut res = Vec::new();
                    for mut m in matches {
                        if !m.contains_key(var) {
                            m.insert(var.clone(), serde_json::Value::Bool(true));
                        }
                        res.push(m);
                    }
                    res
                }
            }

            TemporalExpr::TimepointBind(t_var) => {
                let mut new_env = env.clone();
                new_env.insert(t_var.clone(), serde_json::json!(curr_idx as u64));
                vec![new_env]
            }

            TemporalExpr::Predicate {
                namespace: _,
                action,
                kind,
                patterns,
            } => {
                if curr_idx >= self.history.len() {
                    return Vec::new();
                }
                let ev = &self.history[curr_idx];

                // Match action name and kind
                let action_norm = action.trim_matches('"');
                let ev_action_norm = ev.action.trim_matches('"');
                if !ev_action_norm.ends_with(action_norm) && !action_norm.ends_with(ev_action_norm)
                {
                    return Vec::new();
                }
                if &ev.kind != kind {
                    return Vec::new();
                }

                // Match field patterns
                let mut new_env = env.clone();
                for (field, pattern) in patterns {
                    let actual_val = match field.as_str() {
                        "callerPrincipal" => {
                            Some(serde_json::Value::String(ev.caller_principal.clone()))
                        }
                        "callerResource" => {
                            Some(serde_json::Value::String(ev.caller_resource.clone()))
                        }
                        other => ev.fields.get(other).cloned(),
                    };

                    match pattern {
                        TermPattern::Wildcard => {}
                        TermPattern::ScopePrincipal => {
                            if ev.caller_principal != self.decision_ctx.principal {
                                return Vec::new();
                            }
                        }
                        TermPattern::ScopeResource => {
                            if ev.caller_resource != self.decision_ctx.resource {
                                return Vec::new();
                            }
                        }
                        TermPattern::PinnedContext(ctx_field) => {
                            let expected = self.resolve_context_field(ctx_field);
                            if expected.is_none() || expected != actual_val {
                                return Vec::new();
                            }
                        }
                        TermPattern::Literal(lit) => {
                            if actual_val.as_ref() != Some(lit) {
                                return Vec::new();
                            }
                        }
                        TermPattern::Variable(var_name) => {
                            if let Some(existing) = new_env.get(var_name) {
                                if actual_val.as_ref() != Some(existing) {
                                    return Vec::new();
                                }
                            } else if let Some(val) = actual_val {
                                new_env.insert(var_name.clone(), val);
                            } else {
                                return Vec::new();
                            }
                        }
                    }
                }
                vec![new_env]
            }

            TemporalExpr::Comparison { left, op, right } => {
                let left_val = self.resolve_term(left, curr_idx, env);
                let right_val = self.resolve_term(right, curr_idx, env);

                if let (Some(l), Some(r)) = (left_val, right_val) {
                    if self.compare_values(&l, *op, &r) {
                        let mut new_env = env.clone();
                        // If left or right is an unbound variable in equality, bind it
                        if *op == CmpOp::Eq {
                            if let TermExpr::Variable(var_name) = left {
                                if !new_env.contains_key(var_name) {
                                    new_env.insert(var_name.clone(), r.clone());
                                }
                            }
                            if let TermExpr::Variable(var_name) = right {
                                if !new_env.contains_key(var_name) {
                                    new_env.insert(var_name.clone(), l);
                                }
                            }
                        }
                        return vec![new_env];
                    }
                }
                Vec::new()
            }
        }
    }

    fn resolve_term(
        &self,
        term: &TermExpr,
        curr_idx: usize,
        env: &BindingEnv,
    ) -> Option<serde_json::Value> {
        match term {
            TermExpr::Literal(val) => Some(val.clone()),
            TermExpr::ContextField(f) => self.resolve_context_field(f),
            TermExpr::ScopePrincipal => Some(serde_json::Value::String(
                self.decision_ctx.principal.clone(),
            )),
            TermExpr::ScopeResource => Some(serde_json::Value::String(
                self.decision_ctx.resource.clone(),
            )),
            TermExpr::Variable(var) => env.get(var).cloned(),
            TermExpr::Aggregate(agg) => match agg.as_ref() {
                AggregateExpr::Count {
                    for_vars: _,
                    where_body,
                } => {
                    let matches = self.eval_expr(where_body, curr_idx, env);
                    Some(serde_json::json!(matches.len() as i64))
                }
                AggregateExpr::Sum {
                    sum_var,
                    for_vars: _,
                    where_body,
                } => {
                    let matches = self.eval_expr(where_body, curr_idx, env);
                    let mut sum: i64 = 0;
                    for m in matches {
                        if let Some(v) = m.get(sum_var).and_then(|x| x.as_i64()) {
                            sum = sum.saturating_add(v);
                        }
                    }
                    Some(serde_json::json!(sum))
                }
            },
        }
    }

    fn resolve_context_field(&self, path: &str) -> Option<serde_json::Value> {
        let clean = path.trim_start_matches("context.");
        self.decision_ctx.context_fields.get(clean).cloned()
    }

    fn get_timepoint_time(&self, idx: usize) -> u64 {
        if idx < self.history.len() {
            self.history[idx].timestamp_secs
        } else {
            self.decision_ctx.current_time_secs
        }
    }

    fn compare_values(
        &self,
        left: &serde_json::Value,
        op: CmpOp,
        right: &serde_json::Value,
    ) -> bool {
        match op {
            CmpOp::Eq => left == right,
            CmpOp::Neq => left != right,
            CmpOp::Lt => {
                left.as_i64().is_some()
                    && right.as_i64().is_some()
                    && left.as_i64() < right.as_i64()
            }
            CmpOp::Lte => {
                left.as_i64().is_some()
                    && right.as_i64().is_some()
                    && left.as_i64() <= right.as_i64()
            }
            CmpOp::Gt => {
                left.as_i64().is_some()
                    && right.as_i64().is_some()
                    && left.as_i64() > right.as_i64()
            }
            CmpOp::Gte => {
                left.as_i64().is_some()
                    && right.as_i64().is_some()
                    && left.as_i64() >= right.as_i64()
            }
        }
    }
}
