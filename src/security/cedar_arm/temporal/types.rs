use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Time unit for Dogwood window intervals (s, m, h, d)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeUnit {
    Seconds,
    Minutes,
    Hours,
    Days,
}

impl TimeUnit {
    pub fn to_seconds(self, amount: u64) -> u64 {
        match self {
            TimeUnit::Seconds => amount,
            TimeUnit::Minutes => amount * 60,
            TimeUnit::Hours => amount * 3600,
            TimeUnit::Days => amount * 86400,
        }
    }
}

/// A closed temporal window: within <amount><unit>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalWindow {
    pub amount: u64,
    pub unit: TimeUnit,
}

impl TemporalWindow {
    pub fn new(amount: u64, unit: TimeUnit) -> Self {
        Self { amount, unit }
    }

    pub fn as_seconds(&self) -> u64 {
        self.unit.to_seconds(self.amount)
    }
}

/// Event kind (request, response, attempt, or custom)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventKind {
    Request,
    Response,
    Attempt,
    Custom(String),
}

impl From<&str> for EventKind {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "request" => EventKind::Request,
            "response" => EventKind::Response,
            "attempt" => EventKind::Attempt,
            other => EventKind::Custom(other.to_string()),
        }
    }
}

/// A recorded event in the history trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalEvent {
    pub id: u64,
    pub timestamp_secs: u64,
    pub action: String,       // e.g. "Octopus::Action::\"LedgerWrite\"" or "Drupe::Action::\"Read\""
    pub kind: EventKind,      // request, response, attempt
    pub caller_principal: String,
    pub caller_resource: String,
    pub fields: HashMap<String, serde_json::Value>, // nested keys like "input.user", "output.result", "amount"
}

/// Term pattern in a predicate field: field: pattern
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TermPattern {
    Wildcard,
    Literal(serde_json::Value),
    PinnedContext(String), // e.g. context.input.user, context.amount
    ScopePrincipal,        // principal
    ScopeResource,         // resource
    Variable(String),      // variable binding, e.g. u, a
}

/// Comparison operators: <, <=, >, >=, ==, !=
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CmpOp {
    Lt,
    Lte,
    Gt,
    Gte,
    Eq,
    Neq,
}

/// A term expression in comparisons and arguments
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TermExpr {
    Literal(serde_json::Value),
    ContextField(String),
    ScopePrincipal,
    ScopeResource,
    Variable(String),
    Aggregate(Box<AggregateExpr>),
}

/// Aggregation expression (count or sum)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AggregateExpr {
    Count {
        for_vars: Vec<(String, String)>, // (var_name, type)
        where_body: Box<TemporalExpr>,
    },
    Sum {
        sum_var: String,
        for_vars: Vec<(String, String)>,
        where_body: Box<TemporalExpr>,
    },
}

/// Dogwood Temporal AST
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TemporalExpr {
    /// formerly within <window> <atom>
    Formerly {
        window: TemporalWindow,
        body: Box<TemporalExpr>,
    },
    /// previous within <window> <atom>
    Previous {
        window: TemporalWindow,
        body: Box<TemporalExpr>,
    },
    /// <left> since within <window> <right>
    Since {
        left: Box<TemporalExpr>,
        window: TemporalWindow,
        right: Box<TemporalExpr>,
    },
    /// Conjunction: A && B
    And(Box<TemporalExpr>, Box<TemporalExpr>),
    /// Negation: !A
    Not(Box<TemporalExpr>),
    /// exists (x: Type). phi
    Exists {
        var: String,
        var_type: String,
        body: Box<TemporalExpr>,
    },
    /// tp(t)
    TimepointBind(String),
    /// Predicate: Namespace::Action::"ActionId"::kind { field: pattern, ... }
    Predicate {
        namespace: String,
        action: String,
        kind: EventKind,
        patterns: HashMap<String, TermPattern>,
    },
    /// Comparison: term cmp term
    Comparison {
        left: TermExpr,
        op: CmpOp,
        right: TermExpr,
    },
}
