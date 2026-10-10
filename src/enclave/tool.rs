use crate::core::types::OctopusSecurityError;

pub trait SafeTool: Send + Sync {
    fn name(&self) -> &'static str;
    fn execute(&self, raw_input: &str) -> Result<String, OctopusSecurityError>;
}
