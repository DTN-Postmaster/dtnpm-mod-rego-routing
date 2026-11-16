//! OPA / Rego policy compilation and evaluation powered by `regorus`.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::blocks::PolicyMutation;
use crate::error::RegoRoutingError;

/// Built-in DTN/mesh Rego constants library.
pub const EMBEDDED_CONSTANTS_REGO: &str = include_str!("../policies/dtn_constants.rego");

/// Built-in DTN/mesh/APRS/Spray-and-Wait Rego helpers library.
pub const EMBEDDED_HELPERS_REGO: &str = include_str!("../policies/helpers.rego");

/// Built-in default ingress policy (`package dtn.ingress`).
pub const EMBEDDED_INGRESS_REGO: &str = include_str!("../policies/ingress.rego");

/// Built-in default egress policy (`package dtn.egress`).
pub const EMBEDDED_EGRESS_REGO: &str = include_str!("../policies/egress.rego");

/// Built-in default dynamic RIB routing policy (`package dtn.routing`).
pub const EMBEDDED_ROUTING_REGO: &str = include_str!("../policies/routing.rego");

const INGRESS_ENTRYPOINT: &str = "data.dtn.ingress.decision";
const EGRESS_ENTRYPOINT: &str = "data.dtn.egress.decision";
const ROUTING_ENTRYPOINT: &str = "data.dtn.routing.routes";
const RIB_DECIDE_ENTRYPOINT: &str = "data.dtn.routing.decide";

/// Maximum accepted size of an inline or file-based Rego policy (256 KiB).
pub const MAX_POLICY_BYTES: usize = 256 * 1024;

/// Active Rego policy source texts (embedded defaults merged with overrides).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySources {
    pub constants: String,
    pub helpers: String,
    pub ingress: String,
    pub egress: String,
    #[serde(default)]
    pub routing: String,
}

impl Default for PolicySources {
    fn default() -> Self {
        Self {
            constants: EMBEDDED_CONSTANTS_REGO.to_string(),
            helpers: EMBEDDED_HELPERS_REGO.to_string(),
            ingress: EMBEDDED_INGRESS_REGO.to_string(),
            egress: EMBEDDED_EGRESS_REGO.to_string(),
            routing: EMBEDDED_ROUTING_REGO.to_string(),
        }
    }
}

impl PolicySources {
    /// Loads embedded defaults and applies optional `.rego` file overrides from `policy_dir`
    /// (`dtn_constants.rego`, `helpers.rego`, `ingress.rego`, `egress.rego`, `routing.rego`).
    pub fn from_dir_or_default(policy_dir: Option<&Path>) -> Result<Self, RegoRoutingError> {
        let mut sources = Self::default();
        let Some(dir) = policy_dir else {
            return Ok(sources);
        };

        load_if_exists(dir, "dtn_constants.rego", &mut sources.constants)?;
        load_if_exists(dir, "helpers.rego", &mut sources.helpers)?;
        load_if_exists(dir, "ingress.rego", &mut sources.ingress)?;
        load_if_exists(dir, "egress.rego", &mut sources.egress)?;
        load_if_exists(dir, "routing.rego", &mut sources.routing)?;
        Ok(sources)
    }

    /// Applies optional inline custom ingress/egress Rego policies stored in configuration/SQLite.
    pub fn with_overrides(
        self,
        custom_ingress: Option<&str>,
        custom_egress: Option<&str>,
    ) -> Result<Self, RegoRoutingError> {
        self.with_all_overrides(custom_ingress, custom_egress, None)
    }

    /// Applies optional inline custom ingress/egress/routing Rego policies stored in configuration/SQLite.
    pub fn with_all_overrides(
        mut self,
        custom_ingress: Option<&str>,
        custom_egress: Option<&str>,
        custom_routing: Option<&str>,
    ) -> Result<Self, RegoRoutingError> {
        if let Some(ingress) = custom_ingress
            && !ingress.trim().is_empty()
        {
            validate_policy_size("ingress", ingress)?;
            self.ingress = ingress.to_string();
        }
        if let Some(egress) = custom_egress
            && !egress.trim().is_empty()
        {
            validate_policy_size("egress", egress)?;
            self.egress = egress.to_string();
        }
        if let Some(routing) = custom_routing
            && !routing.trim().is_empty()
        {
            validate_policy_size("routing", routing)?;
            self.routing = routing.to_string();
        }
        Ok(self)
    }
}

fn load_if_exists(dir: &Path, filename: &str, dest: &mut String) -> Result<(), RegoRoutingError> {
    let candidate = dir.join(filename);
    if !candidate.exists() {
        return Ok(());
    }
    let content = std::fs::read_to_string(&candidate).map_err(|e| {
        RegoRoutingError::InvalidConfig(format!(
            "Failed to read Rego override file {}: {e}",
            candidate.display()
        ))
    })?;
    validate_policy_size(filename, &content)?;
    *dest = content;
    Ok(())
}

fn validate_policy_size(label: &str, src: &str) -> Result<(), RegoRoutingError> {
    if src.len() > MAX_POLICY_BYTES {
        return Err(RegoRoutingError::InvalidConfig(format!(
            "Policy '{label}' exceeds maximum size of {MAX_POLICY_BYTES} bytes"
        )));
    }
    Ok(())
}

/// Structured output returned by `data.dtn.ingress.decision` and `data.dtn.egress.decision`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegoDecision {
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<u64>,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub generate_status_report: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_action: Option<String>,
    #[serde(default)]
    pub mutations: Vec<PolicyMutation>,
}

impl Default for RegoDecision {
    fn default() -> Self {
        Self {
            action: "DROP".to_string(),
            reason_code: Some(6),
            reason: "Default fail-closed decision".to_string(),
            generate_status_report: false,
            route_key: None,
            route_action: None,
            mutations: Vec::new(),
        }
    }
}

fn default_route_priority() -> u32 {
    100
}

/// Declarative RIB route returned by `data.dtn.routing.routes`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DesiredRoute {
    pub pattern: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_hop: Option<String>,
    #[serde(default = "default_route_priority")]
    pub priority: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<u64>,
}

/// Per-bundle routing decision evaluated by `RegoRib::decide` from `data.dtn.routing.decide`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RibDecision {
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_hop: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retain: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<u64>,
}

/// Thread-safe compiled OPA/Rego policy suite (ingress + egress + routing).
#[derive(Clone)]
pub struct PolicySuite {
    ingress: regorus::CompiledPolicy,
    egress: regorus::CompiledPolicy,
    routing: regorus::CompiledPolicy,
    rib_decide: Option<regorus::CompiledPolicy>,
    has_custom_decide: bool,
    sources: PolicySources,
}

impl std::fmt::Debug for PolicySuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicySuite")
            .field("ingress_len", &self.sources.ingress.len())
            .field("egress_len", &self.sources.egress.len())
            .field("routing_len", &self.sources.routing.len())
            .finish()
    }
}

impl PolicySuite {
    /// Compiles ingress, egress, and routing Rego entrypoints from `sources`.
    pub fn compile(sources: PolicySources) -> Result<Self, RegoRoutingError> {
        let ingress = compile_entrypoint(&sources, INGRESS_ENTRYPOINT)?;
        let egress = compile_entrypoint(&sources, EGRESS_ENTRYPOINT)?;
        let routing = compile_entrypoint(&sources, ROUTING_ENTRYPOINT)?;
        let rib_decide = match compile_entrypoint(&sources, RIB_DECIDE_ENTRYPOINT) {
            Ok(policy) => Some(policy),
            Err(err) => {
                // Allow legacy custom routing.rego files that omit `default decide := null`.
                let mentions_decide = sources
                    .routing
                    .lines()
                    .any(|l| !l.trim_start().starts_with('#') && l.contains("decide"));
                if mentions_decide {
                    return Err(err);
                }
                None
            }
        };
        let has_custom_decide = rib_decide.is_some()
            && sources.routing.lines().any(|line| {
                let trimmed = line.trim();
                !trimmed.starts_with('#')
                    && trimmed.contains("decide")
                    && trimmed != "default decide := null"
            });
        Ok(Self {
            ingress,
            egress,
            routing,
            rib_decide,
            has_custom_decide,
            sources,
        })
    }

    /// Returns the active Rego source bundle.
    pub fn sources(&self) -> &PolicySources {
        &self.sources
    }

    /// Evaluates `data.dtn.ingress.decision` against a JSON evaluation context.
    pub fn evaluate_ingress(
        &self,
        input: &serde_json::Value,
    ) -> Result<RegoDecision, RegoRoutingError> {
        eval_compiled(&self.ingress, input)
    }

    /// Evaluates `data.dtn.egress.decision` against a JSON evaluation context.
    pub fn evaluate_egress(
        &self,
        input: &serde_json::Value,
    ) -> Result<RegoDecision, RegoRoutingError> {
        eval_compiled(&self.egress, input)
    }

    /// Evaluates `data.dtn.routing.routes` against a JSON neighbor/node context.
    pub fn evaluate_routing(
        &self,
        input: &serde_json::Value,
    ) -> Result<Vec<DesiredRoute>, RegoRoutingError> {
        eval_compiled_json(&self.routing, input)
    }

    /// Returns whether `routing.rego` defines a non-default per-bundle `decide` rule.
    pub fn has_custom_decide(&self) -> bool {
        self.has_custom_decide
    }

    /// Evaluates optional per-bundle `data.dtn.routing.decide` against a bundle/neighbor/node context.
    pub fn evaluate_rib_decide(
        &self,
        input: &serde_json::Value,
    ) -> Result<Option<RibDecision>, RegoRoutingError> {
        if !self.has_custom_decide {
            return Ok(None);
        }
        let Some(policy) = &self.rib_decide else {
            return Ok(None);
        };
        eval_compiled_json(policy, input)
    }
}

fn compile_entrypoint(
    sources: &PolicySources,
    entrypoint: &str,
) -> Result<regorus::CompiledPolicy, RegoRoutingError> {
    let mut engine = regorus::Engine::new();
    let uses_v0 = [&sources.ingress, &sources.egress, &sources.routing]
        .iter()
        .any(|s| s.contains("import future.keywords") && !s.contains("import rego.v1"));
    engine.set_rego_v0(uses_v0);

    for (name, src) in [
        ("dtn_constants.rego", &sources.constants),
        ("helpers.rego", &sources.helpers),
        ("ingress.rego", &sources.ingress),
        ("egress.rego", &sources.egress),
        ("routing.rego", &sources.routing),
    ] {
        validate_policy_size(name, src)?;
        engine
            .add_policy(name.to_string(), src.clone())
            .map_err(|e| RegoRoutingError::PolicyCompile(format!("Failed to parse {name}: {e}")))?;
    }

    let ep: Arc<str> = Arc::from(entrypoint);
    engine.compile_with_entrypoint(&ep).map_err(|e| {
        RegoRoutingError::PolicyCompile(format!(
            "Failed to compile Rego entrypoint {entrypoint}: {e}"
        ))
    })
}

fn eval_compiled_json<T: serde::de::DeserializeOwned>(
    policy: &regorus::CompiledPolicy,
    input: &serde_json::Value,
) -> Result<T, RegoRoutingError> {
    let json_str = serde_json::to_string(input)?;
    let rego_input = regorus::Value::from_json_str(&json_str).map_err(|e| {
        RegoRoutingError::PolicyEval(format!("Failed to build Rego input value: {e}"))
    })?;
    let output = policy
        .eval_with_input(rego_input)
        .map_err(|e| RegoRoutingError::PolicyEval(format!("Rego evaluation error: {e}")))?;
    let out_json = output.to_json_str().map_err(|e| {
        RegoRoutingError::PolicyEval(format!("Failed to convert Rego decision to JSON: {e}"))
    })?;
    let val: T = serde_json::from_str(&out_json)?;
    Ok(val)
}

fn eval_compiled(
    policy: &regorus::CompiledPolicy,
    input: &serde_json::Value,
) -> Result<RegoDecision, RegoRoutingError> {
    eval_compiled_json(policy, input)
}
