//! HDC-based Variable & Function Auto-naming engine.
//!
//! Exposes a memory-efficient Associative Memory mapping contextual
//! hypervectors of variables and functions to their best-guess clean names.
//! Fits in <10MB of memory and executes in microseconds without floating-point math.

use crate::HyperVector;
use omnisec_json::{FromJson, ToJson};

/// Role of a variable within a specific instruction.
#[derive(Debug, Clone, ToJson, FromJson, PartialEq, Eq)]
pub enum VariableRole {
    /// Variable is the destination of the operation.
    Dst,
    /// Variable is a source operand.
    Src,
    /// Variable is an argument in a function call.
    CallArg {
        /// 0-indexed argument position.
        arg_index: usize,
        /// Name of the function being called (if known).
        callee: String,
    },
}

/// Description of a single usage of a variable in the decompiled code.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct VariableUsage {
    /// Mnemonic or opcode name (e.g., "add", "mov", "call").
    pub opcode: String,
    /// Role in the instruction.
    pub role: VariableRole,
}

/// Struct representing the context of a variable to be encoded.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct VariableContext {
    /// Type of the variable (e.g., "int", "char*", "size_t").
    pub var_type: String,
    /// List of usages of the variable in the function body.
    pub usages: Vec<VariableUsage>,
}

/// Struct representing the structural and API context of a function.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct FunctionContext {
    /// Node instruction hypervectors (subgraph of instructions/blocks).
    pub node_vectors: Vec<Vec<u64>>,
    /// CFG edges: (src_idx, dst_idx, edge_type) where 0=Data, 1=Control, 2=Sequential.
    pub edges: Vec<(usize, usize, u8)>,
    /// Set of API/imported functions called inside this function.
    pub called_apis: Vec<String>,
}

/// Associative memory storing signature hypervectors of known variables/functions.
#[derive(Debug, Clone, Default, ToJson, FromJson)]
pub struct HdcNamerStore {
    /// Maps hypervector string representation (or ID) to clean names for variables.
    pub variables: Vec<(HyperVector, String)>,
    /// Maps hypervector to clean names for functions.
    pub functions: Vec<(HyperVector, String)>,
}

/// Main HDC Auto-naming Engine.
pub struct HdcNamer {
    store: HdcNamerStore,
}

impl HdcNamer {
    /// Create a new HdcNamer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: HdcNamerStore::default(),
        }
    }

    /// Load store from serialized JSON bytes.
    pub fn from_json(json_str: &str) -> Result<Self, omnisec_json::JsonError> {
        let store = omnisec_json::from_json_str(json_str)?;
        Ok(Self { store })
    }

    /// Save store to JSON string.
    pub fn to_json(&self) -> String {
        omnisec_json::to_json_string(&self.store)
    }

    /// Train the namer with a confirmed variable context and name.
    pub fn train_variable(&mut self, context: &VariableContext, clean_name: String) {
        let hv = self.encode_variable(context);
        // Clean duplicates: if name already exists, we bundle/reinforce the HV
        if let Some(existing) = self
            .store
            .variables
            .iter_mut()
            .find(|(_, name)| name == &clean_name)
        {
            existing.0 = HyperVector::bundle(&[existing.0, hv]);
        } else {
            self.store.variables.push((hv, clean_name));
        }
    }

    /// Train the namer with a confirmed function context and name.
    pub fn train_function(&mut self, context: &FunctionContext, clean_name: String) {
        let hv = self.encode_function(context);
        if let Some(existing) = self
            .store
            .functions
            .iter_mut()
            .find(|(_, name)| name == &clean_name)
        {
            existing.0 = HyperVector::bundle(&[existing.0, hv]);
        } else {
            self.store.functions.push((hv, clean_name));
        }
    }

    /// Predict the name of a variable given its context.
    /// Returns a list of predictions sorted by Jaccard similarity (highest first).
    pub fn predict_variable(
        &self,
        context: &VariableContext,
        threshold: f64,
    ) -> Vec<(String, f64)> {
        let target_hv = self.encode_variable(context);
        let mut matches = Vec::new();

        for (sig_hv, name) in &self.store.variables {
            let jaccard = target_hv.jaccard(*sig_hv);
            if jaccard >= threshold {
                matches.push((name.clone(), jaccard));
            }
        }

        matches.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        matches
    }

    /// Predict the name of a function given its context.
    /// Returns a list of predictions sorted by Jaccard similarity (highest first).
    pub fn predict_function(
        &self,
        context: &FunctionContext,
        threshold: f64,
    ) -> Vec<(String, f64)> {
        let target_hv = self.encode_function(context);
        let mut matches = Vec::new();

        for (sig_hv, name) in &self.store.functions {
            let jaccard = target_hv.jaccard(*sig_hv);
            if jaccard >= threshold {
                matches.push((name.clone(), jaccard));
            }
        }

        matches.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        matches
    }

    /// Encodes a variable's contextual information into a 2048-bit sparse HyperVector.
    #[must_use]
    pub fn encode_variable(&self, context: &VariableContext) -> HyperVector {
        // 1. Encode variable type.
        let type_seed = deterministic_seed(&context.var_type);
        let type_hv = HyperVector::sparse(type_seed);

        // 2. Encode usages.
        let mut usages_hvs = Vec::new();
        for usage in &context.usages {
            let op_seed = deterministic_seed(&usage.opcode);
            let op_hv = HyperVector::sparse(op_seed);

            let usage_hv = match &usage.role {
                VariableRole::Dst => {
                    // Positional permutation slot 1 represents Dst
                    op_hv.bind(HyperVector::sparse(0xDEAD_0001))
                }
                VariableRole::Src => {
                    // Positional permutation slot 2 represents Src
                    op_hv.bind(HyperVector::sparse(0xDEAD_0002))
                }
                VariableRole::CallArg { arg_index, callee } => {
                    // Bind op, callee and arg index
                    let callee_seed = deterministic_seed(callee);
                    let callee_hv = HyperVector::sparse(callee_seed);
                    let arg_hv = HyperVector::sparse((0xCAF0_0000 + arg_index) as u64);
                    op_hv.bind(callee_hv).bind(arg_hv)
                }
            };
            usages_hvs.push(usage_hv);
        }

        if usages_hvs.is_empty() {
            type_hv
        } else {
            type_hv.bind(HyperVector::bundle(&usages_hvs))
        }
    }

    /// Encodes a function's context into a single HyperVector.
    #[must_use]
    pub fn encode_function(&self, context: &FunctionContext) -> HyperVector {
        // 1. Structural Subgraph Encoding of instructions/blocks
        let mut node_hvs = Vec::new();
        for node in &context.node_vectors {
            let mut arr = [0u64; HyperVector::WORDS];
            let len = node.len().min(HyperVector::WORDS);
            arr[..len].copy_from_slice(&node[..len]);
            node_hvs.push(HyperVector { data: arr });
        }

        // Encode the structural topology using a lightweight encoder
        let encoder = crate::subgraph::SubgraphEncoder::new();
        let structural_edges: Vec<(usize, usize, crate::subgraph::EdgeType)> = context
            .edges
            .iter()
            .map(|&(s, d, etype)| {
                let t = match etype {
                    0 => crate::subgraph::EdgeType::Data,
                    1 => crate::subgraph::EdgeType::Control,
                    _ => crate::subgraph::EdgeType::Sequential,
                };
                (s, d, t)
            })
            .collect();

        let structural_hv = encoder.encode_subgraph(&node_hvs, &structural_edges);

        // 2. Encode called APIs.
        if context.called_apis.is_empty() {
            structural_hv
        } else {
            let api_hvs: Vec<HyperVector> = context
                .called_apis
                .iter()
                .map(|api| HyperVector::sparse(deterministic_seed(api)))
                .collect();
            let apis_hv = HyperVector::bundle(&api_hvs);
            // Bind structural context and API context together
            structural_hv.bind(apis_hv)
        }
    }
}

fn deterministic_seed(value: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in value.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variable_naming_roundtrip() {
        let mut namer = HdcNamer::new();

        let buffer_context = VariableContext {
            var_type: "char*".into(),
            usages: vec![
                VariableUsage {
                    opcode: "call".into(),
                    role: VariableRole::CallArg {
                        arg_index: 0,
                        callee: "recv".into(),
                    },
                },
                VariableUsage {
                    opcode: "call".into(),
                    role: VariableRole::CallArg {
                        arg_index: 1,
                        callee: "memcpy".into(),
                    },
                },
            ],
        };

        namer.train_variable(&buffer_context, "network_buffer".into());

        // Predict on exact match
        let pred = namer.predict_variable(&buffer_context, 0.1);
        assert!(!pred.is_empty());
        assert_eq!(pred[0].0, "network_buffer");

        // Predict on slightly perturbed match (different variable type but same usages)
        let similar_context = VariableContext {
            var_type: "unsigned char*".into(),
            usages: buffer_context.usages.clone(),
        };
        let pred2 = namer.predict_variable(&similar_context, 0.15);
        assert!(!pred2.is_empty());
        assert_eq!(pred2[0].0, "network_buffer");
    }

    #[test]
    fn test_function_naming_roundtrip() {
        let mut namer = HdcNamer::new();

        let context = FunctionContext {
            node_vectors: vec![vec![1, 2, 3], vec![4, 5, 6]],
            edges: vec![(0, 1, 0)],
            called_apis: vec!["recv".into(), "memcpy".into(), "decrypt".into()],
        };

        namer.train_function(&context, "decrypt_network_packet".into());

        // Test JSON roundtrip
        let json = namer.to_json();
        // [DEBUG CLEANUP] println!("DEBUG namer JSON: {}", json);
        let loaded_namer = HdcNamer::from_json(&json).unwrap();

        let pred = loaded_namer.predict_function(&context, 0.1);
        // [DEBUG CLEANUP] println!("DEBUG predictions: {:?}", pred);
        assert!(!pred.is_empty());
        assert_eq!(pred[0].0, "decrypt_network_packet");
    }
}
