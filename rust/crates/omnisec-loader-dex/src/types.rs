//! Parsed DEX data types — Rust equivalents of Go structs from `dex_parser.go`.

use omnisec_json::ToJson;
use std::time::Duration;

/// Parse metrics — statistics collected during parsing.
#[derive(Debug, Clone, Default, ToJson)]
pub struct ParseMetrics {
    /// Total wall-clock time for parsing.
    #[json(with = "duration_ms_serde")]
    pub parse_duration: Duration,
    /// Number of strings in the string table.
    pub strings_count: usize,
    /// Number of type descriptors.
    pub types_count: usize,
    /// Number of method prototypes.
    pub protos_count: usize,
    /// Number of field definitions.
    pub fields_count: usize,
    /// Number of method definitions.
    pub methods_count: usize,
    /// Number of class definitions.
    pub classes_count: usize,
    /// Number of warnings produced during parsing.
    pub warnings_count: usize,
    /// Total bytes of bytecode across all methods.
    pub total_code_bytes: u64,
    /// Total instruction count across all methods.
    pub instruction_count: u64,
}

mod duration_ms_serde {
    use omnisec_json::JsonValue;
    use std::time::Duration;

    pub fn to_json(d: &Duration) -> JsonValue {
        JsonValue::UInt(d.as_millis() as u64)
    }
}

/// Proto — method prototype (shorty, return type, parameters).
#[derive(Debug, Clone, ToJson)]
pub struct Proto {
    /// Index into string table for the short-form descriptor.
    pub shorty_idx: u32,
    /// Index into type table for return type.
    pub return_type_idx: u32,
    /// File offset to parameter type list (0 = no params).
    pub parameters_off: u32,
    /// Short-form descriptor string.
    pub shorty: String,
    /// Return type descriptor.
    pub return_type: String,
    /// Parameter type descriptors.
    pub parameters: Vec<String>,
}

/// Field — field definition.
#[derive(Debug, Clone, ToJson)]
pub struct Field {
    /// Index into type table for the defining class.
    pub class_idx: u16,
    /// Index into type table for the field type.
    pub type_idx: u16,
    /// Index into string table for the field name.
    pub name_idx: u32,
    /// Resolved class name.
    pub class_name: String,
    /// Resolved type name.
    pub type_name: String,
    /// Resolved field name.
    pub field_name: String,
}

/// Method — method definition (from method_ids section).
#[derive(Debug, Clone, ToJson)]
pub struct Method {
    /// Index into type table for the defining class.
    pub class_idx: u16,
    /// Index into proto table.
    pub proto_idx: u16,
    /// Index into string table for the method name.
    pub name_idx: u32,
    /// Resolved class name.
    pub class_name: String,
    /// Resolved method name.
    pub method_name: String,
    /// Resolved return type.
    pub return_type: String,
    /// Resolved parameter types.
    pub parameters: Vec<String>,
}

/// ClassDef — class definition.
#[derive(Debug, Clone, ToJson)]
pub struct ClassDef {
    /// Index into type table for this class.
    pub class_idx: u32,
    /// Access flags (public, final, abstract, etc.).
    pub access_flags: u32,
    /// Index into type table for the superclass.
    pub superclass_idx: u32,
    /// File offset to interfaces type list.
    pub interfaces_off: u32,
    /// Index into string table for source file name.
    pub source_file_idx: u32,
    /// File offset to annotations directory.
    pub annotations_off: u32,
    /// File offset to class data.
    pub class_data_off: u32,
    /// File offset to static values.
    pub static_values_off: u32,

    /// Resolved class name.
    pub class_name: String,
    /// Resolved superclass name.
    pub super_class: String,
    /// Resolved source file name.
    pub source_file: String,
    /// Resolved interface names.
    pub interfaces: Vec<String>,
    /// Static fields with access flags.
    pub static_fields: Vec<EncodedField>,
    /// Instance fields with access flags.
    pub instance_fields: Vec<EncodedField>,
    /// Direct (static + private) methods with bytecode.
    pub direct_methods: Vec<EncodedMethod>,
    /// Virtual methods with bytecode.
    pub virtual_methods: Vec<EncodedMethod>,
}

/// EncodedField — field with access flags (from class_data).
#[derive(Debug, Clone, ToJson)]
pub struct EncodedField {
    /// Absolute field index (after delta decoding).
    pub field_idx: u32,
    /// Access flags.
    pub access_flags: u32,
    /// Resolved field name.
    pub name: String,
    /// Resolved field type.
    pub type_name: String,
    /// Resolved defining class name.
    pub class_name: String,
}

/// EncodedMethod — method with bytecode (from class_data).
#[derive(Debug, Clone, ToJson)]
pub struct EncodedMethod {
    /// Absolute method index (after delta decoding).
    pub method_idx: u32,
    /// Access flags.
    pub access_flags: u32,
    /// File offset to code item (0 = abstract/native).
    pub code_off: u32,
    /// Resolved method name.
    pub name: String,
    /// Resolved defining class name.
    pub class_name: String,
    /// Resolved return type.
    pub return_type: String,
    /// Resolved parameter types.
    pub parameters: Vec<String>,
    /// Parsed bytecode (None if abstract/native).
    pub code: Option<CodeItem>,
}

/// CodeItem — method bytecode and metadata.
#[derive(Debug, Clone, ToJson)]
pub struct CodeItem {
    /// Number of registers used.
    pub registers_size: u16,
    /// Number of incoming argument words.
    pub ins_size: u16,
    /// Number of outgoing argument words.
    pub outs_size: u16,
    /// Number of try/catch blocks.
    pub tries_size: u16,
    /// File offset to debug info.
    pub debug_info_off: u32,
    /// Number of 16-bit code units.
    pub insns_size: u32,
    /// Raw bytecode as 16-bit words.
    pub insns: Vec<u16>,
    /// Try/catch blocks.
    pub tries: Vec<TryItem>,
    /// Exception handlers.
    pub handlers: Vec<CatchHandler>,
}

/// TryItem — try/catch block.
#[derive(Debug, Clone, ToJson)]
pub struct TryItem {
    /// Start address (code unit index).
    pub start_addr: u32,
    /// Number of code units covered.
    pub insn_count: u16,
    /// Offset into handler list.
    pub handler_off: u16,
    /// Resolved catch handlers for this try block.
    pub catch_handlers: Vec<CatchHandler>,
}

/// CatchHandler — single exception handler.
#[derive(Debug, Clone, ToJson)]
pub struct CatchHandler {
    /// Type index (-1 for catch-all).
    pub type_idx: i32,
    /// Resolved exception type name.
    pub type_name: String,
    /// Handler address (code unit index).
    pub handler_addr: u32,
    /// Catch-all address (only if `has_catch_all`).
    pub catch_all_addr: u32,
    /// Whether this is a catch-all handler.
    pub has_catch_all: bool,
}

/// Complete parsed DEX file — the main output of the parser.
#[derive(Debug, Clone, ToJson)]
pub struct ParsedDex {
    /// DEX version string (e.g. "035", "039").
    pub version: String,
    /// All resolved strings from the string table.
    pub strings: Vec<String>,
    /// All resolved type descriptors.
    pub types: Vec<String>,
    /// All method prototypes.
    pub protos: Vec<Proto>,
    /// All field definitions.
    pub fields: Vec<Field>,
    /// All method definitions.
    pub methods: Vec<Method>,
    /// All class definitions (with class data filled in).
    pub classes: Vec<ClassDef>,
    /// Warnings accumulated during parsing.
    pub warnings: Vec<String>,
    /// Parse metrics.
    pub metrics: ParseMetrics,
}
