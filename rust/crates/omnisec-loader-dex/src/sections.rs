//! Section parsers — strings, types, protos, fields, methods, classes, class_data.

use crate::error::DexResult;
use crate::header::{DEX_NO_INDEX, DexHeader, bounds_ok, le_u16, le_u32, read_uleb128};
use crate::mutf8::decode_mutf8;
use crate::types::{ClassDef, CodeItem, EncodedField, EncodedMethod, Field, Method, Proto};

use std::sync::Mutex;

/// Parse all string entries from the string_ids section.
///
/// Uses rayon for parallel decoding when count >= 1000.
pub fn parse_strings(
    data: &[u8],
    header: &DexHeader,
    warnings: &Mutex<Vec<String>>,
) -> DexResult<Vec<String>> {
    let count = header.string_ids_size as usize;
    let off = header.string_ids_off;

    if count == 0 {
        return Ok(Vec::new());
    }

    // Collect string data offsets first
    let mut str_offsets = Vec::with_capacity(count);
    for i in 0..count {
        let pos = off + (i as u32) * 4;
        if !bounds_ok(data, pos, 4) {
            let mut w = warnings.lock().unwrap();
            w.push(format!("string_id[{i}]: offset out of bounds"));
            str_offsets.push(None);
            continue;
        }
        str_offsets.push(Some(le_u32(data, pos)));
    }

    // Decode strings (sequentially for safety — rayon can be added later)
    let mut strings = vec![String::new(); count];
    for (i, maybe_off) in str_offsets.iter().enumerate() {
        if let Some(str_data_off) = maybe_off {
            let (s, ws) = decode_mutf8(data, *str_data_off);
            if !ws.is_empty() {
                let mut w = warnings.lock().unwrap();
                for warning in ws {
                    w.push(format!("string[{i}]@0x{str_data_off:x}: {warning}"));
                }
            }
            strings[i] = s;
        }
    }

    Ok(strings)
}

/// Parse all type descriptors.
pub fn parse_types(
    data: &[u8],
    header: &DexHeader,
    strings: &[String],
    warnings: &Mutex<Vec<String>>,
) -> DexResult<Vec<String>> {
    let count = header.type_ids_size as usize;
    let mut types = vec![String::new(); count];

    for i in 0..count {
        let pos = header.type_ids_off + (i as u32) * 4;
        if !bounds_ok(data, pos, 4) {
            let mut w = warnings.lock().unwrap();
            w.push(format!("type_id[{i}]: offset out of bounds"));
            continue;
        }
        let str_idx = le_u32(data, pos) as usize;
        if str_idx < strings.len() {
            types[i] = strings[str_idx].clone();
        }
    }

    Ok(types)
}

/// Parse all method prototypes.
pub fn parse_protos(
    data: &[u8],
    header: &DexHeader,
    strings: &[String],
    types: &[String],
    warnings: &Mutex<Vec<String>>,
) -> DexResult<Vec<Proto>> {
    let count = header.proto_ids_size as usize;
    let mut protos = Vec::with_capacity(count);

    for i in 0..count {
        let pos = header.proto_ids_off + (i as u32) * 12;
        if !bounds_ok(data, pos, 12) {
            let mut w = warnings.lock().unwrap();
            w.push(format!("proto_id[{i}]: offset out of bounds"));
            protos.push(Proto {
                shorty_idx: 0,
                return_type_idx: 0,
                parameters_off: 0,
                shorty: String::new(),
                return_type: String::new(),
                parameters: Vec::new(),
            });
            continue;
        }

        let shorty_idx = le_u32(data, pos);
        let return_type_idx = le_u32(data, pos + 4);
        let parameters_off = le_u32(data, pos + 8);

        let shorty = get_string(strings, shorty_idx);
        let return_type = get_type(types, return_type_idx);

        let parameters = if parameters_off != 0 {
            if let Ok(params) = read_type_list(data, parameters_off, types) {
                params
            } else {
                let mut w = warnings.lock().unwrap();
                w.push(format!("proto[{i}] params: out of bounds"));
                Vec::new()
            }
        } else {
            Vec::new()
        };

        protos.push(Proto {
            shorty_idx,
            return_type_idx,
            parameters_off,
            shorty,
            return_type,
            parameters,
        });
    }

    Ok(protos)
}

/// Parse all field definitions.
pub fn parse_fields(
    data: &[u8],
    header: &DexHeader,
    strings: &[String],
    types: &[String],
    warnings: &Mutex<Vec<String>>,
) -> DexResult<Vec<Field>> {
    let count = header.field_ids_size as usize;
    let mut fields = Vec::with_capacity(count);

    for i in 0..count {
        let pos = header.field_ids_off + (i as u32) * 8;
        if !bounds_ok(data, pos, 8) {
            let mut w = warnings.lock().unwrap();
            w.push(format!("field_id[{i}]: offset out of bounds"));
            fields.push(Field {
                class_idx: 0,
                type_idx: 0,
                name_idx: 0,
                class_name: String::new(),
                type_name: String::new(),
                field_name: String::new(),
            });
            continue;
        }

        let class_idx = le_u16(data, pos);
        let type_idx = le_u16(data, pos + 2);
        let name_idx = le_u32(data, pos + 4);

        fields.push(Field {
            class_idx,
            type_idx,
            name_idx,
            class_name: get_type(types, u32::from(class_idx)),
            type_name: get_type(types, u32::from(type_idx)),
            field_name: get_string(strings, name_idx),
        });
    }

    Ok(fields)
}

/// Parse all method definitions.
pub fn parse_methods(
    data: &[u8],
    header: &DexHeader,
    strings: &[String],
    types: &[String],
    protos: &[Proto],
    warnings: &Mutex<Vec<String>>,
) -> DexResult<Vec<Method>> {
    let count = header.method_ids_size as usize;
    let mut methods = Vec::with_capacity(count);

    for i in 0..count {
        let pos = header.method_ids_off + (i as u32) * 8;
        if !bounds_ok(data, pos, 8) {
            let mut w = warnings.lock().unwrap();
            w.push(format!("method_id[{i}]: offset out of bounds"));
            methods.push(Method {
                class_idx: 0,
                proto_idx: 0,
                name_idx: 0,
                class_name: String::new(),
                method_name: String::new(),
                return_type: String::new(),
                parameters: Vec::new(),
            });
            continue;
        }

        let class_idx = le_u16(data, pos);
        let proto_idx = le_u16(data, pos + 2);
        let name_idx = le_u32(data, pos + 4);

        let (return_type, parameters) = if (proto_idx as usize) < protos.len() {
            let proto = &protos[proto_idx as usize];
            (proto.return_type.clone(), proto.parameters.clone())
        } else {
            (String::new(), Vec::new())
        };

        methods.push(Method {
            class_idx,
            proto_idx,
            name_idx,
            class_name: get_type(types, u32::from(class_idx)),
            method_name: get_string(strings, name_idx),
            return_type,
            parameters,
        });
    }

    Ok(methods)
}

/// Parse all class definitions (without class_data — that's a separate pass).
pub fn parse_classes(
    data: &[u8],
    header: &DexHeader,
    strings: &[String],
    types: &[String],
    warnings: &Mutex<Vec<String>>,
) -> DexResult<Vec<ClassDef>> {
    let count = header.class_defs_size as usize;
    let mut classes = Vec::with_capacity(count);

    for i in 0..count {
        let pos = header.class_defs_off + (i as u32) * 32;
        if !bounds_ok(data, pos, 32) {
            let mut w = warnings.lock().unwrap();
            w.push(format!("class_def[{i}]: offset out of bounds"));
            continue;
        }

        let class_idx = le_u32(data, pos);
        let access_flags = le_u32(data, pos + 4);
        let superclass_idx = le_u32(data, pos + 8);
        let interfaces_off = le_u32(data, pos + 12);
        let source_file_idx = le_u32(data, pos + 16);
        let annotations_off = le_u32(data, pos + 20);
        let class_data_off = le_u32(data, pos + 24);
        let static_values_off = le_u32(data, pos + 28);

        let class_name = get_type(types, class_idx);
        let super_class = if superclass_idx == DEX_NO_INDEX {
            String::new()
        } else {
            get_type(types, superclass_idx)
        };
        let source_file = if source_file_idx == DEX_NO_INDEX {
            String::new()
        } else {
            get_string(strings, source_file_idx)
        };
        let interfaces = if interfaces_off != 0 {
            read_type_list(data, interfaces_off, types).unwrap_or_else(|_| {
                let mut w = warnings.lock().unwrap();
                w.push(format!("class[{i}] interfaces: out of bounds"));
                Vec::new()
            })
        } else {
            Vec::new()
        };

        classes.push(ClassDef {
            class_idx,
            access_flags,
            superclass_idx,
            interfaces_off,
            source_file_idx,
            annotations_off,
            class_data_off,
            static_values_off,
            class_name,
            super_class,
            source_file,
            interfaces,
            static_fields: Vec::new(),
            instance_fields: Vec::new(),
            direct_methods: Vec::new(),
            virtual_methods: Vec::new(),
        });
    }

    Ok(classes)
}

/// Parse class_data for all classes that have one.
pub fn parse_all_class_data(
    data: &[u8],
    classes: &mut [ClassDef],
    fields: &[Field],
    methods: &[Method],
    warnings: &Mutex<Vec<String>>,
    metrics: &Mutex<(u64, u64)>, // (total_code_bytes, instruction_count)
) {
    for (i, class) in classes.iter_mut().enumerate() {
        if class.class_data_off == 0 || !bounds_ok(data, class.class_data_off, 4) {
            if class.class_data_off != 0 {
                let mut w = warnings.lock().unwrap();
                w.push(format!(
                    "class[{i}] class_data_off=0x{:x}: out of bounds",
                    class.class_data_off
                ));
            }
            continue;
        }

        if let Err(e) = parse_class_data(data, class, fields, methods, metrics) {
            let mut w = warnings.lock().unwrap();
            w.push(format!("class[{i}] {}: {e}", class.class_name));
        }
    }
}

/// Parse a single class_data_item.
fn parse_class_data(
    data: &[u8],
    class: &mut ClassDef,
    fields_table: &[Field],
    methods_table: &[Method],
    metrics: &Mutex<(u64, u64)>,
) -> Result<(), String> {
    let mut cursor = class.class_data_off;

    let (static_count, n) = read_uleb128(data, cursor);
    if n == 0 {
        return Err("bad ULEB128 for static_fields_size".into());
    }
    cursor += n as u32;

    let (instance_count, n) = read_uleb128(data, cursor);
    if n == 0 {
        return Err("bad ULEB128 for instance_fields_size".into());
    }
    cursor += n as u32;

    let (direct_count, n) = read_uleb128(data, cursor);
    if n == 0 {
        return Err("bad ULEB128 for direct_methods_size".into());
    }
    cursor += n as u32;

    let (virtual_count, n) = read_uleb128(data, cursor);
    if n == 0 {
        return Err("bad ULEB128 for virtual_methods_size".into());
    }
    cursor += n as u32;

    // OOM guard
    let data_len = data.len() as u64;
    for (name, count) in [
        ("static_fields", static_count),
        ("instance_fields", instance_count),
        ("direct_methods", direct_count),
        ("virtual_methods", virtual_count),
    ] {
        if u64::from(count) > data_len {
            return Err(format!("{name} count={count} impossible"));
        }
    }

    // Static fields
    let mut field_idx: u32 = 0;
    class.static_fields.reserve(static_count as usize);
    for _ in 0..static_count {
        let (ef, next) =
            read_encoded_field(data, cursor, field_idx, fields_table, &class.class_name)?;
        field_idx = ef.field_idx;
        cursor = next;
        class.static_fields.push(ef);
    }

    // Instance fields
    field_idx = 0;
    class.instance_fields.reserve(instance_count as usize);
    for _ in 0..instance_count {
        let (ef, next) =
            read_encoded_field(data, cursor, field_idx, fields_table, &class.class_name)?;
        field_idx = ef.field_idx;
        cursor = next;
        class.instance_fields.push(ef);
    }

    // Direct methods
    let mut method_idx: u32 = 0;
    class.direct_methods.reserve(direct_count as usize);
    for _ in 0..direct_count {
        let (em, next) = read_encoded_method(
            data,
            cursor,
            method_idx,
            methods_table,
            &class.class_name,
            metrics,
        )?;
        method_idx = em.method_idx;
        cursor = next;
        class.direct_methods.push(em);
    }

    // Virtual methods
    method_idx = 0;
    class.virtual_methods.reserve(virtual_count as usize);
    for _ in 0..virtual_count {
        let (em, next) = read_encoded_method(
            data,
            cursor,
            method_idx,
            methods_table,
            &class.class_name,
            metrics,
        )?;
        method_idx = em.method_idx;
        cursor = next;
        class.virtual_methods.push(em);
    }

    Ok(())
}

fn read_encoded_field(
    data: &[u8],
    cursor: u32,
    prev_idx: u32,
    fields_table: &[Field],
    class_name: &str,
) -> Result<(EncodedField, u32), String> {
    let (diff, n) = read_uleb128(data, cursor);
    if n == 0 {
        return Err("bad ULEB128 in encoded_field".into());
    }
    let mut pos = cursor + n as u32;

    let (flags, n) = read_uleb128(data, pos);
    if n == 0 {
        return Err("bad ULEB128 in encoded_field flags".into());
    }
    pos += n as u32;

    let field_idx = prev_idx + diff;
    let (name, type_name) = if (field_idx as usize) < fields_table.len() {
        let f = &fields_table[field_idx as usize];
        (f.field_name.clone(), f.type_name.clone())
    } else {
        (String::new(), String::new())
    };

    Ok((
        EncodedField {
            field_idx,
            access_flags: flags,
            name,
            type_name,
            class_name: class_name.to_string(),
        },
        pos,
    ))
}

fn read_encoded_method(
    data: &[u8],
    cursor: u32,
    prev_idx: u32,
    methods_table: &[Method],
    class_name: &str,
    metrics: &Mutex<(u64, u64)>,
) -> Result<(EncodedMethod, u32), String> {
    let (diff, n) = read_uleb128(data, cursor);
    if n == 0 {
        return Err("bad ULEB128 in encoded_method".into());
    }
    let mut pos = cursor + n as u32;

    let (flags, n) = read_uleb128(data, pos);
    if n == 0 {
        return Err("bad ULEB128 in encoded_method flags".into());
    }
    pos += n as u32;

    let (code_off, n) = read_uleb128(data, pos);
    if n == 0 {
        return Err("bad ULEB128 in encoded_method code_off".into());
    }
    pos += n as u32;

    let method_idx = prev_idx + diff;
    let (name, return_type, parameters) = if (method_idx as usize) < methods_table.len() {
        let m = &methods_table[method_idx as usize];
        (
            m.method_name.clone(),
            m.return_type.clone(),
            m.parameters.clone(),
        )
    } else {
        (String::new(), String::new(), Vec::new())
    };

    let code = if code_off != 0 && bounds_ok(data, code_off, 16) {
        match parse_code_item(data, code_off) {
            Ok(code) => {
                let mut m = metrics.lock().unwrap();
                m.0 += u64::from(code.insns_size) * 2;
                m.1 += u64::from(code.insns_size);
                Some(code)
            }
            Err(_) => None,
        }
    } else {
        None
    };

    Ok((
        EncodedMethod {
            method_idx,
            access_flags: flags,
            code_off,
            name,
            class_name: class_name.to_string(),
            return_type,
            parameters,
            code,
        },
        pos,
    ))
}

/// Parse a code_item at the given offset.
fn parse_code_item(data: &[u8], offset: u32) -> Result<CodeItem, String> {
    if !bounds_ok(data, offset, 16) {
        return Err("code_item out of bounds".into());
    }

    let registers_size = le_u16(data, offset);
    let ins_size = le_u16(data, offset + 2);
    let outs_size = le_u16(data, offset + 4);
    let tries_size = le_u16(data, offset + 6);
    let debug_info_off = le_u32(data, offset + 8);
    let insns_size = le_u32(data, offset + 12);

    let insns_start = offset + 16;
    let insns_bytes = u64::from(insns_size) * 2;

    if insns_bytes > data.len() as u64 {
        return Err(format!("insns_size={insns_size} impossible"));
    }

    let end = u64::from(insns_start) + insns_bytes;
    if end > data.len() as u64 {
        return Err(format!(
            "insns out of bounds: off=0x{insns_start:x} size={insns_size}"
        ));
    }

    // Copy bytecode as u16 words
    let mut insns = Vec::with_capacity(insns_size as usize);
    for i in 0..insns_size {
        let pos = insns_start + i * 2;
        insns.push(le_u16(data, pos));
    }

    Ok(CodeItem {
        registers_size,
        ins_size,
        outs_size,
        tries_size,
        debug_info_off,
        insns_size,
        insns,
        tries: Vec::new(),
        handlers: Vec::new(),
    })
}

/// Read a type_list from the given offset.
fn read_type_list(data: &[u8], offset: u32, types: &[String]) -> Result<Vec<String>, String> {
    if !bounds_ok(data, offset, 4) {
        return Err("type_list out of bounds".into());
    }
    let size = le_u32(data, offset);
    if size == 0 {
        return Ok(Vec::new());
    }
    if u64::from(size) * 2 > data.len() as u64 {
        return Err(format!("type_list size={size} impossible"));
    }

    let mut result = Vec::with_capacity(size as usize);
    let mut pos = offset + 4;
    for _ in 0..size {
        if !bounds_ok(data, pos, 2) {
            break;
        }
        let type_idx = u32::from(le_u16(data, pos));
        result.push(get_type(types, type_idx));
        pos += 2;
    }
    Ok(result)
}

#[inline]
fn get_string(strings: &[String], idx: u32) -> String {
    strings.get(idx as usize).cloned().unwrap_or_default()
}

#[inline]
fn get_type(types: &[String], idx: u32) -> String {
    types.get(idx as usize).cloned().unwrap_or_default()
}
