// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;
use tree_sitter::{Node, Parser};

use crate::file_extensions::is_supported_for_analysis;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileSurvey {
    pub file: String,
    pub functions_defined: Vec<(String, usize)>,
    pub calls: Vec<(String, usize)>,
    pub types_defined: Vec<(String, usize)>,
    pub types_mentioned: Vec<(String, usize)>,
    pub parse_errors: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SurveyLanguage {
    C,
    Cpp,
    Rust,
    Python,
    Zig,
}

impl SurveyLanguage {
    fn from_path(path: &Path) -> Option<Self> {
        match path.extension()?.to_str()? {
            "c" | "h" => Some(Self::C),
            "cpp" | "cc" | "cxx" | "c++" | "hh" | "hpp" | "hxx" | "h++" => Some(Self::Cpp),
            "rs" => Some(Self::Rust),
            "py" => Some(Self::Python),
            "zig" => Some(Self::Zig),
            _ => None,
        }
    }
}

#[derive(Default)]
struct SurveyBuilder {
    functions_defined: Vec<(String, usize)>,
    calls: BTreeMap<String, usize>,
    types_defined: Vec<(String, usize)>,
    types_mentioned: BTreeMap<String, usize>,
    parse_errors: usize,
}

/// Parse a source file under `workspace_root` and return a compact syntactic survey.
pub fn survey_file(workspace_root: &Path, requested_path: &Path) -> Result<FileSurvey> {
    let root = workspace_root
        .canonicalize()
        .with_context(|| format!("cannot resolve workspace '{}'", workspace_root.display()))?;
    let candidate = if requested_path.is_absolute() {
        requested_path.to_path_buf()
    } else {
        root.join(requested_path)
    };
    let path = candidate
        .canonicalize()
        .with_context(|| format!("cannot resolve source file '{}'", candidate.display()))?;

    if !path.starts_with(&root) {
        bail!(
            "source file '{}' is outside workspace '{}'",
            path.display(),
            root.display()
        );
    }
    if !path.is_file() {
        bail!("'{}' is not a regular file", path.display());
    }
    if !is_supported_for_analysis(path.to_string_lossy().as_ref()) {
        bail!(
            "unsupported source file '{}'; expected C, C++, Rust, Python, or Zig",
            path.display()
        );
    }

    let language = SurveyLanguage::from_path(&path)
        .ok_or_else(|| anyhow::anyhow!("unsupported source file '{}'", path.display()))?;
    let source = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read source file '{}'", path.display()))?;
    let mut parser = Parser::new();
    let grammar = match language {
        SurveyLanguage::C => tree_sitter_c::LANGUAGE.into(),
        SurveyLanguage::Cpp => tree_sitter_cpp::LANGUAGE.into(),
        SurveyLanguage::Rust => tree_sitter_rust::LANGUAGE.into(),
        SurveyLanguage::Python => tree_sitter_python::LANGUAGE.into(),
        SurveyLanguage::Zig => tree_sitter_zig::LANGUAGE.into(),
    };
    parser.set_language(&grammar)?;
    let tree = parser
        .parse(&source, None)
        .ok_or_else(|| anyhow::anyhow!("Tree-sitter failed to parse '{}'", path.display()))?;

    let mut builder = SurveyBuilder::default();
    walk(tree.root_node(), source.as_bytes(), language, &mut builder);

    builder.functions_defined.sort_by_key(|(_, line)| *line);
    builder.types_defined.sort_by_key(|(_, line)| *line);

    let calls = builder.calls.into_iter().collect();
    let types_mentioned = builder
        .types_mentioned
        .into_iter()
        .filter(|(name, _)| !is_basic_type(language, name))
        .collect();
    let file = path
        .strip_prefix(&root)
        .unwrap_or(&path)
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/");

    Ok(FileSurvey {
        file,
        functions_defined: builder
            .functions_defined
            .into_iter()
            .map(|(name, _)| (name, 0))
            .collect(),
        calls,
        types_defined: builder
            .types_defined
            .into_iter()
            .map(|(name, _)| (name, 0))
            .collect(),
        types_mentioned,
        parse_errors: builder.parse_errors,
        truncated: false,
    })
}

/// Add distinct git-aware caller and type-referencer counts to a syntactic survey.
pub async fn survey_file_with_references(
    workspace_root: &Path,
    requested_path: &Path,
    db: &crate::DatabaseManager,
    git_sha: &str,
) -> Result<FileSurvey> {
    let mut survey = survey_file(workspace_root, requested_path)?;
    let function_names: Vec<String> = survey
        .functions_defined
        .iter()
        .map(|(name, _)| name.clone())
        .collect();
    let type_names: Vec<String> = survey
        .types_defined
        .iter()
        .map(|(name, _)| reference_type_name(name).to_string())
        .collect();
    let (function_counts, type_counts) = db
        .get_distinct_reference_counts_git_aware(&function_names, &type_names, git_sha)
        .await?;

    for (name, count) in &mut survey.functions_defined {
        *count = function_counts.get(name).copied().unwrap_or_default();
    }
    for (name, count) in &mut survey.types_defined {
        *count = type_counts
            .get(reference_type_name(name))
            .copied()
            .unwrap_or_default();
    }
    Ok(survey)
}

fn reference_type_name(name: &str) -> &str {
    name.strip_prefix("struct ")
        .or_else(|| name.strip_prefix("union "))
        .or_else(|| name.strip_prefix("enum "))
        .or_else(|| name.strip_prefix("class "))
        .unwrap_or(name)
}

fn is_basic_type(language: SurveyLanguage, name: &str) -> bool {
    let name = name.trim();
    match language {
        // C++ widens C's scalars with the same names; the basics of one
        // are the basics of the other.
        SurveyLanguage::C | SurveyLanguage::Cpp => {
            const C_SCALARS: &[&str] = &[
                "void",
                "char",
                "signed char",
                "unsigned char",
                "short",
                "short int",
                "signed short",
                "signed short int",
                "unsigned short",
                "unsigned short int",
                "int",
                "signed",
                "signed int",
                "unsigned",
                "unsigned int",
                "long",
                "long int",
                "signed long",
                "signed long int",
                "unsigned long",
                "unsigned long int",
                "long long",
                "long long int",
                "signed long long",
                "signed long long int",
                "unsigned long long",
                "unsigned long long int",
                "float",
                "double",
                "long double",
                "_Bool",
                "bool",
                "wchar_t",
                "char8_t",
                "char16_t",
                "char32_t",
                "__int128",
                "unsigned __int128",
                "size_t",
                "ssize_t",
                "off_t",
                "loff_t",
                "ptrdiff_t",
                "intptr_t",
                "uintptr_t",
                "intmax_t",
                "uintmax_t",
            ];
            C_SCALARS.contains(&name) || is_fixed_width_integer(name)
        }
        SurveyLanguage::Rust => matches!(
            name,
            "()" | "!"
                | "bool"
                | "char"
                | "str"
                | "i8"
                | "i16"
                | "i32"
                | "i64"
                | "i128"
                | "isize"
                | "u8"
                | "u16"
                | "u32"
                | "u64"
                | "u128"
                | "usize"
                | "f32"
                | "f64"
        ),
        SurveyLanguage::Python => matches!(
            name,
            "None" | "bool" | "int" | "float" | "complex" | "str" | "bytes" | "bytearray"
        ),
        SurveyLanguage::Zig => is_zig_basic_type(name),
    }
}

fn is_zig_basic_type(name: &str) -> bool {
    matches!(
        name,
        "bool"
            | "f16"
            | "f32"
            | "f64"
            | "f128"
            | "void"
            | "type"
            | "anyerror"
            | "anyopaque"
            | "anytype"
            | "noreturn"
            | "isize"
            | "usize"
            | "comptime_int"
            | "comptime_float"
            | "c_short"
            | "c_ushort"
            | "c_int"
            | "c_uint"
            | "c_long"
            | "c_ulong"
            | "c_longlong"
            | "c_ulonglong"
            | "c_longdouble"
    ) || is_zig_integer_type(name)
}

fn is_zig_integer_type(name: &str) -> bool {
    let Some(digits) = name.strip_prefix('i').or_else(|| name.strip_prefix('u')) else {
        return false;
    };
    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
}

fn is_fixed_width_integer(name: &str) -> bool {
    let name = name.strip_prefix("__").unwrap_or(name);
    if let Some(width) = name.strip_prefix('u').or_else(|| name.strip_prefix('s')) {
        return matches!(width, "8" | "16" | "32" | "64" | "128");
    }
    if let Some(width) = name
        .strip_prefix("uint")
        .or_else(|| name.strip_prefix("int"))
        .and_then(|name| name.strip_suffix("_t"))
    {
        return matches!(width, "8" | "16" | "32" | "64" | "128");
    }
    false
}

fn walk(node: Node<'_>, source: &[u8], language: SurveyLanguage, out: &mut SurveyBuilder) {
    if node.is_error() || node.is_missing() {
        out.parse_errors += 1;
    }

    match language {
        // tree-sitter-cpp shares tree-sitter-c's node kinds for these
        // shapes and adds class_specifier, which the C grammar never
        // produces.
        SurveyLanguage::C | SurveyLanguage::Cpp => extract_c(node, source, out),
        SurveyLanguage::Rust => extract_rust(node, source, out),
        SurveyLanguage::Python => extract_python(node, source, out),
        SurveyLanguage::Zig => extract_zig(node, source, out),
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, source, language, out);
    }
}

fn extract_c(node: Node<'_>, source: &[u8], out: &mut SurveyBuilder) {
    match node.kind() {
        "function_definition" => {
            if let Some(name) = function_name(node, source) {
                out.functions_defined.push((name, line(node)));
            }
        }
        "call_expression" => record_call(node, source, out),
        "struct_specifier" | "union_specifier" | "enum_specifier" | "class_specifier" => {
            let prefix = match node.kind() {
                "struct_specifier" => "struct",
                "union_specifier" => "union",
                "class_specifier" => "class",
                _ => "enum",
            };
            if node.child_by_field_name("body").is_some() {
                if let Some(name) = node
                    .child_by_field_name("name")
                    .and_then(|n| text(n, source))
                {
                    out.types_defined
                        .push((format!("{prefix} {name}"), line(node)));
                }
            } else if let Some(value) = text(node, source) {
                increment(&mut out.types_mentioned, value);
            }
        }
        "type_definition" => {
            let mut cursor = node.walk();
            for declarator in node.children_by_field_name("declarator", &mut cursor) {
                if let Some(name) = declarator_name(declarator, source) {
                    out.types_defined.push((name, line(node)));
                }
            }
        }
        "type_identifier" => {
            if !has_ancestor(node, "type_definition")
                && !matches!(
                    node.parent().map(|p| p.kind()),
                    Some(
                        "struct_specifier"
                            | "union_specifier"
                            | "enum_specifier"
                            | "class_specifier"
                    )
                )
            {
                if let Some(value) = text(node, source) {
                    increment(&mut out.types_mentioned, value);
                }
            }
        }
        "primitive_type" | "sized_type_specifier" => {
            if let Some(value) = text(node, source) {
                increment(&mut out.types_mentioned, value);
            }
        }
        _ => {}
    }
}

fn extract_rust(node: Node<'_>, source: &[u8], out: &mut SurveyBuilder) {
    match node.kind() {
        "function_item" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| text(n, source))
            {
                out.functions_defined.push((name, line(node)));
            }
        }
        "call_expression" => record_call(node, source, out),
        "struct_item" | "enum_item" | "union_item" | "type_item" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| text(n, source))
            {
                let prefix = match node.kind() {
                    "struct_item" => "struct ",
                    "enum_item" => "enum ",
                    "union_item" => "union ",
                    _ => "",
                };
                out.types_defined
                    .push((format!("{prefix}{name}"), line(node)));
            }
        }
        "type_identifier" | "primitive_type"
            if !matches!(
                node.parent().map(|p| p.kind()),
                Some("struct_item" | "enum_item" | "union_item" | "type_item")
            ) =>
        {
            if let Some(value) = text(node, source) {
                increment(&mut out.types_mentioned, value);
            }
        }
        _ => {}
    }
}

fn extract_python(node: Node<'_>, source: &[u8], out: &mut SurveyBuilder) {
    match node.kind() {
        "function_definition" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| text(n, source))
            {
                out.functions_defined.push((name, line(node)));
            }
        }
        "call" => record_call(node, source, out),
        "class_definition" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| text(n, source))
            {
                out.types_defined
                    .push((format!("class {name}"), line(node)));
            }
        }
        "type" => {
            if let Some(value) = text(node, source) {
                increment(&mut out.types_mentioned, value);
            }
        }
        _ => {}
    }
}

fn extract_zig(node: Node<'_>, source: &[u8], out: &mut SurveyBuilder) {
    match node.kind() {
        "function_declaration" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| text(n, source))
            {
                out.functions_defined.push((name, line(node)));
            }
        }
        "test_declaration" => {
            if let Some(name) = node
                .named_child(0)
                .filter(|n| matches!(n.kind(), "string" | "identifier"))
                .and_then(|n| text(n, source))
            {
                out.functions_defined.push((name, line(node)));
            }
        }
        "call_expression" => record_call(node, source, out),
        "builtin_function" => {
            if let Some(name) = node.named_child(0).and_then(|n| text(n, source)) {
                increment(&mut out.calls, name);
            }
        }
        "variable_declaration" => {
            if let Some(name) = zig_type_binding(node, source) {
                out.types_defined.push((name, line(node)));
            }
        }
        "builtin_type" => {
            if let Some(value) = text(node, source) {
                increment(&mut out.types_mentioned, value);
            }
        }
        _ => {}
    }
}

fn zig_type_binding(node: Node<'_>, source: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    let is_type = node.children(&mut cursor).any(|child| {
        matches!(
            child.kind(),
            "struct_declaration"
                | "enum_declaration"
                | "union_declaration"
                | "opaque_declaration"
                | "error_set_declaration"
        ) || zig_type_builtin(child, source)
    });
    if !is_type {
        return None;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "identifier" {
            return text(child, source);
        }
    }
    None
}

fn zig_type_builtin(node: Node<'_>, source: &[u8]) -> bool {
    if node.kind() != "builtin_function" {
        return false;
    }
    node.named_child(0)
        .and_then(|n| n.utf8_text(source).ok())
        .is_some_and(|name| {
            matches!(
                name,
                "@Int"
                    | "@Struct"
                    | "@Union"
                    | "@Enum"
                    | "@Tuple"
                    | "@Pointer"
                    | "@Fn"
                    | "@EnumLiteral"
                    | "@Type"
            )
        })
}

fn record_call(node: Node<'_>, source: &[u8], out: &mut SurveyBuilder) {
    if let Some(value) = node
        .child_by_field_name("function")
        .and_then(|n| text(n, source))
    {
        increment(&mut out.calls, value);
    }
}

fn function_name(node: Node<'_>, source: &[u8]) -> Option<String> {
    let declarator = find_descendant(node, "function_declarator")?;
    declarator
        .child_by_field_name("declarator")
        .and_then(|n| declarator_name(n, source))
}

fn declarator_name(node: Node<'_>, source: &[u8]) -> Option<String> {
    if matches!(
        node.kind(),
        "identifier" | "field_identifier" | "type_identifier" | "qualified_identifier"
    ) {
        return text(node, source);
    }
    if let Some(child) = node.child_by_field_name("declarator") {
        if let Some(name) = declarator_name(child, source) {
            return Some(name);
        }
    }
    let mut cursor = node.walk();
    let result = node
        .named_children(&mut cursor)
        .find_map(|child| declarator_name(child, source));
    result
}

fn find_descendant<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    if node.kind() == kind {
        return Some(node);
    }
    let mut cursor = node.walk();
    let result = node
        .named_children(&mut cursor)
        .find_map(|child| find_descendant(child, kind));
    result
}

fn has_ancestor(mut node: Node<'_>, kind: &str) -> bool {
    while let Some(parent) = node.parent() {
        if parent.kind() == kind {
            return true;
        }
        node = parent;
    }
    false
}

fn text(node: Node<'_>, source: &[u8]) -> Option<String> {
    let value = node.utf8_text(source).ok()?;
    Some(normalize(value))
}

fn normalize(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn line(node: Node<'_>) -> usize {
    node.start_position().row + 1
}

fn increment(values: &mut BTreeMap<String, usize>, value: String) {
    if !value.is_empty() {
        *values.entry(value).or_default() += 1;
    }
}

pub fn survey_file_json(workspace_root: &Path, requested_path: &Path) -> Result<String> {
    Ok(serde_json::to_string(&survey_file(
        workspace_root,
        requested_path,
    )?)?)
}

pub async fn survey_file_json_with_references(
    workspace_root: &Path,
    requested_path: &Path,
    db: &crate::DatabaseManager,
    git_sha: &str,
) -> Result<String> {
    Ok(serde_json::to_string(
        &survey_file_with_references(workspace_root, requested_path, db, git_sha).await?,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn surveys_c_syntax_deterministically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sample.c");
        std::fs::write(
            &path,
            r#"
struct item { int value; };
typedef unsigned long item_id, *item_ptr;
int declared(struct item *item);
int defined(struct item *item)
{
    helper(item);
    helper(item);
    item->ops->run(item);
    return 0;
}
"#,
        )
        .unwrap();

        let survey = survey_file(dir.path(), Path::new("sample.c")).unwrap();
        assert_eq!(survey.file, "sample.c");
        assert_eq!(survey.functions_defined, vec![("defined".to_string(), 0)]);
        assert_eq!(
            survey.calls,
            vec![("helper".to_string(), 2), ("item->ops->run".to_string(), 1)]
        );
        assert_eq!(
            survey.types_defined,
            vec![
                ("struct item".to_string(), 0),
                ("item_id".to_string(), 0),
                ("item_ptr".to_string(), 0),
            ]
        );
        assert_eq!(survey.parse_errors, 0);
        assert!(!survey.truncated);
        let json = serde_json::to_value(&survey).unwrap();
        assert!(json.get("functions_declared").is_none());
        assert_eq!(json["functions_defined"][0].as_array().unwrap().len(), 2);
        assert_eq!(json["types_defined"][0].as_array().unwrap().len(), 2);
        let compact = survey_file_json(dir.path(), Path::new("sample.c")).unwrap();
        assert!(!compact.contains('\n'));
        assert!(!compact.contains(": "));
    }

    #[test]
    fn rejects_paths_outside_workspace() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let error = survey_file(workspace.path(), outside.path()).unwrap_err();
        assert!(error.to_string().contains("outside workspace"));
    }

    #[test]
    fn returns_more_than_500_unique_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.c");
        let calls = (0..600)
            .map(|index| format!("    function_{index}();\n"))
            .collect::<String>();
        std::fs::write(&path, format!("void survey(void)\n{{\n{calls}}}\n")).unwrap();

        let survey = survey_file(dir.path(), Path::new("large.c")).unwrap();
        assert_eq!(survey.calls.len(), 600);
        assert_eq!(survey.calls.first().unwrap().0, "function_0");
        assert_eq!(survey.calls.last().unwrap().0, "function_99");
        assert!(!survey.truncated);
    }

    #[test]
    fn omits_basic_types() {
        for name in [
            "int",
            "unsigned long",
            "unsigned long long",
            "u8",
            "u64",
            "int32_t",
            "__u32",
            "size_t",
            "ssize_t",
            "off_t",
            "loff_t",
        ] {
            assert!(is_basic_type(SurveyLanguage::C, name), "{name}");
        }
        for name in ["u8", "i64", "usize", "bool", "char", "f32"] {
            assert!(is_basic_type(SurveyLanguage::Rust, name), "{name}");
        }
        for name in ["int", "float", "str", "bytes", "None"] {
            assert!(is_basic_type(SurveyLanguage::Python, name), "{name}");
        }
        for name in ["u8", "i3", "usize", "bool", "f32", "anyerror", "void"] {
            assert!(is_basic_type(SurveyLanguage::Zig, name), "{name}");
        }
        for name in ["struct folio", "vm_fault_t", "sector_t"] {
            assert!(!is_basic_type(SurveyLanguage::C, name), "{name}");
        }
        for name in ["Allocator", "Io"] {
            assert!(!is_basic_type(SurveyLanguage::Zig, name), "{name}");
        }
    }

    #[test]
    fn surveys_zig_syntax_deterministically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sample.zig");
        std::fs::write(
            &path,
            r#"
const Point = struct {
    x: i32,
    y: i32,
};

const Bits = packed union(u2) {
    a: i2,
    b: u2,
};

const Width = @Int(.unsigned, 10);

pub fn add(a: i32, b: i32) i32 {
    return helper(a) + b;
}

fn helper(v: i32) i32 {
    return v;
}

test "add" {
    _ = add(1, 2);
}
"#,
        )
        .unwrap();

        let survey = survey_file(dir.path(), Path::new("sample.zig")).unwrap();
        assert_eq!(survey.file, "sample.zig");
        assert!(survey.functions_defined.iter().any(|(n, _)| n == "add"));
        assert!(survey.functions_defined.iter().any(|(n, _)| n == "helper"));
        assert!(survey.functions_defined.iter().any(|(n, _)| n == "\"add\""));
        assert!(survey.calls.iter().any(|(n, _)| n == "helper"));
        assert!(survey.calls.iter().any(|(n, _)| n == "add"));
        assert!(survey.types_defined.iter().any(|(n, _)| n == "Point"));
        assert!(survey.types_defined.iter().any(|(n, _)| n == "Bits"));
        assert!(survey.types_defined.iter().any(|(n, _)| n == "Width"));
        assert_eq!(survey.parse_errors, 0);
    }
}
