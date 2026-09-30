// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::Result;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use streaming_iterator::StreamingIterator;
use tree_sitter::{Parser, Query, QueryCursor, Tree};

use crate::types::{
    ArgumentFunction, DispatchKind, DispatchSite, FieldInfo, FunctionInfo, GlobalTypeRegistry,
    GlobalVariable, MacroParams, ParameterInfo, Registration, RegistrationKind, TypeInfo,
    ARRAY_ELEMENT_MEMBER, STATIC_CALL_MEMBER,
};
// TemporaryCallRelationship import removed - call relationships are now embedded in function JSON columns
use crate::hash::compute_file_hash;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    C,
    Rust,
    Python,
    Zig,
}

impl Language {
    /// Detect language from file extension
    pub fn from_path(path: &Path) -> Option<Self> {
        path.extension()
            .and_then(|ext| ext.to_str())
            .and_then(|ext| match ext {
                "c" | "h" | "cpp" | "cc" | "cxx" | "c++" | "hh" | "hpp" | "hxx" | "h++" => {
                    Some(Language::C)
                }
                "rs" => Some(Language::Rust),
                "py" => Some(Language::Python),
                "zig" => Some(Language::Zig),
                _ => None,
            })
    }
}

/// Context for extracting code elements from a parsed tree
pub struct ExtractionContext<'a> {
    pub tree: &'a Tree,
    pub source: &'a str,
    pub file_path: &'a Path,
    pub git_hash: &'a str,
    pub source_root: Option<&'a Path>,
    pub language: Language,
}

struct LanguageQueries {
    function_query: Query,
    comment_query: Query,
    type_query: Query,
    typedef_query: Option<Query>, // Not needed for Rust
    macro_query: Query,
    call_query: Query,
}

/// What macro extraction yields: the macros themselves and the facts their
/// bodies hold, which belong to the same tables as any other code's.
type ExtractedMacros = (
    Vec<FunctionInfo>,
    Vec<DispatchSite>,
    Vec<Registration>,
    Vec<ArgumentFunction>,
    Vec<crate::types::UnresolvedEdge>,
);

/// What a healed parse adds to a file's macros: the definitions the original
/// parse could not see, and what their bodies do.
#[derive(Debug, Default)]
struct GraftedMacros {
    macros: Vec<FunctionInfo>,
    dispatch_sites: Vec<DispatchSite>,
    registrations: Vec<Registration>,
    argument_functions: Vec<ArgumentFunction>,
    unresolved_edges: Vec<crate::types::UnresolvedEdge>,
}

impl GraftedMacros {
    /// A graft that was refused: the original macros, and nothing from the
    /// healed tree.
    fn keeping(macros: Vec<FunctionInfo>) -> Self {
        Self {
            macros,
            ..Default::default()
        }
    }
}

/// What one file yields.
#[derive(Debug, Default)]
pub struct FileAnalysis {
    pub functions: Vec<FunctionInfo>,
    pub types: Vec<TypeInfo>,
    pub macros: Vec<FunctionInfo>,
    /// Calls that dispatch through a value; their targets are resolved later.
    pub dispatch_sites: Vec<DispatchSite>,
    /// Functions installed in struct members: what those sites can reach.
    pub registrations: Vec<Registration>,
    /// Functions named as call arguments: what a callee was handed.
    pub argument_functions: Vec<ArgumentFunction>,
    /// Edges that cannot be recorded, with where to look for the other side.
    pub unresolved_edges: Vec<crate::types::UnresolvedEdge>,
    /// File-scope variables of aggregate type.
    pub globals: Vec<GlobalVariable>,
}

/// Calls found in one file: resolved edges, and dispatch sites whose targets
/// are not known until query time.
#[derive(Debug, Default)]
struct CallExtraction {
    calls: Vec<(String, usize, usize)>,
    member_sites: Vec<RawDispatchSite>,
    /// Function-pointer variables declared in this file, so that a call
    /// naming one of them is recognised as dispatch rather than a call to a
    /// function of that name.
    pointer_vars: Vec<PointerVar>,
    registrations: Vec<RawRegistration>,
    argument_functions: Vec<RawArgumentFunction>,
}

/// What a macro body yields once parsed.
#[derive(Debug, Default)]
struct MacroBodyFacts {
    calls: Vec<String>,
    types: Vec<String>,
    sites: Vec<RawDispatchSite>,
    registrations: Vec<RawRegistration>,
    argument_functions: Vec<RawArgumentFunction>,
}

/// A designated initializer before it is attributed to a function.
#[derive(Debug, Clone)]
struct RawRegistration {
    container_type: String,
    /// For `base->field->member = f`: what the file proves about the base,
    /// and the path of fields read from it. Set only when `container_type`
    /// could not be read from the file directly.
    container_base_type: Option<String>,
    container_field: Option<String>,
    member: String,
    target: String,
    byte_start: usize,
    line: u32,
    kind: RegistrationKind,
}

impl RawRegistration {
    fn attribute(&self, enclosing: &str, file_path: &str, git_hash: &str) -> Registration {
        Registration {
            container_type: self.container_type.clone(),
            container_base_type: self.container_base_type.clone(),
            container_field: self.container_field.clone(),
            member: self.member.clone(),
            target: self.target.clone(),
            file_path: file_path.to_string(),
            git_file_hash: git_hash.to_string(),
            byte_start: self.byte_start as u64,
            line: self.line,
            enclosing_function: enclosing.to_string(),
            kind: self.kind,
        }
    }
}

/// What a function does with a parameter it is given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterFate {
    /// Written into a struct member, which is where a dispatch site finds it.
    StoredIn {
        /// Empty where the body alone does not say what the container is.
        container_type: String,
        member: String,
    },
    /// Passed to another call, which is how a wrapper registers.
    HandedOn { callee: String, argument_index: u32 },
    /// Called directly.
    Invoked,
}

/// What one pass over a file's functions yields.
#[derive(Debug, Default)]
struct ExtractedFunctions {
    functions: Vec<FunctionInfo>,
    dispatch_sites: Vec<DispatchSite>,
    registrations: Vec<Registration>,
    argument_functions: Vec<ArgumentFunction>,
}

/// A function whose definition a macro opens.
#[derive(Debug, Clone)]
struct MacroDefinedFunction {
    name: String,
    start_byte: usize,
    end_byte: usize,
    line_start: u32,
    line_end: u32,
    guard: Option<String>,
}

/// A file-scope variable, before its file is known.
#[derive(Debug, Clone)]
struct RawGlobal {
    name: String,
    type_name: String,
    line: u32,
}

/// A call argument naming an identifier, before it is attributed to the
/// function containing the call.
#[derive(Debug, Clone)]
struct RawArgumentFunction {
    callee: String,
    target: String,
    argument_index: u32,
    taken_address: bool,
    subject_type: Option<String>,
    subject_member: Option<String>,
    byte_start: usize,
    line: u32,
}

impl RawArgumentFunction {
    fn attribute(&self, enclosing: &str, file_path: &str, git_hash: &str) -> ArgumentFunction {
        ArgumentFunction {
            target: self.target.clone(),
            callee: self.callee.clone(),
            argument_index: self.argument_index,
            taken_address: self.taken_address,
            subject_type: self.subject_type.clone(),
            subject_member: self.subject_member.clone(),
            file_path: file_path.to_string(),
            git_file_hash: git_hash.to_string(),
            byte_start: self.byte_start as u64,
            line: self.line,
            enclosing_function: enclosing.to_string(),
        }
    }
}

/// Names bound to values, by scope, used to tell an argument that names a
/// function from one that names a variable.
struct ValueNames {
    file_scope: HashSet<String>,
    per_function: Vec<(usize, usize, HashSet<String>)>,
}

impl ValueNames {
    fn contains(&self, name: &str, at: usize) -> bool {
        self.file_scope.contains(name)
            || self
                .per_function
                .iter()
                .any(|(start, end, names)| at >= *start && at < *end && names.contains(name))
    }
}

/// A declared function-pointer variable or parameter.
#[derive(Debug, Clone)]
struct PointerVar {
    name: String,
    /// Where the declaration sits, used to scope it to its function.
    byte_start: usize,
    /// The function it is initialised with, when the declaration says.
    target: Option<String>,
    is_parameter: bool,
}

/// A dispatch site before it is attributed to the function containing it.
#[derive(Debug, Clone)]
struct RawDispatchSite {
    member: String,
    receiver_expr: Option<String>,
    /// The struct or union the receiver was declared as, when the file says
    /// so. Filled in after extraction, once the declarations are in scope.
    receiver_type: Option<String>,
    /// For `base->field->member()`, what the file proves about `base` and
    /// which field the receiver reads from it.
    receiver_base_type: Option<String>,
    receiver_field: Option<String>,
    kind: DispatchKind,
    byte_start: usize,
    line: u32,
    target: Option<String>,
}

impl RawDispatchSite {
    fn attribute(&self, caller_name: &str, file_path: &str, git_hash: &str) -> DispatchSite {
        DispatchSite {
            caller_name: caller_name.to_string(),
            file_path: file_path.to_string(),
            git_file_hash: git_hash.to_string(),
            byte_start: self.byte_start as u64,
            line: self.line,
            member: self.member.clone(),
            receiver_expr: self.receiver_expr.clone(),
            receiver_type: self.receiver_type.clone(),
            receiver_base_type: self.receiver_base_type.clone(),
            receiver_field: self.receiver_field.clone(),
            kind: self.kind,
            target: self.target.clone(),
        }
    }
}

/// An identifier and nothing else: `ops`, but not `ops->fn` or `get()`.
fn is_plain_name(text: &str) -> bool {
    !text.is_empty()
        && !text.starts_with(|c: char| c.is_numeric())
        && text.chars().all(|c| c.is_alphanumeric() || c == '_')
}

/// `base->field`, `base.field`, or a longer chain of them: the base and the
/// fields read from it, in order.
///
/// `display->parent->dsb` gives `display` and `parent.dsb`. Every part has to
/// be a plain name — an index, a call or a cast in the middle needs more than
/// a field lookup, and the whole receiver is left untyped rather than
/// half-read.
fn field_path(text: &str) -> Option<(&str, String)> {
    let mut parts = text.split("->").flat_map(|part| part.split('.'));

    let base = parts.next()?;
    if !is_plain_name(base) {
        return None;
    }

    let fields: Vec<&str> = parts.collect();
    if fields.is_empty() || !fields.iter().all(|field| is_plain_name(field)) {
        return None;
    }

    Some((base, fields.join(".")))
}

/// Collapse runs of whitespace (including newlines) into single spaces.
fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub struct TreeSitterAnalyzer {
    c_parser: Parser,
    rust_parser: Parser,
    python_parser: Parser,
    zig_parser: Parser,
    c_queries: &'static LanguageQueries,
    rust_queries: &'static LanguageQueries,
    python_queries: &'static LanguageQueries,
    zig_queries: &'static LanguageQueries,
}

/// A table of function pointers, and the typedef that hid that fact when the
/// declaration did not spell it out.
struct Table {
    name: String,
    /// The element type, when it is a name defined elsewhere. `None` means
    /// the declarator itself said the elements are functions.
    element_type: Option<String>,
}

/// Rounds of blanking a file gets before recovery gives up on it.
///
/// Measured over Linux 28a2bc7211da, where 1,639 files enter recovery: a cap
/// of one reads 572 recovered names in 110 files, two reads 673 in 136, and
/// four reads 681 in 139 and is where it stops improving. The last two rounds
/// buy 8 names for 317 of the 2,003 second parses, which is a rounding error
/// against the cost of indexing the tree at all -- so this is set where
/// recovery stops finding rather than where the returns thin out.
const HEAL_ROUND_CAP: usize = 4;

impl TreeSitterAnalyzer {
    pub fn new() -> Result<Self> {
        // Initialize C parser and queries
        let c_language = tree_sitter_c::LANGUAGE.into();
        let mut c_parser = Parser::new();
        c_parser.set_language(&c_language)?;

        // Initialize Rust parser and queries
        let rust_language = tree_sitter_rust::LANGUAGE.into();
        let mut rust_parser = Parser::new();
        rust_parser.set_language(&rust_language)?;

        // Initialize Python parser and queries
        let python_language = tree_sitter_python::LANGUAGE.into();
        let mut python_parser = Parser::new();
        python_parser.set_language(&python_language)?;

        // Initialize Zig parser and queries (Zig 0.16 syntax)
        let zig_language = tree_sitter_zig::LANGUAGE.into();
        let mut zig_parser = Parser::new();
        zig_parser.set_language(&zig_language)?;

        // Compiled once for the process, not once per analyzer: see
        // c_queries() below.
        let c_queries = Self::c_queries()?;
        let rust_queries = Self::rust_queries()?;
        let python_queries = Self::python_queries()?;
        let zig_queries = Self::zig_queries()?;

        Ok(TreeSitterAnalyzer {
            c_parser,
            rust_parser,
            python_parser,
            zig_parser,
            c_queries,
            rust_queries,
            python_queries,
            zig_queries,
        })
    }

    /// Compiled queries for one language, built on first use and shared by
    /// every analyzer after that.
    ///
    /// Every file is analyzed with the same queries, and compiling them is
    /// what building an analyzer costs, so they are built once rather than
    /// once per file. A `Query` is immutable and `Send + Sync`, so one copy
    /// serves every thread; a `Parser` is neither, and stays per-analyzer.
    ///
    /// `OnceLock` takes no fallible initialiser, so a compile failure is kept
    /// as its message and returned to each caller.
    fn c_queries() -> Result<&'static LanguageQueries> {
        static QUERIES: std::sync::OnceLock<std::result::Result<LanguageQueries, String>> =
            std::sync::OnceLock::new();
        QUERIES
            .get_or_init(|| {
                Self::create_c_queries(&tree_sitter_c::LANGUAGE.into()).map_err(|e| e.to_string())
            })
            .as_ref()
            .map_err(|e| anyhow::anyhow!("C queries: {e}"))
    }

    fn rust_queries() -> Result<&'static LanguageQueries> {
        static QUERIES: std::sync::OnceLock<std::result::Result<LanguageQueries, String>> =
            std::sync::OnceLock::new();
        QUERIES
            .get_or_init(|| {
                Self::create_rust_queries(&tree_sitter_rust::LANGUAGE.into())
                    .map_err(|e| e.to_string())
            })
            .as_ref()
            .map_err(|e| anyhow::anyhow!("Rust queries: {e}"))
    }

    fn python_queries() -> Result<&'static LanguageQueries> {
        static QUERIES: std::sync::OnceLock<std::result::Result<LanguageQueries, String>> =
            std::sync::OnceLock::new();
        QUERIES
            .get_or_init(|| {
                Self::create_python_queries(&tree_sitter_python::LANGUAGE.into())
                    .map_err(|e| e.to_string())
            })
            .as_ref()
            .map_err(|e| anyhow::anyhow!("Python queries: {e}"))
    }

    fn zig_queries() -> Result<&'static LanguageQueries> {
        static QUERIES: std::sync::OnceLock<std::result::Result<LanguageQueries, String>> =
            std::sync::OnceLock::new();
        QUERIES
            .get_or_init(|| {
                Self::create_zig_queries(&tree_sitter_zig::LANGUAGE.into())
                    .map_err(|e| e.to_string())
            })
            .as_ref()
            .map_err(|e| anyhow::anyhow!("Zig queries: {e}"))
    }

    fn create_c_queries(language: &tree_sitter::Language) -> Result<LanguageQueries> {
        // Query for function definitions - handles both regular and inline functions
        let function_query = Query::new(
            language,
            r#"
            ; Standard function definitions with bodies
            (function_definition
                type: (_) @return_type
                declarator: (function_declarator
                    declarator: (identifier) @function_name
                    parameters: (parameter_list) @parameters
                )
                body: (compound_statement) @body
            ) @function

            ; Function pointers with bodies (single level)
            (function_definition
                type: (_) @return_type
                declarator: (pointer_declarator
                    declarator: (function_declarator
                        declarator: (identifier) @function_name
                        parameters: (parameter_list) @parameters
                    )
                )
                body: (compound_statement) @body
            ) @function_ptr

            ; Function pointers with bodies (double level, e.g. struct fsverity_info **)
            (function_definition
                type: (_) @return_type
                declarator: (pointer_declarator
                    declarator: (pointer_declarator
                        declarator: (function_declarator
                            declarator: (identifier) @function_name
                            parameters: (parameter_list) @parameters
                        )
                    )
                )
                body: (compound_statement) @body
            ) @function_ptr2

            ; Function declarations without bodies (prototypes only)
            (declaration
                type: (_) @return_type
                declarator: (function_declarator
                    declarator: (identifier) @function_name
                    parameters: (parameter_list) @parameters
                )
            ) @declaration
        "#,
        )?;

        // Query for comments
        let comment_query = Query::new(
            language,
            r#"
            (comment) @comment
        "#,
        )?;

        // Query for struct/union/enum definitions
        let type_query = Query::new(
            language,
            r#"
            (struct_specifier
                name: (type_identifier) @type_name
                body: (field_declaration_list) @body
            ) @struct

            (union_specifier
                name: (type_identifier) @type_name
                body: (field_declaration_list) @body
            ) @union

            (enum_specifier
                name: (type_identifier) @type_name
                body: (enumerator_list) @body
            ) @enum
        "#,
        )?;

        // Query for typedef definitions
        let typedef_query = Query::new(
            language,
            r#"
            (type_definition
                type: (_) @underlying_type
                declarator: (type_identifier) @typedef_name
            ) @typedef

            (type_definition
                type: (_) @underlying_type
                declarator: (function_declarator
                    declarator: (parenthesized_declarator
                        (pointer_declarator declarator: (type_identifier) @typedef_name)
                    )
                    parameters: (parameter_list) @pointer_params
                )
            ) @typedef
        "#,
        )?;

        // Query for macro definitions
        let macro_query = Query::new(
            language,
            r#"
            (preproc_def
                name: (identifier) @macro_name
                value: (_)? @value
            ) @macro

            (preproc_function_def
                name: (identifier) @macro_name
                parameters: (preproc_params) @parameters
                value: (_)? @value
            ) @function_macro
        "#,
        )?;

        // Query for function calls
        let call_query = Query::new(
            language,
            r#"
            (call_expression
                function: (identifier) @function_name
            ) @call

            (call_expression
                function: (field_expression
                    argument: (_) @receiver
                    field: (field_identifier) @member_name
                )
            ) @method_call

            (call_expression
                function: (parenthesized_expression
                    (pointer_expression argument: (_) @pointer_expr)
                )
            ) @deref_call


            (call_expression
                function: (identifier) @macro_name
                arguments: (argument_list) @macro_args
            ) @macro_call

            (call_expression
                function: (subscript_expression
                    argument: (_) @array_name
                    index: (_) @array_index
                )
            ) @array_call

            (call_expression
                function: (call_expression
                    function: (identifier) @static_call_name
                    arguments: (argument_list (identifier) @static_call_key)
                )
            ) @static_call_site
        "#,
        )?;

        Ok(LanguageQueries {
            function_query,
            comment_query,
            type_query,
            typedef_query: Some(typedef_query),
            macro_query,
            call_query,
        })
    }

    fn create_rust_queries(language: &tree_sitter::Language) -> Result<LanguageQueries> {
        // Query for function definitions
        let function_query = Query::new(
            language,
            r#"
            (function_item
                name: (identifier) @function_name
                parameters: (parameters) @parameters
                return_type: (_)? @return_type
                body: (block)? @body
            ) @function
        "#,
        )?;

        // Query for comments
        let comment_query = Query::new(
            language,
            r#"
            (line_comment) @comment
            (block_comment) @comment
        "#,
        )?;

        // Query for struct/enum definitions
        let type_query = Query::new(
            language,
            r#"
            (struct_item
                name: (type_identifier) @type_name
                body: (field_declaration_list)? @body
            ) @struct

            (enum_item
                name: (type_identifier) @type_name
                body: (enum_variant_list)? @body
            ) @enum
        "#,
        )?;

        // Query for macro definitions (Rust macros)
        let macro_query = Query::new(
            language,
            r#"
            (macro_definition
                name: (identifier) @macro_name
            ) @macro
        "#,
        )?;

        // Query for function calls
        let call_query = Query::new(
            language,
            r#"
            (call_expression
                function: (identifier) @function_name
            ) @call

            (call_expression
                function: (field_expression
                    value: (_) @receiver
                    field: (field_identifier) @member_name
                )
            ) @method_call
        "#,
        )?;

        Ok(LanguageQueries {
            function_query,
            comment_query,
            type_query,
            typedef_query: None, // Rust doesn't have typedefs like C
            macro_query,
            call_query,
        })
    }

    fn create_python_queries(language: &tree_sitter::Language) -> Result<LanguageQueries> {
        // Query for function definitions (including methods)
        let function_query = Query::new(
            language,
            r#"
            (function_definition
                name: (identifier) @function_name
                parameters: (parameters) @parameters
                return_type: (_)? @return_type
                body: (block) @body
            ) @function
        "#,
        )?;

        // Query for comments
        let comment_query = Query::new(
            language,
            r#"
            (comment) @comment
        "#,
        )?;

        // Query for class definitions
        let type_query = Query::new(
            language,
            r#"
            (class_definition
                name: (identifier) @type_name
                body: (block) @body
            ) @class
        "#,
        )?;

        // Python doesn't have traditional macros, but we can track decorators
        let macro_query = Query::new(
            language,
            r#"
            (decorator
                (identifier) @macro_name
            ) @decorator
        "#,
        )?;

        // Query for function calls
        let call_query = Query::new(
            language,
            r#"
            (call
                function: (identifier) @function_name
            ) @call

            (call
                function: (attribute
                    object: (_) @receiver
                    attribute: (identifier) @member_name
                )
            ) @method_call
        "#,
        )?;

        Ok(LanguageQueries {
            function_query,
            comment_query,
            type_query,
            typedef_query: None, // Python doesn't have typedefs
            macro_query,
            call_query,
        })
    }

    fn create_zig_queries(language: &tree_sitter::Language) -> Result<LanguageQueries> {
        // Named functions and tests. Anonymous `fn` types have no name field
        // and are left to the type query. `!body` is the extern/declaration
        // form; a second pattern without it would also match definitions.
        let function_query = Query::new(
            language,
            r#"
            (function_declaration
                name: (identifier) @function_name
                (parameters) @parameters
                type: (_) @return_type
                body: (block) @body
            ) @function

            (function_declaration
                name: (identifier) @function_name
                (parameters) @parameters
                type: (_) @return_type
                !body
            ) @declaration

            (test_declaration
                (string) @function_name
                (block) @body
            ) @function

            (test_declaration
                (identifier) @function_name
                (block) @body
            ) @function
        "#,
        )?;

        let comment_query = Query::new(
            language,
            r#"
            (comment) @comment
        "#,
        )?;

        // Zig types are `const Name = struct { ... }` (and enum/union/opaque
        // / error). The identifier is the type name; the RHS is the body.
        // Zig 0.16 replaced `@Type` with `@Int`/`@Struct`/`@Union`/`@Enum`/
        // `@Tuple`/`@Pointer`/`@Fn`/`@EnumLiteral`.
        let type_query = Query::new(
            language,
            r#"
            (variable_declaration
                (identifier) @type_name
                (struct_declaration) @body
            ) @struct

            (variable_declaration
                (identifier) @type_name
                (enum_declaration) @body
            ) @enum

            (variable_declaration
                (identifier) @type_name
                (union_declaration) @body
            ) @union

            (variable_declaration
                (identifier) @type_name
                (opaque_declaration) @body
            ) @opaque

            (variable_declaration
                (identifier) @type_name
                (error_set_declaration) @body
            ) @error

            (
              (variable_declaration
                  (identifier) @type_name
                  (builtin_function
                      (builtin_identifier) @builtin
                  )
              ) @type_alias
              (#match? @builtin "^@(Int|Struct|Union|Enum|Tuple|Pointer|Fn|EnumLiteral|Type)$")
            )
        "#,
        )?;

        // Zig has no preprocessor macros.
        let macro_query = Query::new(language, "(source_file)")?;

        let call_query = Query::new(
            language,
            r#"
            (call_expression
                function: (identifier) @function_name
            ) @call

            (call_expression
                function: (field_expression
                    object: (_) @receiver
                    member: (identifier) @member_name
                )
            ) @method_call

            (builtin_function
                (builtin_identifier) @function_name
            ) @call
        "#,
        )?;

        Ok(LanguageQueries {
            function_query,
            comment_query,
            type_query,
            typedef_query: None,
            macro_query,
            call_query,
        })
    }

    /// Helper method to convert absolute path to relative path based on source root
    fn make_relative_path(&self, file_path: &Path, source_root: Option<&Path>) -> String {
        if let Some(root) = source_root {
            file_path
                .strip_prefix(root)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| file_path.to_string_lossy().to_string())
        } else {
            file_path.to_string_lossy().to_string()
        }
    }

    /// Get the appropriate parser for a language
    fn get_parser(&mut self, language: Language) -> &mut Parser {
        match language {
            Language::C => &mut self.c_parser,
            Language::Rust => &mut self.rust_parser,
            Language::Python => &mut self.python_parser,
            Language::Zig => &mut self.zig_parser,
        }
    }

    /// Get the appropriate queries for a language
    fn get_queries(&self, language: Language) -> &LanguageQueries {
        match language {
            Language::C => self.c_queries,
            Language::Rust => self.rust_queries,
            Language::Python => self.python_queries,
            Language::Zig => self.zig_queries,
        }
    }

    pub fn analyze_file(
        &mut self,
        file_path: &Path,
    ) -> Result<(Vec<FunctionInfo>, Vec<TypeInfo>, Vec<FunctionInfo>)> {
        self.analyze_file_with_source_root(file_path, None)
    }

    pub fn analyze_file_with_source_root(
        &mut self,
        file_path: &Path,
        source_root: Option<&Path>,
    ) -> Result<(Vec<FunctionInfo>, Vec<TypeInfo>, Vec<FunctionInfo>)> {
        // Detect language from file extension
        let language = Language::from_path(file_path)
            .ok_or_else(|| anyhow::anyhow!("Unsupported file type: {}", file_path.display()))?;

        let source_code = std::fs::read_to_string(file_path)?;
        let parser = self.get_parser(language);
        let tree = parser
            .parse(&source_code, None)
            .ok_or_else(|| anyhow::anyhow!("Failed to parse file: {}", file_path.display()))?;

        // Compute git hash of the file
        let git_hash = compute_file_hash(file_path)?.unwrap_or_default();

        let mut raw_functions = Vec::new();
        let mut raw_types = Vec::new();
        let mut raw_macros = Vec::new();

        // Extract functions
        raw_functions.extend(self.extract_functions(
            &tree,
            &source_code,
            file_path,
            &git_hash,
            source_root,
            language,
        )?);

        // Extract types
        raw_types.extend(self.extract_types(
            &tree,
            &source_code,
            file_path,
            &git_hash,
            source_root,
            language,
        )?);

        // Extract typedefs as TypeInfo with kind="typedef" and add to types (C only)
        if language == Language::C {
            raw_types.extend(self.extract_typedefs_as_typeinfo(
                &tree,
                &source_code,
                file_path,
                &git_hash,
                source_root,
            )?);
        }

        // Extract macros; the sites in their bodies are dropped on this
        // path, which serves callers that want definitions only.
        let (extracted_macros, _macro_sites, _macro_registrations, _macro_arguments, _macro_edges) =
            self.extract_macros(
                &tree,
                &source_code,
                file_path,
                &git_hash,
                source_root,
                language,
            )?;
        raw_macros.extend(extracted_macros);

        // Call relationships are now embedded in function/macro JSON columns during parsing

        // Perform intra-file deduplication (no thread contention since this is per-file)
        let functions = self.deduplicate_functions_within_file(raw_functions);
        let types = self.deduplicate_types_within_file(raw_types);
        let mut macros = self.deduplicate_macros_within_file(raw_macros);

        // Read the directives an unreadable construct swallowed here too, so
        // this path and `analyze_source_with_metadata` cannot answer
        // differently for one file.
        if let Some((healed_source, healed_tree, declared)) =
            self.heal_swallowed_directives(&source_code, &tree, language)
        {
            macros = self
                .graft_recovered_macros(
                    macros,
                    &healed_source,
                    &healed_tree,
                    &declared,
                    file_path,
                    &git_hash,
                    source_root,
                )?
                .macros;
        }

        Ok((functions, types, macros))
    }

    /// Parse a code snippet and extract function definitions
    pub fn analyze_code_snippet(&mut self, code: &str) -> Result<Vec<FunctionInfo>> {
        // Default to C language for code snippets (can be enhanced to accept language parameter)
        let language = Language::C;
        let parser = self.get_parser(language);
        let tree = parser
            .parse(code, None)
            .ok_or_else(|| anyhow::anyhow!("Failed to parse code snippet"))?;

        // Use a dummy path for the snippet and compute hash of the code content
        let dummy_path = Path::new("snippet.c");
        let git_hash = crate::hash::compute_content_hash(code);
        // No git SHA for code snippets
        self.extract_functions(&tree, code, dummy_path, &git_hash, None, language)
    }

    /// Analyze source code directly with specified file path and git hash
    /// This is used for processing git blob content without writing to disk
    pub fn analyze_source_with_metadata(
        &mut self,
        source_code: &str,
        file_path: &Path,
        git_hash: &str,
        source_root: Option<&Path>,
    ) -> Result<FileAnalysis> {
        // Detect language from file extension
        let language = Language::from_path(file_path)
            .ok_or_else(|| anyhow::anyhow!("Unsupported file type: {}", file_path.display()))?;

        let parser = self.get_parser(language);
        let tree = parser.parse(source_code, None).ok_or_else(|| {
            anyhow::anyhow!("Failed to parse source code for: {}", file_path.display())
        })?;

        // An unreadable construct yields an ERROR node that does not stop at
        // the declaration: it runs on and swallows the directives after it, so
        // the file indexes without the macros it defines. Read those from a
        // second parse of the same file with what the ERROR covers blanked.
        let healed = self.heal_swallowed_directives(source_code, &tree, language);

        // Single-pass extraction with optimized call analysis
        let FileAnalysis {
            functions: raw_functions,
            types: mut raw_types,
            macros: raw_macros,
            mut dispatch_sites,
            mut registrations,
            mut argument_functions,
            mut unresolved_edges,
            globals,
        } = self.extract_all_with_embedded_data(
            &tree,
            source_code,
            file_path,
            git_hash,
            source_root,
            language,
        )?;

        // Extract typedefs as TypeInfo with kind="typedef" and add to types (C only)
        if language == Language::C {
            raw_types.extend(self.extract_typedefs_as_typeinfo(
                &tree,
                source_code,
                file_path,
                git_hash,
                source_root,
            )?);
        }

        // Perform intra-file deduplication (no thread contention since this is per-file)
        let functions = self.deduplicate_functions_within_file(raw_functions);
        let types = self.deduplicate_types_within_file(raw_types);
        let mut macros = self.deduplicate_macros_within_file(raw_macros);

        // The healed tree contributes macro rows and nothing else: functions
        // and types stay as the original parse read them, so blanking cannot
        // cost a definition that parses today.
        if let Some((healed_source, healed_tree, declared)) = healed {
            let grafted = self.graft_recovered_macros(
                macros,
                &healed_source,
                &healed_tree,
                &declared,
                file_path,
                git_hash,
                source_root,
            )?;
            macros = grafted.macros;
            dispatch_sites.extend(grafted.dispatch_sites);
            registrations.extend(grafted.registrations);
            argument_functions.extend(grafted.argument_functions);
            unresolved_edges.extend(grafted.unresolved_edges);
        }

        // Call relationships are now embedded in function/macro JSON columns

        Ok(FileAnalysis {
            functions,
            types,
            macros,
            dispatch_sites,
            registrations,
            argument_functions,
            unresolved_edges,
            globals,
        })
    }

    /// Blank the code an `ERROR` covers, reparse, and hand back that source
    /// and tree when the directives inside the span became readable.
    ///
    /// Returns `None` unless the file is one this can help: the pre-gate is
    /// that an `ERROR` covers a line that looks like a directive, so a file
    /// whose ERROR swallows only code pays for no extra parse.
    fn heal_swallowed_directives(
        &mut self,
        source: &str,
        tree: &Tree,
        language: Language,
    ) -> Option<(String, Tree, HashSet<u32>)> {
        // Most files parse whole, and for those the flag on the root is the
        // whole test: reserve the tree walk and the row scan for a file that
        // has an ERROR at all.
        if language != Language::C || !tree.root_node().has_error() {
            return None;
        }

        // The rows the file really opens a directive on, read once from the
        // original source. Gating on these rather than on directive-shaped
        // text keeps a file whose ERROR covers only a commented-out
        // `#define` from paying for a second parse it cannot gain from.
        let declared = Self::define_rows_in_code_region(source);
        if !Self::error_covers_declared_define(tree, &declared) {
            return None;
        }

        let mut text = source.to_string();
        let mut current = tree.clone();
        let mut healed = false;

        for _ in 0..HEAL_ROUND_CAP {
            // A round that changes no text has nothing left to try: the rows
            // an ERROR still covers are all directives, which are never
            // blanked. Without this the loop re-blanks identical rows until
            // the cap, parsing the file as many times for no delta.
            let Some(next_text) = Self::blank_error_lines(&text, &current) else {
                break;
            };
            // Belt to the braces above: a round that reproduces the text it
            // was given has nothing left to blank, whatever the row
            // bookkeeping says.
            if next_text == text {
                break;
            }
            let Some(next_tree) = self.get_parser(language).parse(&next_text, None) else {
                break;
            };
            text = next_text;
            current = next_tree;
            healed = true;
            if !Self::error_covers_declared_define(&current, &declared) {
                break;
            }
        }

        healed.then_some((text, current, declared))
    }

    /// Add the macros a healed parse reads and the original did not.
    ///
    /// Blanking is not semantics-preserving -- it can cost the tokens an
    /// extraction depended on, turning one header from 59 definitions into
    /// 35 -- and it can strip the delimiters around a commented-out
    /// `#define`, inventing one the file never declared. So a gain is
    /// believed only when the healed tree lost nothing, the gained name is
    /// new to the file, and its line held a directive in the original source
    /// outside any comment or string.
    #[allow(clippy::too_many_arguments)]
    fn graft_recovered_macros(
        &self,
        macros: Vec<FunctionInfo>,
        healed_source: &str,
        healed_tree: &Tree,
        declared: &HashSet<u32>,
        file_path: &Path,
        git_hash: &str,
        source_root: Option<&Path>,
    ) -> Result<GraftedMacros> {
        let (raw_healed, sites, registrations, arguments, edges) = self
            .extract_macros_with_embedded_data(
                healed_tree,
                healed_source,
                file_path,
                git_hash,
                source_root,
                Language::C,
            )?;
        // Losslessness: a healed parse that no longer reads a definition the
        // original read is a corrupted read of the file, not a recovery of
        // it, and a count or a name-superset check cannot tell the two apart.
        // Reject the whole graft rather than reason about which row moved.
        //
        // Ask this of every row the healed tree read, before one row per
        // name and arm survives deduplication: a name defined twice under
        // one arm loses its original row to a longer definition the healing
        // made readable, which is a recovery rather than a loss.
        {
            let readable: HashSet<(&str, u32)> = raw_healed
                .iter()
                .map(|entry| (entry.name.as_str(), entry.line_start))
                .collect();
            if macros
                .iter()
                .any(|entry| !readable.contains(&(entry.name.as_str(), entry.line_start)))
            {
                tracing::info!(
                    file = %file_path.display(),
                    "refused to read the macros an unreadable construct swallowed here: \
                     the second reading of this file that would recover them no longer \
                     sees a definition the first reading does, so nothing it found can \
                     be trusted. The swallowed macros stay missing from the index."
                );
                return Ok(GraftedMacros::keeping(macros));
            }
        }

        // Keep only the rows the file states are `#define`s before one row
        // per name and arm survives: a row that looked like a definition once the
        // construct around it was blanked can carry a longer body than the
        // real definition of the same name, and would take that name's place.
        let (on_define_rows, elsewhere): (Vec<FunctionInfo>, Vec<FunctionInfo>) = raw_healed
            .into_iter()
            .partition(|entry| declared.contains(&entry.line_start));

        let known: HashSet<&str> = macros.iter().map(|entry| entry.name.as_str()).collect();
        let gained: Vec<FunctionInfo> = self
            .deduplicate_macros_within_file(on_define_rows)
            .into_iter()
            // A name the original already read keeps the rows the original
            // read, every arm of it, and gains no arm from the blanked parse:
            // the two parses do not see the same conditionals (the original
            // lost the directives the ERROR swallowed), so a guard read from
            // one is not trusted to name the same arm as a guard read from
            // the other, and on a tie the tree that needed no blanking wins.
            .filter(|entry| !known.contains(entry.name.as_str()))
            .collect();

        // The names a blanked parse found where the file writes a comment or
        // a string. Naming them matters: it is the difference between a file
        // this cannot help and a file it refused to invent a macro for.
        let refused: HashSet<&str> = {
            let taken: HashSet<&str> = gained.iter().map(|entry| entry.name.as_str()).collect();
            elsewhere
                .iter()
                .map(|entry| entry.name.as_str())
                .filter(|name| !known.contains(name) && !taken.contains(name))
                .collect()
        };
        let invented = refused.len();

        if gained.is_empty() {
            if invented > 0 {
                tracing::info!(
                    file = %file_path.display(),
                    refused = invented,
                    "read no macros an unreadable construct swallowed here: every \
                     definition found inside the swallowed part of this file sits where \
                     the file writes a comment or a string, so none of them is a macro \
                     the file defines"
                );
            }
            return Ok(GraftedMacros::keeping(macros));
        }

        // What a recovered body does, not only that it exists. Dropping
        // these would leave `dev_dbg` with a row and no edge to
        // `dev_printk`, which is the same silence one hop along. Offsets
        // survive blanking, so a site read from the healed tree is at the
        // place the file puts it.
        // A file that indexes without the macros it defines says nothing
        // today, which is why the defect stood for as long as it did: 41
        // directives in one logging header, one row, no warning. Say it.
        tracing::info!(
            file = %file_path.display(),
            recovered = gained.len(),
            refused = invented,
            "read {} function-like macro{} an unreadable construct had swallowed in this \
             file{}",
            gained.len(),
            if gained.len() == 1 { "" } else { "s" },
            match invented {
                0 => String::new(),
                1 => ", and refused one more that sits where the file writes a comment or a \
                      string"
                    .to_string(),
                n => format!(
                    ", and refused {n} more that sit where the file writes a comment or a string"
                ),
            }
        );

        let recovered: HashSet<&str> = gained.iter().map(|entry| entry.name.as_str()).collect();
        let grafted = GraftedMacros {
            dispatch_sites: sites
                .into_iter()
                .filter(|site| recovered.contains(site.caller_name.as_str()))
                .collect(),
            registrations: registrations
                .into_iter()
                .filter(|entry| recovered.contains(entry.enclosing_function.as_str()))
                .collect(),
            argument_functions: arguments
                .into_iter()
                .filter(|entry| recovered.contains(entry.enclosing_function.as_str()))
                .collect(),
            unresolved_edges: edges
                .into_iter()
                .filter(|edge| recovered.contains(edge.name.as_str()))
                .collect(),
            macros: {
                let mut all = macros;
                all.extend(gained);
                all
            },
        };
        Ok(grafted)
    }

    /// Whether `define` follows the `#` at `at`, allowing whitespace
    /// between them, as `#  define X(y) y` does.
    fn opens_a_define(bytes: &[u8], at: usize) -> bool {
        let mut at = at;
        while matches!(bytes.get(at), Some(b' ' | b'\t')) {
            at += 1;
        }
        let Some(rest) = bytes.get(at..) else {
            return false;
        };
        rest.starts_with(b"define")
            && !matches!(rest.get(6), Some(b) if b.is_ascii_alphanumeric() || *b == b'_')
    }

    /// Whether an `ERROR` node covers a row on which the file opens a
    /// `#define`.
    ///
    /// This is the pre-gate and the loop's exit test: while it holds, the
    /// file has directives the extraction query cannot see. `declared` holds
    /// 1-based rows and a tree reports 0-based ones.
    fn error_covers_declared_define(tree: &Tree, declared: &HashSet<u32>) -> bool {
        Self::error_rows(tree)
            .into_iter()
            .any(|row| declared.contains(&(row as u32 + 1)))
    }

    /// The rows every `ERROR` node in the tree covers.
    fn error_rows(tree: &Tree) -> Vec<usize> {
        let mut rows = Vec::new();
        let mut cursor = tree.walk();
        let mut descend = true;
        loop {
            let node = cursor.node();
            if node.is_error() {
                rows.extend(node.start_position().row..=node.end_position().row);
                // Everything under an ERROR is inside the span already.
                descend = false;
            }
            if descend && cursor.goto_first_child() {
                continue;
            }
            descend = true;
            while !cursor.goto_next_sibling() {
                if !cursor.goto_parent() {
                    return rows;
                }
            }
        }
    }

    /// Blank every row an `ERROR` covers that is not part of a directive,
    /// returning `None` when that leaves the text unchanged.
    ///
    /// Blanking is whole-row and byte-for-byte the same length, so every
    /// offset, row and column outside a blanked row is what it was. Rows are
    /// split on `\n`, which a file using lone `\r` for line endings does not
    /// have: that file reads as one row, no row is ever blanked, and
    /// recovery declines it.
    fn blank_error_lines(text: &str, tree: &Tree) -> Option<String> {
        let directive = Self::directive_lines(text);
        let lines: Vec<&str> = text.split_inclusive('\n').collect();
        let mut blank = vec![false; directive.len()];
        let mut any = false;
        for row in Self::error_rows(tree) {
            // A row a previous round already blanked would rewrite the same
            // text, and an ERROR that survives blanking covers those rows
            // every round: without this the loop reparses identical source
            // until the cap.
            let worth_blanking = matches!(directive.get(row), Some(false))
                && !blank[row]
                && lines.get(row).is_some_and(|line| !line.trim().is_empty());
            if worth_blanking {
                blank[row] = true;
                any = true;
            }
        }
        if !any {
            return None;
        }

        let mut out = Vec::with_capacity(text.len());
        for (row, line) in lines.iter().enumerate() {
            if blank.get(row).copied().unwrap_or(false) {
                out.extend(line.bytes().map(|byte| {
                    if byte == b'\n' || byte == b'\r' {
                        byte
                    } else {
                        b' '
                    }
                }));
            } else {
                out.extend_from_slice(line.as_bytes());
            }
        }
        String::from_utf8(out).ok()
    }

    /// For each row, whether it is part of a preprocessor directive: it
    /// starts with `#`, or it continues a directive because the row above it
    /// ended in a backslash.
    ///
    /// The continuation rule is what makes recovery worth having. Without it
    /// the body of every multi-line macro is blanked along with the code,
    /// and one logging header recovers 25 of its 41 directives instead of
    /// all of them.
    fn directive_lines(source: &str) -> Vec<bool> {
        let mut rows = Vec::new();
        let mut continuing = false;
        for line in source.split_inclusive('\n') {
            let line = line.trim_end_matches('\n').trim_end_matches('\r');
            let directive = continuing || line.trim_start().starts_with('#');
            rows.push(directive);
            // Only a backslash last on the row splices; whitespace after it
            // does not, and treating it as if it did would pin a row of code
            // as a directive and leave it unblanked.
            continuing = directive && line.ends_with('\\');
        }
        rows
    }

    /// The rows on which the original source opens a `#define` with the `#`
    /// outside any comment or string literal.
    ///
    /// This is what separates a recovered directive from an invented one: a
    /// `#define` inside a block comment becomes a real node once blanking
    /// strips the comment's delimiters, and it was never a definition.
    fn define_rows_in_code_region(source: &str) -> HashSet<u32> {
        #[derive(PartialEq)]
        enum Region {
            Code,
            LineComment,
            BlockComment,
            Str,
            Char,
        }

        let mut declared = HashSet::new();
        let mut region = Region::Code;
        let mut row = 1u32;
        // Whether a `#` here would open a directive: everything before it on
        // this logical line is whitespace or a comment, and the line is not
        // the continuation of another.
        let mut opens_row = true;
        let bytes = source.as_bytes();
        let mut at = 0usize;

        // A byte-order mark is not code and does not stop the row it leads
        // from opening a directive.
        if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
            at = 3;
        }

        while at < bytes.len() {
            let byte = bytes[at];
            let next = bytes.get(at + 1).copied();

            if byte == b'\n' {
                // A backslash immediately before the newline splices this row
                // onto the next, and that happens before a comment or a
                // string is recognised: `// ...\` continues the comment over
                // the row below, so a `#` down there opens nothing. Only a
                // lone row-ending backslash splices -- trailing whitespace
                // after it does not.
                let spliced = match at.checked_sub(1).map(|i| bytes[i]) {
                    Some(b'\r') => at.checked_sub(2).map(|i| bytes[i]) == Some(b'\\'),
                    last => last == Some(b'\\'),
                };
                row += 1;
                opens_row = !spliced;
                if !spliced {
                    // A `//` comment ends at an unspliced newline, and so
                    // does an unterminated literal: C has no literal that
                    // crosses a row without a splice, and leaving one open
                    // would hand the rest of the file the wrong region --
                    // which reads a `#define` inside a later comment as
                    // code and believes a macro the file never declared.
                    if matches!(region, Region::LineComment | Region::Str | Region::Char) {
                        region = Region::Code;
                    }
                }
                at += 1;
                continue;
            }

            match region {
                // A comment is whitespace by the time directives are read, so
                // `/* c */ #define REAL(x) x` really does define a macro and
                // neither delimiter closes the row to one.
                Region::Code => match (byte, next) {
                    (b'/', Some(b'/')) => {
                        region = Region::LineComment;
                        at += 2;
                    }
                    (b'/', Some(b'*')) => {
                        region = Region::BlockComment;
                        at += 2;
                    }
                    (b'"', _) => {
                        region = Region::Str;
                        opens_row = false;
                        at += 1;
                    }
                    (b'\'', _) => {
                        region = Region::Char;
                        opens_row = false;
                        at += 1;
                    }
                    (b'#', _) => {
                        // Only a `#define` row matters: a gained row is a
                        // macro definition, and gating on every directive
                        // shape sends files into a second parse that cannot
                        // gain anything from it.
                        if opens_row && Self::opens_a_define(bytes, at + 1) {
                            declared.insert(row);
                        }
                        opens_row = false;
                        at += 1;
                    }
                    _ => {
                        if !byte.is_ascii_whitespace() {
                            opens_row = false;
                        }
                        at += 1;
                    }
                },
                Region::BlockComment => {
                    if (byte, next) == (b'*', Some(b'/')) {
                        region = Region::Code;
                        at += 2;
                    } else {
                        at += 1;
                    }
                }
                Region::Str | Region::Char => {
                    let closes = if region == Region::Str { b'"' } else { b'\'' };
                    if byte == b'\\' {
                        if next == Some(b'\n') {
                            row += 1;
                        }
                        at += 2;
                    } else {
                        if byte == closes {
                            region = Region::Code;
                        }
                        at += 1;
                    }
                }
                Region::LineComment => at += 1,
            }
        }

        declared
    }

    /// Optimized single-pass extraction with embedded JSON data
    /// This replaces multiple tree traversals with one efficient pass
    fn extract_all_with_embedded_data(
        &self,
        tree: &Tree,
        source_code: &str,
        file_path: &Path,
        git_hash: &str,
        source_root: Option<&Path>,
        language: Language,
    ) -> Result<FileAnalysis> {
        // Single pass: extract all calls once and map them to functions by byte ranges
        let extraction = Self::extract_all_calls_optimized(
            self.get_queries(language),
            tree,
            source_code,
            language,
        )?;

        // Create extraction context
        let ctx = ExtractionContext {
            tree,
            source: source_code,
            file_path,
            git_hash,
            source_root,
            language,
        };

        // Extract functions with embedded call data
        let ExtractedFunctions {
            functions,
            mut dispatch_sites,
            mut registrations,
            mut argument_functions,
        } = self.extract_functions_with_calls(&ctx, &extraction)?;

        // Extract types (single traversal as before)
        let types = self.extract_types(
            tree,
            source_code,
            file_path,
            git_hash,
            source_root,
            language,
        )?;

        // Extract macros with embedded data (single traversal)
        let (macros, macro_sites, macro_registrations, macro_arguments, unresolved_edges) = self
            .extract_macros_with_embedded_data(
                tree,
                source_code,
                file_path,
                git_hash,
                source_root,
                language,
            )?;
        dispatch_sites.extend(macro_sites);
        registrations.extend(macro_registrations);
        argument_functions.extend(macro_arguments);

        // Only C states a variable's aggregate this way; other languages get
        // their receivers typed by their own pass.
        let globals = if matches!(language, Language::C) {
            Self::collect_file_scope_globals(tree.root_node(), source_code)
                .into_iter()
                .map(|raw| GlobalVariable {
                    name: raw.name,
                    type_name: raw.type_name,
                    file_path: self.make_relative_path(file_path, source_root),
                    git_file_hash: git_hash.to_string(),
                    line: raw.line,
                })
                .collect()
        } else {
            Vec::new()
        };

        // A fact inside a body a macro opens is found by two walks; the store
        // keys rows by place, so the pair is one fact and a duplicate.
        let dispatch_sites = Self::keep_innermost(
            dispatch_sites,
            |site| (site.byte_start, site.target.clone().unwrap_or_default()),
            |site| site.caller_name.as_str(),
        );
        let registrations = Self::keep_innermost(
            registrations,
            |registration| (registration.byte_start, registration.target.clone()),
            |registration| registration.enclosing_function.as_str(),
        );
        let argument_functions = Self::keep_innermost(
            argument_functions,
            |argument| (argument.byte_start, argument.target.clone()),
            |argument| argument.enclosing_function.as_str(),
        );

        Ok(FileAnalysis {
            functions,
            types,
            macros,
            dispatch_sites,
            registrations,
            argument_functions,
            unresolved_edges,
            globals,
        })
    }

    /// One place in a file yields one row, attributed to whatever encloses it.
    ///
    /// A body a macro opens is not a `function_definition`, so a fact inside
    /// it is found twice: once by the walk over the function the macro
    /// defines, and once by the walk that collects what no function encloses.
    /// `kargs.set_tid = set_tid` inside `SYSCALL_DEFINE2(clone3, ...)` was
    /// recorded as a registration in `sys_clone3` and as one at file scope,
    /// both at kernel/fork.c:3060. A row is keyed by its place in the file, so
    /// the second is not another fact but the same one, and the database
    /// refuses the pair rather than storing it:
    ///
    /// ```text
    /// Ambiguous merge inserts are prohibited: multiple source rows match
    /// the same target row on (file_path = "kernel/fork.c", ...)
    /// ```
    ///
    /// The row naming what encloses the fact is the one worth keeping.
    fn keep_innermost<T>(
        rows: Vec<T>,
        place: impl Fn(&T) -> (u64, String),
        enclosing: impl Fn(&T) -> &str,
    ) -> Vec<T> {
        let mut best: HashMap<(u64, String), usize> = HashMap::new();
        let mut keep: Vec<bool> = vec![true; rows.len()];
        for (index, row) in rows.iter().enumerate() {
            match best.get(&place(row)) {
                Some(&previous) => {
                    if enclosing(&rows[previous]).is_empty() && !enclosing(row).is_empty() {
                        keep[previous] = false;
                        best.insert(place(row), index);
                    } else {
                        keep[index] = false;
                    }
                }
                None => {
                    best.insert(place(row), index);
                }
            }
        }
        rows.into_iter()
            .zip(keep)
            .filter_map(|(row, keep)| keep.then_some(row))
            .collect()
    }

    /// Extract all calls in a single tree traversal and return with byte positions
    fn extract_all_calls_optimized(
        queries: &LanguageQueries,
        tree: &Tree,
        source_code: &str,
        language: Language,
    ) -> Result<CallExtraction> {
        let mut extraction = CallExtraction::default();
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(
            &queries.call_query,
            tree.root_node(),
            source_code.as_bytes(),
        );

        while let Some(call_match) = matches.next() {
            let mut member: Option<tree_sitter::Node> = None;
            let mut receiver: Option<tree_sitter::Node> = None;
            let mut macro_name: Option<tree_sitter::Node> = None;
            let mut macro_args: Option<tree_sitter::Node> = None;
            let mut array_name: Option<tree_sitter::Node> = None;
            let mut static_call_name: Option<tree_sitter::Node> = None;
            let mut static_call_key: Option<tree_sitter::Node> = None;
            let mut static_call_site: Option<tree_sitter::Node> = None;

            for capture in call_match.captures {
                match queries.call_query.capture_names()[capture.index as usize] {
                    "function_name" => {
                        if let Some(call) = Self::call_site_from_capture(capture.node, source_code)
                        {
                            extraction.calls.push(call);
                        }
                    }
                    "member_name" => member = Some(capture.node),
                    "receiver" => receiver = Some(capture.node),
                    "macro_name" => macro_name = Some(capture.node),
                    "macro_args" => macro_args = Some(capture.node),
                    "array_name" => array_name = Some(capture.node),
                    "static_call_name" => static_call_name = Some(capture.node),
                    "static_call_key" => static_call_key = Some(capture.node),
                    "static_call_site" => static_call_site = Some(capture.node),
                    "pointer_expr" => {
                        // `(*fp)(...)`: a call through a pointer value, which
                        // the plain call pattern does not match at all.
                        let text = collapse_whitespace(&source_code[capture.node.byte_range()]);
                        if !text.is_empty() {
                            extraction.member_sites.push(RawDispatchSite {
                                member: String::new(),
                                receiver_expr: Some(text),
                                receiver_type: None,
                                receiver_base_type: None,
                                receiver_field: None,
                                kind: DispatchKind::PointerDeref,
                                byte_start: capture.node.start_byte(),
                                line: capture.node.start_position().row as u32 + 1,
                                target: None,
                            });
                        }
                    }
                    _ => {}
                }
            }

            // `table[i](...)`: the call names no function and no member, and
            // the table it indexes is the only thing that says what it can
            // reach. Record the table as the container, with every element a
            // candidate — which is what a runtime index leaves open, and what
            // the kernel's exit-handler and syscall tables are.
            // `static_call(key)(vcpu)`: the callee is itself a call, naming
            // the key that holds the function. The branch is patched at run
            // time, so nothing here dispatches through a pointer.
            if let (Some(name), Some(key), Some(call)) =
                (static_call_name, static_call_key, static_call_site)
            {
                if source_code[name.byte_range()].trim() != "static_call" {
                    continue;
                }
                // `kvm_x86_call(op)` writes `static_call(kvm_x86_##op)`,
                // which parses as an identifier and the rest of the paste
                // beside it. The name it means does not exist until the
                // preprocessor makes it, and half of one joins to nothing, so
                // the key has to be the only thing in there.
                if key
                    .parent()
                    .is_some_and(|args| args.named_child_count() != 1)
                {
                    continue;
                }
                let key = source_code[key.byte_range()].to_string();
                extraction.member_sites.push(RawDispatchSite {
                    member: STATIC_CALL_MEMBER.to_string(),
                    receiver_expr: Some(key.clone()),
                    receiver_type: Some(key),
                    receiver_base_type: None,
                    receiver_field: None,
                    kind: DispatchKind::StaticCall,
                    byte_start: call.start_byte(),
                    line: call.start_position().row as u32 + 1,
                    target: None,
                });
            }

            if let Some(array) = array_name {
                // The thing indexed has to be nameable, or there is nothing
                // to join a table against. A bare name is the table itself;
                // a field is a table held in a struct, which receiver typing
                // can still say something about. Anything else names no
                // container — a macro body can parse as a subscripted call —
                // and recording one would invent a table out of whatever text
                // sat between the brackets.
                let container = match array.kind() {
                    "identifier" => Some(collapse_whitespace(&source_code[array.byte_range()])),
                    "field_expression" => None,
                    _ => continue,
                };
                let name = collapse_whitespace(&source_code[array.byte_range()]);
                if !name.is_empty() {
                    extraction.member_sites.push(RawDispatchSite {
                        member: ARRAY_ELEMENT_MEMBER.to_string(),
                        receiver_expr: Some(name),
                        // A table is named, not typed: the array variable is
                        // the container, and no struct declares a member of
                        // this name, so the two cannot collide.
                        receiver_type: container,
                        receiver_base_type: None,
                        receiver_field: None,
                        kind: DispatchKind::ArrayElement,
                        byte_start: array.start_byte(),
                        line: array.start_position().row as u32 + 1,
                        target: None,
                    });
                }
            }

            // An indirect-call macro names the targets it expects, which is
            // the one place the source states the answer outright.
            if let (Some(name), Some(args)) = (macro_name, macro_args) {
                let name = &source_code[name.byte_range()];
                if let Some(candidates) = Self::indirect_call_candidate_count(name) {
                    extraction.member_sites.extend(Self::indirect_call_sites(
                        args,
                        source_code,
                        candidates,
                    ));
                }
            }

            // A member call names a member, not a function. Record where the
            // dispatch happens; what it can reach is resolved by joining
            // against the functions installed in that member.
            if let Some(member) = member {
                let name = &source_code[member.byte_range()];
                if name.is_empty() {
                    continue;
                }

                let (receiver_expr, kind) = match receiver {
                    Some(receiver) => (
                        Some(collapse_whitespace(&source_code[receiver.byte_range()])),
                        Self::member_kind(member, source_code),
                    ),
                    None => (None, DispatchKind::MemberArrow),
                };

                extraction.member_sites.push(RawDispatchSite {
                    member: name.to_string(),
                    receiver_expr,
                    receiver_type: None,
                    receiver_base_type: None,
                    receiver_field: None,
                    kind,
                    byte_start: member.start_byte(),
                    line: member.start_position().row as u32 + 1,
                    target: None,
                });
            }
        }

        extraction.pointer_vars = Self::collect_pointer_vars(tree.root_node(), source_code);
        extraction.registrations = Self::collect_registrations(tree.root_node(), source_code);
        extraction.argument_functions =
            Self::collect_argument_functions(tree.root_node(), source_code);
        extraction
            .registrations
            .extend(Self::collect_assignments(tree.root_node(), source_code));

        // The shapes a declaration takes differ per language, so each gets
        // the pass that can read it.
        match language {
            Language::Rust => Self::type_rust_receivers(
                tree.root_node(),
                source_code,
                &mut extraction.member_sites,
            ),
            _ => Self::type_receivers(tree.root_node(), source_code, &mut extraction.member_sites),
        }

        // A keyword is not a member, so anything named after one came from a
        // misread, not from the code. Neither is a member reached from
        // nothing: every dispatch has a receiver, and a site without one came
        // from the same kind of misread — assembly in a macro body, read as C.
        extraction.member_sites.retain(|site| {
            !Self::is_c_keyword(&site.member)
                && !matches!(
                    site.kind,
                    DispatchKind::MemberArrow | DispatchKind::MemberDot
                ) | site
                    .receiver_expr
                    .as_deref()
                    .is_some_and(|receiver| !receiver.trim().is_empty())
        });
        extraction
            .registrations
            .retain(|registration| !Self::is_c_keyword(&registration.member));

        Ok(extraction)
    }

    /// File-scope variables of aggregate type, declaration or definition.
    ///
    /// `extern struct machdep_calls ppc_md;` is what lets a call written as
    /// `ppc_md.memory_block_size()` be typed, in a file that includes the
    /// header rather than containing it.
    fn collect_file_scope_globals(root: tree_sitter::Node, source: &str) -> Vec<RawGlobal> {
        let mut out = Vec::new();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            // A declaration inside a function is a local, and locals are
            // typed by the pass that can see the scope.
            if node.kind() == "function_definition" {
                continue;
            }
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                stack.push(child);
            }
            if node.kind() != "declaration" {
                continue;
            }
            let Some(type_node) = node.child_by_field_name("type") else {
                continue;
            };
            let Some(type_name) = Self::aggregate_type_name(type_node, source) else {
                continue;
            };
            let mut cursor = node.walk();
            for declarator in node.children_by_field_name("declarator", &mut cursor) {
                let mut current = declarator;
                let mut is_function = false;
                loop {
                    if current.kind() == "function_declarator" {
                        is_function = true;
                    }
                    if current.kind() == "identifier" {
                        // A prototype names a function, not a variable.
                        if !is_function {
                            out.push(RawGlobal {
                                name: source[current.byte_range()].to_string(),
                                type_name: type_name.clone(),
                                line: current.start_position().row as u32 + 1,
                            });
                        }
                        break;
                    }
                    match current
                        .child_by_field_name("declarator")
                        .or_else(|| current.named_child(0))
                    {
                        Some(next) => current = next,
                        None => break,
                    }
                }
            }
        }
        out
    }

    /// Give each Rust dispatch site the type of its receiver.
    ///
    /// Rust states the type of every parameter and of every annotated
    /// binding, and `self` is whatever the enclosing `impl` names, so a
    /// receiver that is a plain name can be typed without leaving the file.
    /// C needs its own pass because the shapes differ; this one reads
    /// `function_item`, `parameter` and `let_declaration`.
    fn type_rust_receivers(root: tree_sitter::Node, source: &str, sites: &mut [RawDispatchSite]) {
        if sites.is_empty() {
            return;
        }

        let mut scopes: Vec<(usize, usize, HashMap<String, String>)> = Vec::new();
        let mut stack = vec![(root, None::<String>)];
        while let Some((node, self_type)) = stack.pop() {
            // `impl Foo { ... }` is what `self` means inside.
            let self_type = if node.kind() == "impl_item" {
                node.child_by_field_name("type")
                    .and_then(|t| Self::rust_type_name(t, source))
                    .or(self_type)
            } else {
                self_type
            };

            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                stack.push((child, self_type.clone()));
            }

            if node.kind() != "function_item" {
                continue;
            }

            let mut declared = HashMap::new();
            if let Some(self_type) = &self_type {
                declared.insert("self".to_string(), self_type.clone());
            }
            Self::rust_declared_types_in(node, source, &mut declared);
            scopes.push((node.start_byte(), node.end_byte(), declared));
        }

        for site in sites.iter_mut() {
            if site.receiver_type.is_some() {
                continue;
            }
            let Some(receiver) = site.receiver_expr.as_deref() else {
                continue;
            };
            let Some((_, _, declared)) = scopes
                .iter()
                .find(|(start, end, _)| site.byte_start >= *start && site.byte_start < *end)
            else {
                continue;
            };

            if is_plain_name(receiver) {
                if let Some(type_name) = declared.get(receiver) {
                    site.receiver_type = Some(type_name.clone());
                }
                continue;
            }

            // `self.inner.write()`: this file states what `self` is, and the
            // fields say what is read from it. What `inner` is declared as
            // belongs to whichever file defines that struct, so the path is
            // recorded and resolution walks it against the types table.
            if let Some((base, fields)) = field_path(receiver) {
                if let Some(base_type) = declared.get(base) {
                    site.receiver_base_type = Some(base_type.clone());
                    site.receiver_field = Some(fields);
                }
            }
        }
    }

    /// Names a Rust body binds to a stated type: parameters, and bindings
    /// annotated at the `let`. An inferred binding states nothing here, and
    /// guessing from the initialiser would need the callee's return type.
    fn rust_declared_types_in(
        node: tree_sitter::Node,
        source: &str,
        out: &mut HashMap<String, String>,
    ) {
        let mut stack = vec![node];
        while let Some(current) = stack.pop() {
            let mut cursor = current.walk();
            for child in current.children(&mut cursor) {
                // A nested closure or item has its own bindings; the outer
                // ones still apply, so keep walking.
                stack.push(child);
            }
            if !matches!(current.kind(), "parameter" | "let_declaration") {
                continue;
            }
            let (Some(pattern), Some(type_node)) = (
                current.child_by_field_name("pattern"),
                current.child_by_field_name("type"),
            ) else {
                continue;
            };
            if pattern.kind() != "identifier" {
                continue;
            }
            let Some(type_name) = Self::rust_type_name(type_node, source) else {
                continue;
            };
            out.insert(source[pattern.byte_range()].to_string(), type_name);
        }
    }

    /// The name a Rust type node denotes, with references, lifetimes and
    /// generic arguments removed: `&mut fmt::Formatter<'_>` is a Formatter.
    ///
    /// A raw pointer is not stripped. `&T` reaches T's methods by
    /// autoderef, so a call on it dispatches on T, but `(*mut T).cast()` is
    /// a method of the pointer, and typing the receiver as T would claim a
    /// member T does not have.
    fn rust_type_name(node: tree_sitter::Node, source: &str) -> Option<String> {
        let mut node = node;
        loop {
            match node.kind() {
                "reference_type" => {
                    node = node.child_by_field_name("type")?;
                }
                "generic_type" => {
                    // A call through a smart pointer dispatches on what it
                    // holds: `Arc<TagSet>::raw_tag_set` is a method of
                    // TagSet, reached by Deref. Only pointers that deref to
                    // their argument are seen through; `Vec<T>` has methods
                    // of its own and is not one.
                    let base = node.child_by_field_name("type")?;
                    let base_name = Self::rust_type_name(base, source)?;
                    if !matches!(
                        base_name.as_str(),
                        "Arc" | "Rc" | "Box" | "Pin" | "ARef" | "KBox" | "UniqueArc" | "Owned"
                    ) {
                        return Some(base_name);
                    }
                    let held = node
                        .child_by_field_name("type_arguments")
                        .and_then(|arguments| {
                            let mut cursor = arguments.walk();
                            let found = arguments
                                .named_children(&mut cursor)
                                .find(|child| child.kind() != "lifetime");
                            found
                        });
                    match held {
                        Some(held) => node = held,
                        None => return Some(base_name),
                    }
                }
                "scoped_type_identifier" => {
                    node = node.child_by_field_name("name")?;
                }
                "type_identifier" | "primitive_type" | "identifier" => {
                    return Some(source[node.byte_range()].to_string());
                }
                _ => return None,
            }
        }
    }

    /// Give each member dispatch the type of its receiver, where the file
    /// declares it.
    ///
    /// ```text
    /// static int probe(struct file_operations *ops) { ops->read(...); }
    /// ```
    ///
    /// `ops` is declared here, so the site can say it dispatches through
    /// `file_operations::read` rather than through some member named `read`.
    /// Only names a scope declares are used: a receiver whose type comes from
    /// a header this file does not contain stays untyped, and a receiver that
    /// is itself a member access (`inode->i_fop->read()`) needs the field's
    /// type, which is a query-time lookup in the types table.
    ///
    /// A name declared twice with different types in one function is left
    /// untyped as well. Shadowing is rare, and a site filed under the wrong
    /// type joins with the wrong registrations, which is worse than a site
    /// that admits it does not know.
    fn type_receivers(root: tree_sitter::Node, source: &str, sites: &mut [RawDispatchSite]) {
        if sites.is_empty() {
            return;
        }

        // Declarations outside every function, which any function can see.
        let file_scope = Self::declared_types_in(root, source, true);

        let mut scopes: Vec<(usize, usize, HashMap<String, Option<String>>)> = Vec::new();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                stack.push(child);
            }

            if node.kind() != "function_definition" {
                continue;
            }
            scopes.push((
                node.start_byte(),
                node.end_byte(),
                Self::declared_types_in(node, source, false),
            ));
        }

        for site in sites.iter_mut() {
            // A table that named itself already has its container: asking
            // the declaration what `kvm_vmx_exit_handlers` is answers `int`,
            // which would replace the answer with a wrong one. A table held
            // in a struct field has not, and typing its base is what would
            // let it be resolved later.
            if matches!(
                site.kind,
                DispatchKind::ArrayElement | DispatchKind::StaticCall
            ) && site.receiver_type.is_some()
            {
                continue;
            }
            let Some(receiver) = site.receiver_expr.as_deref() else {
                continue;
            };

            let scope = scopes
                .iter()
                .find(|(start, end, _)| site.byte_start >= *start && site.byte_start < *end)
                .map(|(_, _, declared)| declared);
            let declared_type = |name: &str| -> Option<String> {
                match scope
                    .and_then(|declared| declared.get(name))
                    .or_else(|| file_scope.get(name))
                {
                    Some(Some(type_name)) => Some(type_name.clone()),
                    _ => None,
                }
            };

            if is_plain_name(receiver) {
                site.receiver_type = declared_type(receiver);
                continue;
            }

            // `inode->i_fop->read()`: the file proves what `inode` is, and
            // the fields say what is read from it. What `i_fop` is declared
            // as belongs to whichever file declares struct inode, so the path
            // is stored and resolution walks it.
            if let Some((base, fields)) = field_path(receiver) {
                if let Some(base_type) = declared_type(base) {
                    // A table held in a field is keyed by the type and the
                    // field together, which is what the initializer recorded.
                    // Anything else needs the field's own type, which lives
                    // with whichever file declares the struct.
                    if site.kind == DispatchKind::ArrayElement {
                        site.receiver_type = Some(format!("{base_type}.{fields}"));
                    } else {
                        site.receiver_base_type = Some(base_type);
                        site.receiver_field = Some(fields);
                    }
                }
            }
        }
    }

    /// Names declared in this subtree with the aggregate type each was
    /// declared as. A name declared twice with conflicting types maps to
    /// `None`: the scope does not say which one a use refers to.
    ///
    /// `outer_only` keeps the walk out of functions entirely, which is how
    /// file scope is collected without picking up another function's
    /// parameters and locals.
    fn declared_types_in(
        node: tree_sitter::Node,
        source: &str,
        outer_only: bool,
    ) -> HashMap<String, Option<String>> {
        let mut declared: HashMap<String, Option<String>> = HashMap::new();
        let mut stack = vec![node];

        while let Some(node) = stack.pop() {
            // File scope is what a function did not declare: parameters and
            // locals belong to one function, and reading them as file scope
            // types a receiver in a function that never declared it.
            if outer_only && node.kind() == "function_definition" {
                continue;
            }

            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                stack.push(child);
            }

            if !matches!(node.kind(), "declaration" | "parameter_declaration") {
                continue;
            }

            let type_name = node
                .child_by_field_name("type")
                .and_then(|type_node| Self::aggregate_type_name(type_node, source));

            let mut cursor = node.walk();
            for declarator in node.children_by_field_name("declarator", &mut cursor) {
                let declarator = if declarator.kind() == "init_declarator" {
                    match declarator.child_by_field_name("declarator") {
                        Some(inner) => inner,
                        None => continue,
                    }
                } else {
                    declarator
                };

                let Some(name) = Self::innermost_declarator_name(declarator) else {
                    continue;
                };
                let name = source[name.byte_range()].to_string();
                if name.is_empty() {
                    continue;
                }

                declared
                    .entry(name)
                    .and_modify(|known| {
                        if *known != type_name {
                            *known = None;
                        }
                    })
                    .or_insert_with(|| type_name.clone());
            }
        }

        declared
    }

    /// A struct has no member named `long`, because C will not allow one.
    /// Assembly written in a macro body reads as C that says otherwise:
    ///
    /// ```text
    /// #define __ASM_EXTABLE_RAW(insn, fixup, type, data)  \
    ///         .pushsection __ex_table, "a";               \
    ///         .long ((insn) - .);
    /// ```
    ///
    /// `.long ((insn) - .)` parses as a call through a member named `long`,
    /// and `.short (type)` as one named `short`. Rejecting a member that is a
    /// keyword drops those without needing to know which bodies are assembly
    /// — the same reading is wrong wherever it happens.
    fn is_c_keyword(name: &str) -> bool {
        const KEYWORDS: [&str; 55] = [
            // C89 and C99
            "auto",
            "break",
            "case",
            "char",
            "const",
            "continue",
            "default",
            "do",
            "double",
            "else",
            "enum",
            "extern",
            "float",
            "for",
            "goto",
            "if",
            "inline",
            "int",
            "long",
            "register",
            "restrict",
            "return",
            "short",
            "signed",
            "sizeof",
            "static",
            "struct",
            "switch",
            "typedef",
            "union",
            "unsigned",
            "void",
            "volatile",
            "while",
            // C11
            "_Alignas",
            "_Alignof",
            "_Atomic",
            "_Bool",
            "_Complex",
            "_Generic",
            "_Imaginary",
            "_Noreturn",
            "_Static_assert",
            "_Thread_local",
            // C23, and the spellings the older headers get from <stdbool.h>
            // and friends, which a member cannot use either
            "alignas",
            "alignof",
            "bool",
            "constexpr",
            "false",
            "nullptr",
            "static_assert",
            "thread_local",
            "true",
            "typeof",
            "typeof_unqual",
        ];

        KEYWORDS.contains(&name)
    }

    /// Every `.member = target` in the file whose container type the file
    /// itself states. An initializer whose type is not stated is skipped: a
    /// registration filed under the wrong type joins with the wrong dispatch
    /// sites, which is worse than not having it.
    /// What a function does with one of its parameters.
    ///
    /// A registrar is not a name on a list: it is a function that puts what it
    /// was given somewhere. `request_threaded_irq` stores its handler in
    /// `irqaction::handler`, and `request_irq` is a registrar only because it
    /// hands its own parameter to that one. Enumerating registrars instead
    /// would miss every subsystem's own.
    ///
    /// Intraprocedural: one body, no value tracking beyond the parameter's
    /// own name. A caller that wants the wrapper case follows `HandedOn`.
    pub fn parameter_fate(body: &str, parameter: &str) -> Vec<ParameterFate> {
        let mut parser = Parser::new();
        if parser
            .set_language(&tree_sitter_c::LANGUAGE.into())
            .is_err()
        {
            return Vec::new();
        }
        let Some(tree) = parser.parse(body, None) else {
            return Vec::new();
        };

        let mut fates = Vec::new();

        // Storing it in a member is what makes the caller's function
        // reachable, and that shape is already recognised.
        let mut written = Self::collect_registrations(tree.root_node(), body);
        written.extend(Self::collect_assignments(tree.root_node(), body));
        for registration in written {
            if registration.target == parameter {
                fates.push(ParameterFate::StoredIn {
                    container_type: registration.container_type.clone(),
                    member: registration.member.clone(),
                });
            }
        }

        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                stack.push(child);
            }
            if node.kind() != "call_expression" {
                continue;
            }
            let Some(callee) = node.child_by_field_name("function") else {
                continue;
            };
            if callee.kind() == "identifier" && &body[callee.byte_range()] == parameter {
                fates.push(ParameterFate::Invoked);
                continue;
            }
            if callee.kind() != "identifier" {
                continue;
            }
            let callee_name = body[callee.byte_range()].to_string();
            let Some(arguments) = node.child_by_field_name("arguments") else {
                continue;
            };
            let mut cursor = arguments.walk();
            for (index, argument) in arguments.named_children(&mut cursor).enumerate() {
                let named = match argument.kind() {
                    "identifier" => Some(argument),
                    "pointer_expression" => argument
                        .child_by_field_name("argument")
                        .filter(|node| node.kind() == "identifier"),
                    _ => None,
                };
                let Some(named) = named else { continue };
                if &body[named.byte_range()] != parameter {
                    continue;
                }
                fates.push(ParameterFate::HandedOn {
                    callee: callee_name.clone(),
                    argument_index: index as u32,
                });
            }
        }

        fates
    }

    /// Macros that define a function, and how the function is named.
    ///
    /// `SYSCALL_DEFINE3(old_readdir, ...)` defines `sys_old_readdir`, whose
    /// body follows the invocation. The prefix is convention held in the
    /// macro, not in the call, so the families are listed; the shape they
    /// share — an invocation followed by a block — is what the extractor
    /// recognises.
    fn body_defining_macro(name: &str) -> Option<&'static str> {
        if let Some(rest) = name.strip_prefix("COMPAT_SYSCALL_DEFINE") {
            return rest.parse::<u8>().is_ok().then_some("compat_sys_");
        }
        if let Some(rest) = name.strip_prefix("SYSCALL_DEFINE") {
            return rest.parse::<u8>().is_ok().then_some("sys_");
        }
        None
    }

    /// Functions a macro defines, whose body follows the invocation.
    ///
    /// ```text
    /// SYSCALL_DEFINE3(old_readdir, unsigned int, fd, ...)
    /// {
    ///         ...
    /// }
    /// ```
    ///
    /// The parser reads the invocation as an expression statement and the
    /// block as an unrelated compound statement, so neither the name nor the
    /// body reaches the functions table and every call the body makes is
    /// lost with it.
    fn macro_defined_functions(root: tree_sitter::Node, source: &str) -> Vec<MacroDefinedFunction> {
        let mut found = Vec::new();

        // The invocation and its block are siblings, and a conditional makes
        // them siblings of each other inside it rather than of the file.
        // `SYSCALL_DEFINE3(old_readdir, ...)` sits inside
        // `#ifdef __ARCH_WANT_OLD_READDIR`.
        for children in &Self::file_scope_sequences(root) {
            for (index, node) in children.iter().enumerate() {
                if node.kind() != "expression_statement" {
                    continue;
                }
                let Some(call) = node
                    .named_child(0)
                    .filter(|c| c.kind() == "call_expression")
                else {
                    continue;
                };
                let Some(callee) = call.child_by_field_name("function") else {
                    continue;
                };
                if callee.kind() != "identifier" {
                    continue;
                }
                let Some(prefix) = Self::body_defining_macro(&source[callee.byte_range()]) else {
                    continue;
                };
                // The block has to be next, and has to be a body rather than an
                // initializer: a macro that opens a struct is the same shape.
                let Some(body) = children
                    .get(index + 1)
                    .filter(|next| next.kind() == "compound_statement")
                else {
                    continue;
                };
                let Some(arguments) = call.child_by_field_name("arguments") else {
                    continue;
                };
                let mut argument_cursor = arguments.walk();
                let Some(first) = arguments
                    .named_children(&mut argument_cursor)
                    .find(|argument| argument.kind() == "identifier")
                else {
                    continue;
                };

                found.push(MacroDefinedFunction {
                    name: format!("{prefix}{}", &source[first.byte_range()]),
                    start_byte: node.start_byte(),
                    end_byte: body.end_byte(),
                    line_start: node.start_position().row as u32 + 1,
                    line_end: body.end_position().row as u32 + 1,
                    guard: Self::guard_of(*node, source),
                });
            }
        }

        found
    }

    /// The functions called between two byte offsets, with calls through a
    /// declared function pointer diverted to dispatch sites.
    ///
    /// Taken from the file's pre-computed call list rather than walking the
    /// body again, so a body found by any means can be attributed the same
    /// way.
    fn calls_in_range(
        ctx: &ExtractionContext,
        extraction: &CallExtraction,
        start: usize,
        end: usize,
        pointer_call_sites: &mut Vec<RawDispatchSite>,
    ) -> Vec<String> {
        let pointers: HashMap<&str, &PointerVar> = extraction
            .pointer_vars
            .iter()
            .filter(|var| var.byte_start >= start && var.byte_start < end)
            .map(|var| (var.name.as_str(), var))
            .collect();

        let mut calls: Vec<String> = Vec::new();
        for (call_name, call_start, call_end) in &extraction.calls {
            if *call_start < start || *call_end > end {
                continue;
            }
            match pointers.get(call_name.as_str()) {
                Some(var) => pointer_call_sites.push(RawDispatchSite {
                    member: String::new(),
                    receiver_expr: Some(var.name.clone()),
                    receiver_type: None,
                    receiver_base_type: None,
                    receiver_field: None,
                    kind: if var.is_parameter {
                        DispatchKind::PointerParam
                    } else {
                        DispatchKind::PointerLocal
                    },
                    byte_start: *call_start,
                    line: ctx.source[..*call_start].lines().count() as u32,
                    target: var.target.clone(),
                }),
                None => calls.push(call_name.clone()),
            }
        }

        calls.sort();
        calls.dedup();
        calls
    }

    /// Names that a scope binds to a value rather than to a function.
    ///
    /// `min_t(u32, len, size)` names no function even where the tree defines
    /// one called `len`, so an argument is only worth recording when the file
    /// does not declare that name as a variable or a parameter.
    fn value_names(root: tree_sitter::Node, source: &str) -> ValueNames {
        let mut file_scope = HashSet::new();
        let mut per_function: Vec<(usize, usize, HashSet<String>)> = Vec::new();
        let mut stack = vec![(root, false)];
        while let Some((node, in_function)) = stack.pop() {
            let entering_function = node.kind() == "function_definition";
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                stack.push((child, in_function || entering_function));
            }
            if entering_function {
                let mut names = HashSet::new();
                Self::declared_value_names(node, source, &mut names);
                per_function.push((node.start_byte(), node.end_byte(), names));
                continue;
            }
            if !in_function && node.kind() == "declaration" {
                Self::declared_value_names(node, source, &mut file_scope);
            }
        }
        ValueNames {
            file_scope,
            per_function,
        }
    }

    /// Identifiers a declaration binds, skipping function prototypes: those
    /// name a function, which is what an argument is being tested against.
    fn declared_value_names(node: tree_sitter::Node, source: &str, out: &mut HashSet<String>) {
        let mut stack = vec![node];
        while let Some(current) = stack.pop() {
            let mut cursor = current.walk();
            for child in current.children(&mut cursor) {
                stack.push(child);
            }
            if !matches!(current.kind(), "declaration" | "parameter_declaration") {
                continue;
            }
            let mut cursor = current.walk();
            for declarator in current.children_by_field_name("declarator", &mut cursor) {
                let mut node = declarator;
                let mut is_function = false;
                loop {
                    if node.kind() == "function_declarator" {
                        is_function = true;
                    }
                    if node.kind() == "identifier" {
                        if !is_function {
                            out.insert(source[node.byte_range()].to_string());
                        }
                        break;
                    }
                    match node
                        .child_by_field_name("declarator")
                        .or_else(|| node.named_child(0))
                    {
                        Some(next) => node = next,
                        None => break,
                    }
                }
            }
        }
    }

    /// Calls that name an identifier as an argument.
    ///
    /// ```text
    /// request_irq(irq, e1000_intr, flags, name, dev);
    /// ```
    ///
    /// `e1000_intr` is handed to `request_irq`, which is the edge that makes
    /// the handler reachable. Whether the callee stores it, calls it, or
    /// merely names it cannot be decided here: the callee's body is usually
    /// in another file. So every identifier argument the file does not bind
    /// to a value is recorded, and the reader keeps those that name a
    /// function.
    fn collect_argument_functions(
        root: tree_sitter::Node,
        source: &str,
    ) -> Vec<RawArgumentFunction> {
        let bound = Self::value_names(root, source);
        let locals = Self::collect_local_struct_types(root, source);
        let mut out = Vec::new();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                stack.push(child);
            }
            if node.kind() != "call_expression" {
                continue;
            }
            let Some(callee) = node.child_by_field_name("function") else {
                continue;
            };
            if callee.kind() != "identifier" {
                continue;
            }
            let callee_name = &source[callee.byte_range()];
            if Self::names_without_handing_over(callee_name) {
                continue;
            }
            let Some(arguments) = node.child_by_field_name("arguments") else {
                continue;
            };
            // What the function is being attached to, if the call says so.
            // `call_rcu(&inode->i_rcu, i_callback)` puts the callback in a
            // member of an rcu_head, and only this argument records which
            // inode holds that head.
            let mut cursor = arguments.walk();
            let subject = arguments.named_children(&mut cursor).find_map(|argument| {
                let field = match argument.kind() {
                    "field_expression" => argument,
                    "pointer_expression" => argument
                        .child_by_field_name("argument")
                        .filter(|node| node.kind() == "field_expression")?,
                    _ => return None,
                };
                let base = field.child_by_field_name("argument")?;
                if base.kind() != "identifier" {
                    return None;
                }
                let member = field.child_by_field_name("field")?;
                let base_type = locals.get(&source[base.byte_range()])?;
                Some((base_type.clone(), source[member.byte_range()].to_string()))
            });

            let mut cursor = arguments.walk();
            for (index, argument) in arguments.named_children(&mut cursor).enumerate() {
                let (identifier, taken_address) = match argument.kind() {
                    "identifier" => (Some(argument), false),
                    "pointer_expression" => (
                        argument
                            .child_by_field_name("argument")
                            .filter(|node| node.kind() == "identifier"),
                        true,
                    ),
                    _ => (None, false),
                };
                let Some(identifier) = identifier else {
                    continue;
                };
                let name = &source[identifier.byte_range()];
                // A call naming itself is recursion, not a handover.
                if name == callee_name || Self::is_c_keyword(name) {
                    continue;
                }
                if bound.contains(name, identifier.start_byte()) {
                    continue;
                }
                out.push(RawArgumentFunction {
                    callee: callee_name.to_string(),
                    target: name.to_string(),
                    argument_index: index as u32,
                    taken_address,
                    subject_type: subject.as_ref().map(|(type_name, _)| type_name.clone()),
                    subject_member: subject.as_ref().map(|(_, member)| member.clone()),
                    byte_start: identifier.start_byte(),
                    line: identifier.start_position().row as u32 + 1,
                });
            }
        }
        out
    }

    /// Callees that name a function without handing it anywhere.
    ///
    /// An export names its own function, and `container_of` takes a type and
    /// a member. `module_init` and `module_exit` install one, but the initcall
    /// they build is recorded already, and recording it twice would double
    /// every module entry point.
    fn names_without_handing_over(callee: &str) -> bool {
        callee.starts_with("EXPORT_SYMBOL")
            || callee.starts_with("KSYMTAB")
            || callee.starts_with("SYMBOL_")
            || callee.starts_with("MODULE_")
            || callee.starts_with("BTF_ID")
            || matches!(
                callee,
                "container_of"
                    | "container_of_const"
                    | "offsetof"
                    | "offsetofend"
                    | "sizeof_field"
                    | "typeof_member"
                    | "module_init"
                    | "module_exit"
            )
    }

    fn collect_registrations(root: tree_sitter::Node, source: &str) -> Vec<RawRegistration> {
        let mut found = Vec::new();
        let mut stack = vec![root];

        while let Some(node) = stack.pop() {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                stack.push(child);
            }

            if let Some(registration) = Self::initcall(node, source) {
                found.push(registration);
                continue;
            }

            if let Some(registration) = Self::static_call_install(node, source) {
                found.push(registration);
                continue;
            }

            if node.kind() != "initializer_list" {
                continue;
            }

            // A table of function pointers names no type to fill and no
            // member to fill it with. The table itself is the container, and
            // every element is a way in.
            if let Some(table) = Self::function_pointer_table(node, source) {
                found.extend(Self::table_elements(node, source, &table));
                continue;
            }

            let Some((outer_type, path)) = Self::initializer_container(node, source) else {
                continue;
            };
            // An empty path means the list fills the type the file named, so
            // the container is known outright.
            let (container_type, container_base_type, container_field) = if path.is_empty() {
                (outer_type, None, None)
            } else {
                (String::new(), Some(outer_type), Some(path.join(".")))
            };

            for (member_node, value) in Self::initializer_members(node) {
                let member = source[member_node.byte_range()].to_string();
                // `.read = my_read` and `.read = &my_read` say the same thing.
                let target_node = match value.kind() {
                    "identifier" => Some(value),
                    "pointer_expression" => value
                        .child_by_field_name("argument")
                        .filter(|a| a.kind() == "identifier"),
                    _ => None,
                };
                // `.demod_attach = { demod_attach_stv0900, cineS2_probe }`
                // is a table the struct holds. The field is the container and
                // every element is a way in, the same shape a standalone
                // table has, so the key names both: a field holds one table
                // per struct type, and the type alone would collide with
                // every other struct that has a field of that name.
                if value.kind() == "initializer_list" && !container_type.is_empty() {
                    found.extend(Self::held_table_elements(
                        value,
                        source,
                        &format!("{container_type}.{member}"),
                    ));
                    continue;
                }

                let Some(target_node) = target_node else {
                    continue;
                };

                let target = source[target_node.byte_range()].to_string();
                if member.is_empty() || target.is_empty() {
                    continue;
                }

                found.push(RawRegistration {
                    container_type: container_type.clone(),
                    container_base_type: container_base_type.clone(),
                    container_field: container_field.clone(),
                    member,
                    target,
                    byte_start: member_node.start_byte(),
                    line: member_node.start_position().row as u32 + 1,
                    kind: RegistrationKind::DesignatedInit,
                });
            }
        }

        found
    }

    /// `x->handler = my_handler;` installs a function just as an initializer
    /// does. The type of `x` has to come from a declaration in this file:
    /// the struct is usually declared in a header the file does not contain,
    /// and a registration filed under a guessed type is worse than none.
    fn collect_assignments(root: tree_sitter::Node, source: &str) -> Vec<RawRegistration> {
        let locals = Self::collect_local_struct_types(root, source);
        let mut found = Vec::new();
        let mut stack = vec![root];

        while let Some(node) = stack.pop() {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                stack.push(child);
            }

            if node.kind() != "assignment_expression" {
                continue;
            }

            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                continue;
            };
            if left.kind() != "field_expression" {
                continue;
            }

            let target = match right.kind() {
                "identifier" => source[right.byte_range()].to_string(),
                "pointer_expression" => match right
                    .child_by_field_name("argument")
                    .filter(|a| a.kind() == "identifier")
                {
                    Some(a) => source[a.byte_range()].to_string(),
                    None => continue,
                },
                _ => continue,
            };

            let Some(member) = left
                .child_by_field_name("field")
                .map(|f| source[f.byte_range()].to_string())
            else {
                continue;
            };

            // Only a receiver that is a plain variable declared here can be
            // typed without leaving the file.
            let Some(receiver) = left.child_by_field_name("argument") else {
                continue;
            };
            let receiver_text = collapse_whitespace(&source[receiver.byte_range()]);

            // `x->member = f` names its container as soon as `x` is declared
            // here. `s->s_shrink->scan_objects = f` does not: `s_shrink` is
            // declared with struct super_block, in a header this file
            // includes rather than contains. Record what is known — the type
            // of the base and the path read from it — and let resolution
            // finish it against the types table.
            let (container_type, container_base_type, container_field) =
                if receiver.kind() == "identifier" {
                    match locals.get(&receiver_text) {
                        Some(container) => (container.clone(), None, None),
                        None => continue,
                    }
                } else {
                    match field_path(&receiver_text) {
                        Some((base, path)) => match locals.get(base) {
                            Some(base_type) => (String::new(), Some(base_type.clone()), Some(path)),
                            None => continue,
                        },
                        None => continue,
                    }
                };

            found.push(RawRegistration {
                container_type,
                container_base_type,
                container_field,
                member,
                target,
                byte_start: node.start_byte(),
                line: node.start_position().row as u32 + 1,
                kind: RegistrationKind::Assignment,
            });
        }

        found
    }

    /// Variables in this file declared as a struct, union or typedef, by name.
    /// Shadowing is ignored: two locals of the same name in one file with
    /// different types are rare, and the cost is a registration filed under
    /// the wrong one of the two.
    fn collect_local_struct_types(
        root: tree_sitter::Node,
        source: &str,
    ) -> std::collections::HashMap<String, String> {
        let mut types = std::collections::HashMap::new();
        let mut stack = vec![root];

        while let Some(node) = stack.pop() {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                stack.push(child);
            }

            if !matches!(node.kind(), "declaration" | "parameter_declaration") {
                continue;
            }

            let Some(type_node) = node.child_by_field_name("type") else {
                continue;
            };
            let Some(type_name) = Self::aggregate_type_name(type_node, source) else {
                continue;
            };

            let mut cursor = node.walk();
            for declarator in node.children_by_field_name("declarator", &mut cursor) {
                let declarator = if declarator.kind() == "init_declarator" {
                    match declarator.child_by_field_name("declarator") {
                        Some(inner) => inner,
                        None => continue,
                    }
                } else {
                    declarator
                };

                if let Some(name) = Self::innermost_declarator_name(declarator) {
                    let name = source[name.byte_range()].to_string();
                    if !name.is_empty() {
                        types.insert(name, type_name.clone());
                    }
                }
            }
        }

        types
    }

    /// The type an initializer fills in, taken from the declaration or the
    /// compound literal that holds it. A nested initializer states no type of
    /// its own, and inferring one would need the member's declared type,
    /// which usually lives in another file.
    /// The members one initializer list installs, as (member, value).
    ///
    /// A preprocessor line inside the list defeats the grammar:
    ///
    /// ```text
    /// static const struct tcp_sock_af_ops tcp_sock_ipv4_specific = {
    /// #ifdef CONFIG_TCP_AO
    ///         .ao_lookup = tcp_v4_ao_lookup,
    /// ```
    ///
    /// parses as an error, and `.ao_lookup = tcp_v4_ao_lookup` then recovers
    /// as an *assignment* whose object is the previous pair's value. Reading
    /// only `initializer_pair` children loses every member the first arm of a
    /// conditional installs while keeping the ones after `#else`, which is how
    /// half a struct goes missing with nothing looking wrong.
    ///
    /// An assignment cannot appear in an initializer list in C, so one here is
    /// always that recovery, and the field it assigns to is the member. The
    /// object it appears to assign through is an artefact and is ignored.
    ///
    /// A nested list is skipped: it is its own list with its own container,
    /// and the walk reaches it separately.
    fn initializer_members(list: tree_sitter::Node) -> Vec<(tree_sitter::Node, tree_sitter::Node)> {
        let mut members = Vec::new();
        let mut cursor = list.walk();

        for child in list.named_children(&mut cursor) {
            let named = match child.kind() {
                "initializer_pair" => child
                    .child_by_field_name("designator")
                    .filter(|d| d.kind() == "field_designator")
                    .and_then(|d| d.named_child(0))
                    .zip(child.child_by_field_name("value")),
                "assignment_expression" => child
                    .child_by_field_name("left")
                    .filter(|l| l.kind() == "field_expression")
                    .and_then(|l| l.child_by_field_name("field"))
                    .zip(child.child_by_field_name("right")),
                _ => None,
            };

            if let Some(pair) = named {
                members.push(pair);
            }
        }

        members
    }

    /// A function installed in a static-call key.
    ///
    /// ```text
    /// DEFINE_STATIC_CALL(kvm_x86_run, vmx_vcpu_run);
    /// static_call_update(kvm_x86_run, svm_vcpu_run);
    /// ```
    ///
    /// The key is a slot holding one function, and a call through it is
    /// patched into a direct branch at run time. Nothing dispatches through a
    /// pointer and nothing assigns one, so neither the member walk nor the
    /// table walk sees this.
    ///
    /// A key built by pasting — the kernel writes `static_call(kvm_x86_##op)`
    /// behind `kvm_x86_call(op)` — is not recorded, because the name does not
    /// exist until the preprocessor makes it.
    fn static_call_install(node: tree_sitter::Node, source: &str) -> Option<RawRegistration> {
        let call = match node.kind() {
            "expression_statement" => node.named_child(0)?,
            "call_expression" => node,
            _ => return None,
        };
        if call.kind() != "call_expression" {
            return None;
        }

        let name = call.child_by_field_name("function")?;
        if name.kind() != "identifier" {
            return None;
        }
        let name = &source[name.byte_range()];
        // Only these two install the function they name.
        // `DEFINE_STATIC_CALL_NULL` and `DEFINE_STATIC_CALL_RET0` take a
        // prototype in that position and install nothing or a stub:
        // `DEFINE_STATIC_CALL_NULL(amd_pmu_branch_reset,
        // amd_pmu_branch_reset_t)` names a type, and the key starts out NULL.
        if !matches!(name, "DEFINE_STATIC_CALL" | "static_call_update") {
            return None;
        }

        let arguments = call.child_by_field_name("arguments")?;
        let mut cursor = arguments.walk();
        let named: Vec<tree_sitter::Node> = arguments.named_children(&mut cursor).collect();
        let [key, target] = named[..] else {
            return None;
        };
        if key.kind() != "identifier" || target.kind() != "identifier" {
            return None;
        }

        let (key, target) = (
            source[key.byte_range()].to_string(),
            source[target.byte_range()].to_string(),
        );
        if key.is_empty() || target.is_empty() {
            return None;
        }

        Some(RawRegistration {
            container_type: key,
            container_base_type: None,
            container_field: None,
            member: STATIC_CALL_MEMBER.to_string(),
            target,
            byte_start: call.start_byte(),
            line: call.start_position().row as u32 + 1,
            kind: RegistrationKind::Assignment,
        })
    }

    /// A function the kernel runs at boot, named by the macro that files it.
    ///
    /// ```text
    /// device_initcall(foo_init);
    /// ```
    ///
    /// The macro puts a pointer to `foo_init` in a section that
    /// `do_initcalls()` walks, so nothing in the source calls it and nothing
    /// assigns it anywhere: the function reads as dead. What the file does say
    /// is which level it is filed under, and that is what this records.
    ///
    /// No dispatch site is claimed. The call is a walk over a linker section
    /// in another file, and pretending to know that from here would be a
    /// guess. `registrations foo_init` answers; `callers foo_init` still says
    /// nothing calls it, which remains true of the source.
    fn initcall(node: tree_sitter::Node, source: &str) -> Option<RawRegistration> {
        // File scope: an initcall inside a function is something else. A
        // conditional is still file scope — `subsys_initcall(cgwb_init)` sits
        // inside `#ifdef CONFIG_CGROUP_WRITEBACK`.
        if node.kind() != "expression_statement" || !Self::at_file_scope(node) {
            return None;
        }

        let call = node
            .named_child(0)
            .filter(|c| c.kind() == "call_expression")?;
        let level = call.child_by_field_name("function")?;
        if level.kind() != "identifier" {
            return None;
        }
        let level = &source[level.byte_range()];
        let (argument_index, _) = Self::entry_point_macro(level)?;

        let arguments = call.child_by_field_name("arguments")?;
        let mut cursor = arguments.walk();
        let named: Vec<tree_sitter::Node> = arguments.named_children(&mut cursor).collect();
        // A macro that files a function alongside other values names it at a
        // fixed position; taking anything else would record a string.
        if named.len() != argument_index + 1 && argument_index == 0 {
            return None;
        }
        let &target = named.get(argument_index)?;
        if target.kind() != "identifier" {
            return None;
        }

        let name = source[target.byte_range()].to_string();
        if name.is_empty() {
            return None;
        }

        Some(RawRegistration {
            container_type: level.to_string(),
            container_base_type: None,
            container_field: None,
            member: ARRAY_ELEMENT_MEMBER.to_string(),
            target: name,
            byte_start: target.start_byte(),
            line: target.start_position().row as u32 + 1,
            kind: RegistrationKind::DesignatedInit,
        })
    }

    /// Whether a name files a function into an init or exit section.
    ///
    /// A closed family, spelled out rather than pattern-matched: `module_init`
    /// is one and `mutex_init` is not, and a suffix rule cannot tell them
    /// apart.
    /// The macros that file a function in a linker section, with the
    /// argument that names the function and when that section is walked.
    ///
    /// A section is walked by code that names no function, so nothing in the
    /// tree calls any of these and they all read as dead. There is no rule in
    /// the source that identifies them: the section attribute is inside the
    /// macro definition, and the name is often pasted together there, so the
    /// families are listed.
    pub fn entry_point_macro(name: &str) -> Option<(usize, &'static str)> {
        const BOOT_LEVELS: &[&str] = &[
            "early_initcall",
            "pure_initcall",
            "core_initcall",
            "core_initcall_sync",
            "postcore_initcall",
            "postcore_initcall_sync",
            "arch_initcall",
            "arch_initcall_sync",
            "subsys_initcall",
            "subsys_initcall_sync",
            "fs_initcall",
            "fs_initcall_sync",
            "rootfs_initcall",
            "device_initcall",
            "device_initcall_sync",
            "late_initcall",
            "late_initcall_sync",
            "console_initcall",
            "security_initcall",
            "subsys_initcall_entry",
        ];

        if BOOT_LEVELS.contains(&name) {
            return Some((0, "runs at boot"));
        }

        match name {
            "module_init" => Some((
                0,
                "runs when the module is inserted, or at boot if built in",
            )),
            "module_exit" => Some((0, "runs when the module is removed")),
            "__exitcall" => Some((0, "runs when the kernel shuts down")),
            // The string is the parameter; the function handles it.
            "__setup" | "early_param" => {
                Some((1, "runs at boot if the kernel is given that parameter"))
            }
            // A name, a compatible string, then the function.
            "CLK_OF_DECLARE"
            | "CLK_OF_DECLARE_DRIVER"
            | "IRQCHIP_DECLARE"
            | "TIMER_OF_DECLARE"
            | "OF_DECLARE_1"
            | "OF_DECLARE_1_RET"
            | "OF_DECLARE_2" => Some((2, "runs when a device tree node matches")),
            _ => None,
        }
    }

    /// Whether a name is one of the macros that files a function in a
    /// section.
    pub fn is_initcall_macro(name: &str) -> bool {
        Self::entry_point_macro(name).is_some()
    }

    /// The name of the array of function pointers this list initialises.
    ///
    /// ```text
    /// static int (*kvm_vmx_exit_handlers[])(struct kvm_vcpu *vcpu) = {
    ///         [EXIT_REASON_CPUID] = kvm_emulate_cpuid,
    /// ```
    ///
    /// The declaration states `int`, which says nothing, and the elements
    /// name an index rather than a member — so neither the type walk nor the
    /// member walk can see this, and everything reached through such a table
    /// looks uncalled. What identifies the slot is the table's own name.
    ///
    /// Recognised by shape: a declarator that is a function returning through
    /// a parenthesised pointer to an array, which is how C spells an array of
    /// function pointers and is not how it spells anything else.
    fn function_pointer_table(list: tree_sitter::Node, source: &str) -> Option<Table> {
        let parent = list.parent()?;
        if parent.kind() != "init_declarator" {
            return None;
        }

        let mut node = parent.child_by_field_name("declarator")?;
        let (mut saw_function, mut saw_pointer, mut saw_array) = (false, false, false);
        loop {
            match node.kind() {
                "function_declarator" => saw_function = true,
                "pointer_declarator" => saw_pointer = true,
                "array_declarator" => saw_array = true,
                "identifier" => break,
                _ => {}
            }
            node = node
                .child_by_field_name("declarator")
                .or_else(|| node.named_child(0))?;
        }

        let name = source[node.byte_range()].to_string();
        if name.is_empty() {
            return None;
        }

        // Written out: `int (*handlers[])(struct kvm_vcpu *)`. The declarator
        // says outright that the elements are functions.
        if saw_function && saw_pointer && saw_array {
            return Some(Table {
                name,
                element_type: None,
            });
        }

        // Hidden behind a typedef: `static bfa_isr_func_t bfa_isrs[N]`. All
        // the declarator says is that this is an array of something named
        // elsewhere, so record which name and let the reader ask the typedef
        // whether it is a function pointer. Guessing here would make a table
        // out of every array of enum constants.
        let declared = list.parent()?.parent()?.child_by_field_name("type")?;
        if saw_array && !saw_function && declared.kind() == "type_identifier" {
            return Some(Table {
                name,
                element_type: Some(source[declared.byte_range()].to_string()),
            });
        }

        None
    }

    /// The functions a table of function pointers holds.
    ///
    /// Both designated elements, `[EXIT_REASON_CPUID] = kvm_emulate_cpuid`,
    /// and positional ones. The index is not recorded as the member: a call
    /// through the table computes it at run time, so every element is a
    /// candidate and recording which one would suggest a precision the join
    /// does not have.
    fn table_elements(
        list: tree_sitter::Node,
        source: &str,
        table: &Table,
    ) -> Vec<RawRegistration> {
        let mut found = Vec::new();
        let mut cursor = list.walk();

        for child in list.named_children(&mut cursor) {
            let value = match child.kind() {
                "initializer_pair" => match child.child_by_field_name("value") {
                    Some(value) => value,
                    None => continue,
                },
                "identifier" => child,
                _ => continue,
            };

            let target_node = match value.kind() {
                "identifier" => Some(value),
                "pointer_expression" => value
                    .child_by_field_name("argument")
                    .filter(|a| a.kind() == "identifier"),
                _ => None,
            };
            let Some(target_node) = target_node else {
                continue;
            };

            let target = source[target_node.byte_range()].to_string();
            if target.is_empty() {
                continue;
            }

            found.push(RawRegistration {
                container_type: table.name.clone(),
                // Set only when a typedef stands between the declaration and
                // the fact that these are functions: the row is a claim that
                // holds if that name is a function-pointer typedef, and the
                // reader checks it.
                container_base_type: table.element_type.clone(),
                container_field: None,
                member: ARRAY_ELEMENT_MEMBER.to_string(),
                target,
                byte_start: target_node.start_byte(),
                line: target_node.start_position().row as u32 + 1,
                kind: RegistrationKind::DesignatedInit,
            });
        }

        found
    }

    /// Elements of a table held in a struct field.
    ///
    /// Every element has to be a plain name for the list to be a table of
    /// functions; a list with a value in it is initialising something else,
    /// and recording half of it would claim a table that is not there.
    fn held_table_elements(
        list: tree_sitter::Node,
        source: &str,
        container: &str,
    ) -> Vec<RawRegistration> {
        let mut cursor = list.walk();
        let elements: Vec<tree_sitter::Node> = list.named_children(&mut cursor).collect();
        if elements.is_empty() || elements.iter().any(|e| e.kind() != "identifier") {
            return Vec::new();
        }

        elements
            .iter()
            .map(|element| RawRegistration {
                container_type: container.to_string(),
                container_base_type: None,
                container_field: None,
                member: ARRAY_ELEMENT_MEMBER.to_string(),
                target: source[element.byte_range()].to_string(),
                byte_start: element.start_byte(),
                line: element.start_position().row as u32 + 1,
                kind: RegistrationKind::DesignatedInit,
            })
            .collect()
    }

    /// The type an initializer list fills in, and the path of fields to reach
    /// it from the type the file states.
    ///
    /// A list directly under a declaration or a compound literal names its
    /// own type and the path is empty. A nested one does not:
    ///
    /// ```text
    /// static struct nft_set_type nft_set_rbtree_type = {
    ///         .ops = {
    ///                 .activate = nft_rbtree_activate,
    /// ```
    ///
    /// `activate` belongs to whatever `ops` is declared as within
    /// `nft_set_type`, which lives with that struct rather than here. The
    /// outer type and the path `ops` are what this file proves; resolution
    /// turns them into the container, exactly as it does for a receiver that
    /// reads through a field.
    fn initializer_container(
        list: tree_sitter::Node,
        source: &str,
    ) -> Option<(String, Vec<String>)> {
        let mut node = list;
        let mut path: Vec<String> = Vec::new();

        while let Some(parent) = node.parent() {
            match parent.kind() {
                // `(struct net_protocol) { .handler = tcp_v4_rcv }`
                "compound_literal_expression" => {
                    let outer = parent
                        .child_by_field_name("type")
                        .and_then(|t| Self::aggregate_type_name(t, source))?;
                    path.reverse();
                    return Some((outer, path));
                }
                // `static const struct file_operations fops = { ... };`
                "init_declarator" | "declaration" => {
                    let declaration = if parent.kind() == "declaration" {
                        parent
                    } else {
                        parent.parent()?
                    };
                    let outer = declaration
                        .child_by_field_name("type")
                        .and_then(|t| Self::aggregate_type_name(t, source))?;
                    path.reverse();
                    return Some((outer, path));
                }
                // One level in: remember which field this list is filling and
                // keep looking outward for a type.
                "initializer_pair" => {
                    let designator = parent.child_by_field_name("designator")?;
                    if designator.kind() == "field_designator" {
                        path.push(source[designator.named_child(0)?.byte_range()].to_string());
                    }
                    // A subscript names a slot rather than a field, and every
                    // slot of an array has the array's element type, so
                    // passing through one leaves the path unchanged.
                    node = parent;
                }
                _ => node = parent,
            }
        }

        None
    }

    /// `struct file_operations` and a typedef name both identify a container.
    fn aggregate_type_name(type_node: tree_sitter::Node, source: &str) -> Option<String> {
        match type_node.kind() {
            "struct_specifier" | "union_specifier" => type_node
                .child_by_field_name("name")
                .map(|n| source[n.byte_range()].to_string()),
            "type_identifier" => Some(source[type_node.byte_range()].to_string()),
            "type_descriptor" => type_node
                .child_by_field_name("type")
                .and_then(|t| Self::aggregate_type_name(t, source)),
            _ => None,
        }
    }

    /// Every function-pointer variable and parameter declared in the file.
    /// A call naming one of these dispatches through a value; it is not a
    /// call to a function of that name.
    fn collect_pointer_vars(root: tree_sitter::Node, source: &str) -> Vec<PointerVar> {
        let mut vars = Vec::new();
        let mut stack = vec![root];

        while let Some(node) = stack.pop() {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                stack.push(child);
            }

            let is_parameter = match node.kind() {
                "parameter_declaration" => true,
                "declaration" => false,
                _ => continue,
            };

            let mut cursor = node.walk();
            for declarator in node.children_by_field_name("declarator", &mut cursor) {
                // `int (*fp)(void) = handler;` wraps the declarator in an
                // init_declarator that also carries the initial value.
                let (declarator, target) = if declarator.kind() == "init_declarator" {
                    let value = declarator.child_by_field_name("value").and_then(|value| {
                        (value.kind() == "identifier")
                            .then(|| source[value.byte_range()].to_string())
                    });
                    match declarator.child_by_field_name("declarator") {
                        Some(inner) => (inner, value),
                        None => continue,
                    }
                } else {
                    (declarator, None)
                };

                if !Self::declares_function_pointer(declarator) {
                    continue;
                }

                if let Some(name_node) = Self::innermost_declarator_name(declarator) {
                    let name = source[name_node.byte_range()].to_string();
                    if !name.is_empty() {
                        vars.push(PointerVar {
                            name,
                            byte_start: node.start_byte(),
                            target,
                            is_parameter,
                        });
                    }
                }
            }
        }

        vars
    }

    /// True for `int (*fp)(void)`: a function declarator whose own declarator
    /// is a parenthesised pointer, as opposed to a plain function declaration.
    fn declares_function_pointer(declarator: tree_sitter::Node) -> bool {
        let mut node = declarator;

        loop {
            if node.kind() == "function_declarator" {
                let inner = node.child_by_field_name("declarator");
                return matches!(inner.map(|i| i.kind()), Some("parenthesized_declarator"));
            }

            match node.child_by_field_name("declarator") {
                Some(inner) => node = inner,
                None => return false,
            }
        }
    }

    /// How many candidates an indirect-call macro names before the call's own
    /// arguments begin. `INDIRECT_CALL_2(f, f2, f1, ...)` names two;
    /// `INDIRECT_CALL_INET(f, f2, f1, ...)` is a two-candidate alias
    /// (include/linux/indirect_call_wrapper.h). The count has to come from the
    /// macro, not from the shape of the arguments: a call's own arguments are
    /// identifiers just as often as the candidates are.
    fn indirect_call_candidate_count(name: &str) -> Option<usize> {
        match name {
            "INDIRECT_CALL_INET" => Some(2),
            "INDIRECT_CALL_INET_1" => Some(1),
            _ => name
                .strip_prefix("INDIRECT_CALL_")
                .and_then(|suffix| suffix.parse::<usize>().ok())
                .filter(|count| *count > 0),
        }
    }

    /// One site per candidate the macro names, all pointing at the same
    /// dispatch: `INDIRECT_CALL_2(ipprot->handler, tcp_v4_rcv, udp_rcv, skb)`
    /// dispatches through `handler` and names two candidates.
    fn indirect_call_sites(
        args: tree_sitter::Node,
        source: &str,
        candidates: usize,
    ) -> Vec<RawDispatchSite> {
        let mut cursor = args.walk();
        let arguments: Vec<tree_sitter::Node> = args.named_children(&mut cursor).collect();

        let Some(dispatch) = arguments.first() else {
            return Vec::new();
        };

        // The dispatch expression is usually a member: keep the member name
        // so the site joins with everything installed in that slot.
        let member = if dispatch.kind() == "field_expression" {
            dispatch
                .child_by_field_name("field")
                .map(|field| source[field.byte_range()].to_string())
                .unwrap_or_default()
        } else {
            String::new()
        };

        let mut sites = Vec::new();
        for candidate in arguments.iter().skip(1).take(candidates) {
            if candidate.kind() != "identifier" {
                continue;
            }

            sites.push(RawDispatchSite {
                member: member.clone(),
                receiver_expr: Some(collapse_whitespace(&source[dispatch.byte_range()])),
                receiver_type: None,
                receiver_base_type: None,
                receiver_field: None,
                kind: DispatchKind::MacroDeclared,
                byte_start: candidate.start_byte(),
                line: candidate.start_position().row as u32 + 1,
                target: Some(source[candidate.byte_range()].to_string()),
            });
        }

        sites
    }

    /// `a->m()` and `a.m()` differ only in the operator between receiver and
    /// member, which the grammar leaves as an anonymous node.
    fn member_kind(member: tree_sitter::Node, source_code: &str) -> DispatchKind {
        let field = member
            .parent()
            .and_then(|field_expression| field_expression.child_by_field_name("operator"));

        match field.map(|op| &source_code[op.byte_range()]) {
            Some(".") => DispatchKind::MemberDot,
            _ => DispatchKind::MemberArrow,
        }
    }

    /// Turn one `function_name` capture into a call site: the called name and
    /// the byte range it occupies, which is what maps a call to its caller.
    fn call_site_from_capture(
        node: tree_sitter::Node,
        source_code: &str,
    ) -> Option<(String, usize, usize)> {
        let name = node.utf8_text(source_code.as_bytes()).unwrap_or("");

        // Skip empty names and obvious non-functions.
        if name.is_empty() || name.chars().all(|c| c.is_numeric()) {
            return None;
        }

        Some((name.to_string(), node.start_byte(), node.end_byte()))
    }

    /// Extract functions with pre-computed call data (avoids per-function tree traversals)
    fn extract_functions_with_calls(
        &self,
        ctx: &ExtractionContext,
        extraction: &CallExtraction,
    ) -> Result<ExtractedFunctions> {
        let mut dispatch_sites: Vec<DispatchSite> = Vec::new();
        let mut registrations: Vec<Registration> = Vec::new();
        let mut covered_sites: std::collections::HashSet<usize> = Default::default();
        let mut covered_registrations: std::collections::HashSet<usize> = Default::default();
        let mut argument_functions: Vec<ArgumentFunction> = Vec::new();
        let mut covered_argument_functions: std::collections::HashSet<usize> = Default::default();
        let mut pointer_call_sites: Vec<RawDispatchSite> = Vec::new();
        let queries = self.get_queries(ctx.language);
        let mut cursor = QueryCursor::new();
        let mut captures = cursor.captures(
            &queries.function_query,
            ctx.tree.root_node(),
            ctx.source.as_bytes(),
        );
        let mut functions = Vec::new();

        // Extract all comments once (used by extract_function_with_comments)
        let comments = self.extract_comments(ctx.tree, ctx.source, ctx.language)?;

        while let Some((m, _)) = captures.next() {
            let mut function_name = None;
            let mut return_type = None;
            let mut parameters = Vec::new();
            let mut line_start = 0;
            let mut line_end = 0;
            let mut function_start_byte = 0;
            let mut function_end_byte = 0;
            let mut body_start_byte = 0;
            let mut function_node = None;

            for capture in m.captures {
                let node = capture.node;
                let text = &ctx.source[node.byte_range()];
                let capture_name = queries.function_query.capture_names()[capture.index as usize];

                match capture_name {
                    "function_name" => {
                        function_name = Some(text.to_string());
                        line_start = node.start_position().row as u32 + 1;
                    }
                    "return_type" => {
                        return_type = Some(text.to_string());
                    }
                    "parameters" => {
                        parameters = self.parse_parameters_from_node(node, ctx.source);
                        if let Some(ref name) = function_name {
                            if name == "btrfs_lookup_inode" {
                                tracing::debug!(
                                    "{}: parameters capture matched, parsed {} params",
                                    name,
                                    parameters.len()
                                );
                            }
                        }
                    }
                    "body" => {
                        line_end = node.end_position().row as u32 + 1;
                        body_start_byte = node.start_byte();
                    }
                    "function" | "function_ptr" | "function_ptr2" => {
                        // All function types with bodies - process fully
                        function_start_byte = node.start_byte();
                        function_end_byte = node.end_byte();
                        function_node = Some(node);
                        if line_end == 0 {
                            line_end = node.end_position().row as u32 + 1;
                        }
                        if line_start == 0 {
                            line_start = node.start_position().row as u32 + 1;
                        }

                        // Extract return type from the full function text if not already captured
                        if return_type.is_none() {
                            return_type = Some(self.extract_return_type_from_function(
                                node,
                                ctx.source,
                                &function_name,
                            ));
                        }
                    }
                    "declaration" if function_start_byte == 0 => {
                        // Function declaration without body - skip call/type extraction
                        // Set minimal bounds for declaration-only functions
                        function_start_byte = node.start_byte();
                        function_end_byte = node.end_byte();
                        if line_end == 0 {
                            line_end = node.end_position().row as u32 + 1;
                        }
                        if line_start == 0 {
                            line_start = node.start_position().row as u32 + 1;
                        }
                    }
                    _ => {}
                }
            }

            if let Some(name) = function_name {
                // Track which capture patterns were matched to determine if function has body
                let mut matched_patterns = std::collections::HashSet::new();
                for capture in m.captures {
                    let capture_name =
                        queries.function_query.capture_names()[capture.index as usize];
                    matched_patterns.insert(capture_name);
                }

                // Fallback parameter extraction if TreeSitter query didn't capture them
                if parameters.is_empty() && !matched_patterns.contains("parameters") {
                    // Try to manually find parameter_list nodes in the function AST
                    for capture in m.captures {
                        let node = capture.node;
                        if self.try_extract_parameters_from_node(node, ctx.source, &mut parameters)
                        {
                            if name == "btrfs_lookup_inode" {
                                tracing::debug!(
                                    "{}: Fallback parameter extraction found {} params",
                                    name,
                                    parameters.len()
                                );
                            }
                            break;
                        }
                    }
                }

                // Determine if this function has a body based on matched patterns
                let has_body = matched_patterns.contains("body")
                    || matched_patterns.contains("function")
                    || matched_patterns.contains("function_ptr")
                    || matched_patterns.contains("function_ptr2");

                // A body the parser stopped reading early ends at the break
                // rather than at its closing brace, and the statements after
                // it are reparented to file scope where they belong to nobody.
                // Counting braces recovers the end, and the range is all the
                // attribution below needs.
                if has_body && body_start_byte > 0 {
                    if let Some(recovered) = Self::body_end_by_braces(
                        ctx.source,
                        body_start_byte,
                        function_node.map_or(ctx.source.len(), Self::next_definition_start),
                    ) {
                        if recovered > function_end_byte {
                            function_end_byte = recovered;
                            line_end = ctx.source[..recovered].lines().count() as u32;
                        }
                    }
                }

                // Extract complete function text including top comments
                let complete_body = self.extract_function_with_comments(
                    ctx.source,
                    function_start_byte,
                    function_end_byte,
                    line_start,
                    &comments,
                );

                // Only extract calls and types for functions with bodies (not just declarations)
                let (unique_calls, function_types) = if has_body {
                    // Extract calls within this function from pre-computed list (O(m) instead of O(n))
                    // Function pointers declared by this function: a call
                    // naming one of them dispatches through a value.
                    let unique_calls = Self::calls_in_range(
                        ctx,
                        extraction,
                        function_start_byte,
                        function_end_byte,
                        &mut pointer_call_sites,
                    );

                    // Extract types used by this function (parameters and return type)
                    let default_void = "void".to_string();
                    let return_type_str = return_type.as_ref().unwrap_or(&default_void);
                    let function_types = self.extract_function_types(return_type_str, &parameters);

                    (unique_calls, function_types)
                } else {
                    // For declarations only, don't extract calls or types from body
                    (Vec::new(), Vec::new())
                };

                for raw in extraction
                    .member_sites
                    .iter()
                    .chain(pointer_call_sites.iter())
                    .filter(|site| {
                        site.byte_start >= function_start_byte
                            && site.byte_start < function_end_byte
                    })
                {
                    // The function query yields several captures per function,
                    // so a site can be reached more than once; a site is one
                    // row regardless.
                    if !covered_sites.insert(raw.byte_start) {
                        continue;
                    }
                    dispatch_sites.push(raw.attribute(
                        &name,
                        &self.make_relative_path(ctx.file_path, ctx.source_root),
                        ctx.git_hash,
                    ));
                }

                for raw in extraction.registrations.iter().filter(|reg| {
                    reg.byte_start >= function_start_byte && reg.byte_start < function_end_byte
                }) {
                    if !covered_registrations.insert(raw.byte_start) {
                        continue;
                    }
                    registrations.push(raw.attribute(
                        &name,
                        &self.make_relative_path(ctx.file_path, ctx.source_root),
                        ctx.git_hash,
                    ));
                }

                for raw in extraction.argument_functions.iter().filter(|arg| {
                    arg.byte_start >= function_start_byte && arg.byte_start < function_end_byte
                }) {
                    if !covered_argument_functions.insert(raw.byte_start) {
                        continue;
                    }
                    argument_functions.push(raw.attribute(
                        &name,
                        &self.make_relative_path(ctx.file_path, ctx.source_root),
                        ctx.git_hash,
                    ));
                }

                let func = FunctionInfo {
                    name: name.clone(),
                    file_path: self.make_relative_path(ctx.file_path, ctx.source_root),
                    git_file_hash: ctx.git_hash.to_string(),
                    line_start,
                    line_end,
                    return_type: return_type.unwrap_or_else(|| "void".to_string()),
                    parameters: parameters.clone(),
                    body: complete_body,
                    calls: if unique_calls.is_empty() {
                        None
                    } else {
                        Some(unique_calls)
                    },
                    types: if function_types.is_empty() {
                        None
                    } else {
                        Some(function_types)
                    },
                    guard: function_node.and_then(|node| Self::guard_of(node, ctx.source)),
                };

                if name == "btrfs_lookup_inode" {
                    tracing::debug!(
                        "{}: FunctionInfo created with {} parameters",
                        name,
                        func.parameters.len()
                    );
                }

                functions.push(func);
            }
        }

        // Most ops tables sit at file scope and belong to no function.
        for raw in extraction
            .registrations
            .iter()
            .filter(|reg| !covered_registrations.contains(&reg.byte_start))
        {
            registrations.push(raw.attribute(
                "",
                &self.make_relative_path(ctx.file_path, ctx.source_root),
                ctx.git_hash,
            ));
        }

        for raw in extraction
            .argument_functions
            .iter()
            .filter(|arg| !covered_argument_functions.contains(&arg.byte_start))
        {
            argument_functions.push(raw.attribute(
                "",
                &self.make_relative_path(ctx.file_path, ctx.source_root),
                ctx.git_hash,
            ));
        }

        // Python module level and class bodies, C++ and Rust static
        // initializers: a dispatch that belongs to no function still happened.
        for raw in extraction
            .member_sites
            .iter()
            .filter(|site| !covered_sites.contains(&site.byte_start))
        {
            dispatch_sites.push(raw.attribute(
                "",
                &self.make_relative_path(ctx.file_path, ctx.source_root),
                ctx.git_hash,
            ));
        }

        // A macro can open a function the query cannot match, and the body
        // that follows carries every call the function makes.
        if matches!(ctx.language, Language::C) {
            for defined in Self::macro_defined_functions(ctx.tree.root_node(), ctx.source) {
                if functions
                    .iter()
                    .any(|f: &FunctionInfo| f.name == defined.name)
                {
                    continue;
                }
                let calls = Self::calls_in_range(
                    ctx,
                    extraction,
                    defined.start_byte,
                    defined.end_byte,
                    &mut pointer_call_sites,
                );

                for raw in extraction.registrations.iter().filter(|reg| {
                    reg.byte_start >= defined.start_byte && reg.byte_start < defined.end_byte
                }) {
                    if !covered_registrations.insert(raw.byte_start) {
                        continue;
                    }
                    registrations.push(raw.attribute(
                        &defined.name,
                        &self.make_relative_path(ctx.file_path, ctx.source_root),
                        ctx.git_hash,
                    ));
                }

                for raw in extraction.member_sites.iter().filter(|site| {
                    site.byte_start >= defined.start_byte && site.byte_start < defined.end_byte
                }) {
                    if !covered_sites.insert(raw.byte_start) {
                        continue;
                    }
                    dispatch_sites.push(raw.attribute(
                        &defined.name,
                        &self.make_relative_path(ctx.file_path, ctx.source_root),
                        ctx.git_hash,
                    ));
                }

                functions.push(FunctionInfo {
                    name: defined.name,
                    file_path: self.make_relative_path(ctx.file_path, ctx.source_root),
                    git_file_hash: ctx.git_hash.to_string(),
                    line_start: defined.line_start,
                    line_end: defined.line_end,
                    // What the macro expands to is not in this file, and a
                    // guessed return type would be read as a fact.
                    return_type: String::new(),
                    parameters: Vec::new(),
                    body: ctx.source[defined.start_byte..defined.end_byte].to_string(),
                    calls: (!calls.is_empty()).then_some(calls),
                    types: None,
                    guard: defined.guard.clone(),
                });
            }
        }

        Ok(ExtractedFunctions {
            functions,
            dispatch_sites,
            registrations,
            argument_functions,
        })
    }

    /// Extract macros with embedded call/type data (optimized)
    fn extract_macros_with_embedded_data(
        &self,
        tree: &Tree,
        source: &str,
        file_path: &Path,
        git_hash: &str,
        source_root: Option<&Path>,
        language: Language,
    ) -> Result<ExtractedMacros> {
        // This is the same as extract_macros but named differently for clarity
        // Macros are not as performance-critical as functions since they're fewer in number
        self.extract_macros(tree, source, file_path, git_hash, source_root, language)
    }

    /// Legacy extract_functions method for backward compatibility with older analyze methods
    fn extract_functions(
        &self,
        tree: &Tree,
        source: &str,
        file_path: &Path,
        git_hash: &str,
        source_root: Option<&Path>,
        language: Language,
    ) -> Result<Vec<FunctionInfo>> {
        // Use the optimized approach but without pre-computed calls (for compatibility)
        let extraction =
            Self::extract_all_calls_optimized(self.get_queries(language), tree, source, language)?;
        let ctx = ExtractionContext {
            tree,
            source,
            file_path,
            git_hash,
            source_root,
            language,
        };
        let ExtractedFunctions { functions, .. } =
            self.extract_functions_with_calls(&ctx, &extraction)?;

        Ok(functions)
    }

    fn extract_comments(
        &self,
        tree: &Tree,
        source: &str,
        language: Language,
    ) -> Result<Vec<(u32, u32, String)>> {
        let queries = self.get_queries(language);
        let mut cursor = QueryCursor::new();
        let mut captures =
            cursor.captures(&queries.comment_query, tree.root_node(), source.as_bytes());
        let mut comments = Vec::new();

        while let Some((m, _)) = captures.next() {
            for capture in m.captures {
                let node = capture.node;
                let text = &source[node.byte_range()];
                let start_line = node.start_position().row as u32 + 1;
                let end_line = node.end_position().row as u32 + 1;
                comments.push((start_line, end_line, text.to_string()));
            }
        }

        // Sort comments by line number
        comments.sort_by_key(|&(start_line, _, _)| start_line);
        Ok(comments)
    }

    fn extract_function_with_comments(
        &self,
        source: &str,
        function_start_byte: usize,
        function_end_byte: usize,
        function_start_line: u32,
        comments: &[(u32, u32, String)],
    ) -> String {
        let top_comments = collect_leading_comments(source, function_start_line, comments);

        // Get the complete function text (including the function body)
        let function_text = &source[function_start_byte..function_end_byte];

        // Combine top comments with function text
        let mut complete_body = String::new();

        if !top_comments.is_empty() {
            for comment in &top_comments {
                complete_body.push_str(comment);
                complete_body.push('\n');
            }
            complete_body.push('\n');
        }

        complete_body.push_str(function_text);
        complete_body
    }

    fn extract_types(
        &self,
        tree: &Tree,
        source: &str,
        file_path: &Path,
        git_hash: &str,
        source_root: Option<&Path>,
        language: Language,
    ) -> Result<Vec<TypeInfo>> {
        let queries = self.get_queries(language);
        let mut cursor = QueryCursor::new();
        let mut captures =
            cursor.captures(&queries.type_query, tree.root_node(), source.as_bytes());
        let mut types = Vec::new();

        // Extract all comments with their positions
        let comments = self.extract_comments(tree, source, language)?;

        while let Some((m, _)) = captures.next() {
            let mut type_name = None;
            let mut kind = String::new();
            let mut members = Vec::new();
            let mut line_start = 0;
            let mut type_start_byte = 0;
            let mut type_end_byte = 0;

            for capture in m.captures {
                let node = capture.node;
                let text = &source[node.byte_range()];
                let capture_name = queries.type_query.capture_names()[capture.index as usize];

                match capture_name {
                    "type_name" => {
                        type_name = Some(text.to_string());
                        line_start = node.start_position().row as u32 + 1;
                    }
                    "body" => {
                        members = self.parse_struct_members_from_node(node, source, language);
                    }
                    "struct" => {
                        kind = "struct".to_string();
                        type_start_byte = node.start_byte();
                        type_end_byte = node.end_byte();
                        if line_start == 0 {
                            line_start = node.start_position().row as u32 + 1;
                        }
                    }
                    "union" => {
                        kind = "union".to_string();
                        type_start_byte = node.start_byte();
                        type_end_byte = node.end_byte();
                        if line_start == 0 {
                            line_start = node.start_position().row as u32 + 1;
                        }
                    }
                    "enum" => {
                        kind = "enum".to_string();
                        type_start_byte = node.start_byte();
                        type_end_byte = node.end_byte();
                        if line_start == 0 {
                            line_start = node.start_position().row as u32 + 1;
                        }
                    }
                    "class" => {
                        kind = "class".to_string();
                        type_start_byte = node.start_byte();
                        type_end_byte = node.end_byte();
                        if line_start == 0 {
                            line_start = node.start_position().row as u32 + 1;
                        }
                    }
                    "opaque" => {
                        kind = "opaque".to_string();
                        type_start_byte = node.start_byte();
                        type_end_byte = node.end_byte();
                        if line_start == 0 {
                            line_start = node.start_position().row as u32 + 1;
                        }
                    }
                    "error" => {
                        kind = "error".to_string();
                        type_start_byte = node.start_byte();
                        type_end_byte = node.end_byte();
                        if line_start == 0 {
                            line_start = node.start_position().row as u32 + 1;
                        }
                    }
                    "type_alias" => {
                        kind = "type".to_string();
                        type_start_byte = node.start_byte();
                        type_end_byte = node.end_byte();
                        if line_start == 0 {
                            line_start = node.start_position().row as u32 + 1;
                        }
                    }
                    _ => {}
                }
            }

            if let Some(name) = type_name {
                // Extract complete type definition including top comments
                let complete_definition = self.extract_type_with_comments(
                    source,
                    type_start_byte,
                    type_end_byte,
                    line_start,
                    &comments,
                );

                // Extract types referenced by this type's members
                let referenced_types = self.extract_type_referenced_types(&members);

                let type_info = TypeInfo {
                    name,
                    file_path: self.make_relative_path(file_path, source_root),
                    git_file_hash: git_hash.to_string(),
                    line_start,
                    kind,
                    size: None, // Tree-sitter can't calculate size
                    members,
                    definition: complete_definition,
                    types: if referenced_types.is_empty() {
                        None
                    } else {
                        Some(referenced_types)
                    },
                };
                types.push(type_info);
            }
        }

        Ok(types)
    }

    fn extract_typedefs_as_typeinfo(
        &self,
        tree: &Tree,
        source: &str,
        file_path: &Path,
        git_hash: &str,
        source_root: Option<&Path>,
    ) -> Result<Vec<TypeInfo>> {
        // This is C-specific, so always use C queries
        let queries = &self.c_queries;
        let typedef_query = queries
            .typedef_query
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No typedef query available for this language"))?;

        let mut cursor = QueryCursor::new();
        let mut captures = cursor.captures(typedef_query, tree.root_node(), source.as_bytes());
        let mut typedef_types = Vec::new();

        while let Some((m, _)) = captures.next() {
            let mut typedef_name = None;
            let mut underlying_type = None;
            let mut line_start = 0;
            let mut typedef_start_byte = 0;
            let mut typedef_end_byte = 0;
            let mut pointer_params: Option<String> = None;

            for capture in m.captures {
                let node = capture.node;
                let text = &source[node.byte_range()];
                let capture_name = typedef_query.capture_names()[capture.index as usize];

                match capture_name {
                    "typedef_name" => {
                        typedef_name = Some(text.to_string());
                        line_start = node.start_position().row as u32 + 1;
                    }
                    "underlying_type" => {
                        underlying_type = Some(text.to_string());
                    }
                    // `typedef void (*bfa_isr_func_t)(struct bfa_s *)` aliases
                    // a function pointer, and the return type alone would read
                    // as an alias for `void`. Spell what it points at.
                    "pointer_params" => {
                        pointer_params = Some(collapse_whitespace(text));
                    }
                    "typedef" => {
                        typedef_start_byte = node.start_byte();
                        typedef_end_byte = node.end_byte();
                        if line_start == 0 {
                            line_start = node.start_position().row as u32 + 1;
                        }
                    }
                    _ => {}
                }
            }

            if let Some(name) = typedef_name {
                // Get the complete typedef definition
                let definition = &source[typedef_start_byte..typedef_end_byte];

                // What a function-pointer typedef aliases is a pointer to a
                // function, not the return type the grammar puts in `type`.
                let underlying_type = match pointer_params {
                    Some(params) => underlying_type
                        .map(|returns| format!("{returns} (*){params}"))
                        .or(Some(format!("(*){params}"))),
                    None => underlying_type,
                };

                // Create TypeInfo with kind="typedef"
                // Store underlying type info in the definition field
                let full_definition = if let Some(ref underlying) = underlying_type {
                    format!("// Underlying type: {underlying}\n{definition}")
                } else {
                    definition.to_string()
                };

                // Extract types referenced by this typedef (from the underlying type)
                let referenced_types = if let Some(ref underlying) = underlying_type {
                    if let Some(cleaned_type) = self.extract_type_name_from_declaration(underlying)
                    {
                        if !self.is_primitive_type(&cleaned_type) {
                            vec![cleaned_type]
                        } else {
                            Vec::new()
                        }
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                };

                let type_info = TypeInfo {
                    name,
                    file_path: self.make_relative_path(file_path, source_root),
                    git_file_hash: git_hash.to_string(),
                    line_start,
                    kind: "typedef".to_string(),
                    size: None,          // Typedefs don't have intrinsic size
                    members: Vec::new(), // Typedefs don't have members
                    definition: full_definition,
                    types: if referenced_types.is_empty() {
                        None
                    } else {
                        Some(referenced_types)
                    },
                };
                typedef_types.push(type_info);
            }
        }

        Ok(typedef_types)
    }

    fn extract_type_with_comments(
        &self,
        source: &str,
        type_start_byte: usize,
        type_end_byte: usize,
        type_start_line: u32,
        comments: &[(u32, u32, String)],
    ) -> String {
        let top_comments = collect_leading_comments(source, type_start_line, comments);

        // Get the complete type definition text (including any internal comments)
        let type_text = &source[type_start_byte..type_end_byte];

        // Combine top comments with type definition
        let mut complete_definition = String::new();

        if !top_comments.is_empty() {
            for comment in &top_comments {
                complete_definition.push_str(comment);
                complete_definition.push('\n');
            }
            complete_definition.push('\n');
        }

        complete_definition.push_str(type_text);
        complete_definition
    }

    fn extract_macros(
        &self,
        tree: &Tree,
        source: &str,
        file_path: &Path,
        git_hash: &str,
        source_root: Option<&Path>,
        language: Language,
    ) -> Result<ExtractedMacros> {
        // Macro bodies are re-parsed as C; one parser serves the whole file.
        let mut body_parser = tree_sitter::Parser::new();
        body_parser.set_language(&tree_sitter_c::LANGUAGE.into())?;
        let mut dispatch_sites: Vec<DispatchSite> = Vec::new();
        let mut registrations: Vec<Registration> = Vec::new();
        let mut argument_functions: Vec<ArgumentFunction> = Vec::new();
        let mut unresolved_edges: Vec<crate::types::UnresolvedEdge> = Vec::new();
        let queries = self.get_queries(language);
        let mut cursor = QueryCursor::new();
        // matches(), not captures(): a match arrives once with every capture
        // present. captures() yields the same match repeatedly as each
        // capture is found, and the early yields have no body yet.
        let mut matches = cursor.matches(&queries.macro_query, tree.root_node(), source.as_bytes());
        let mut macros = Vec::new();

        while let Some(m) = matches.next() {
            let mut body: Option<tree_sitter::Node> = None;
            let mut macro_name = None;
            let mut parameters = None;
            let mut definition = String::new();
            let mut line_start = 0;
            let mut is_function_like = false;
            let mut macro_node: Option<tree_sitter::Node> = None;

            for capture in m.captures {
                let node = capture.node;
                let text = &source[node.byte_range()];
                let capture_name = queries.macro_query.capture_names()[capture.index as usize];

                match capture_name {
                    "macro_name" => {
                        macro_name = Some(text.to_string());
                        line_start = node.start_position().row as u32 + 1;
                    }
                    "parameters" => {
                        parameters = Some(self.parse_macro_parameters(text));
                        is_function_like = true;
                    }
                    "value" => body = Some(node),
                    "macro" | "function_macro" => {
                        definition = text.to_string();
                        macro_node = Some(node);
                        if capture_name == "function_macro" {
                            is_function_like = true;
                        }
                    }
                    _ => {}
                }
            }

            if let Some(name) = macro_name {
                // Extract calls and types from macro definition
                let facts = match body {
                    Some(body) => {
                        let mut facts = Self::macro_body_calls_and_types(
                            &mut body_parser,
                            queries,
                            &source[body.byte_range()],
                        );

                        // Positions come back relative to the body; place them
                        // in the file so a fact is where the macro is.
                        let body_start = body.start_byte();
                        let body_line = body.start_position().row as u32 + 1;
                        for site in &mut facts.sites {
                            site.byte_start += body_start;
                            site.line = body_line + site.line.saturating_sub(1);
                        }
                        // A macro's own parameter is not a function.
                        // `#define hypercall_update(hc) static_call_update(hv_hypercall, hc)`
                        // installs whatever a caller passes, and `hc` names
                        // that nowhere.
                        if let Some(names) = parameters.as_ref() {
                            facts.registrations.retain(|r| !names.contains(&r.target));
                            facts
                                .argument_functions
                                .retain(|a| !names.contains(&a.target));

                            // A macro that calls one of its own parameters
                            //
                            //     #define printk_index_wrap(_p_func, fmt, ...) \
                            //             _p_func(fmt, ##__VA_ARGS__)
                            //
                            // calls whatever its caller passed. Recording
                            // `_p_func` as the callee names a function that
                            // does not exist, and recording nothing says the
                            // macro calls only what is left. The edge is real
                            // and its other end is at the invocation site.
                            let called_parameters: Vec<String> = facts
                                .calls
                                .iter()
                                .filter(|call| names.contains(call))
                                .cloned()
                                .collect();
                            facts.calls.retain(|call| !names.contains(call));
                            for parameter in called_parameters {
                                let position = names
                                    .iter()
                                    .position(|name| *name == parameter)
                                    .unwrap_or(0);
                                unresolved_edges.push(crate::types::UnresolvedEdge {
                                    name: name.clone(),
                                    direction: "out".to_string(),
                                    kind: "c:macro_parameter_call".to_string(),
                                    evidence: format!("{parameter} (parameter {position})"),
                                    locations: vec![crate::types::EdgeLocation {
                                        role: "definition".to_string(),
                                        file_path: self.make_relative_path(file_path, source_root),
                                        line: body_line,
                                    }],
                                    file_path: self.make_relative_path(file_path, source_root),
                                    git_file_hash: git_hash.to_string(),
                                    line: body_line,
                                });
                            }
                        }
                        for registration in &mut facts.registrations {
                            registration.byte_start += body_start;
                            registration.line = body_line + registration.line.saturating_sub(1);
                        }
                        for argument in &mut facts.argument_functions {
                            argument.byte_start += body_start;
                            argument.line = body_line + argument.line.saturating_sub(1);
                        }

                        facts
                    }
                    None => MacroBodyFacts::default(),
                };
                let (macro_calls, macro_types) = (facts.calls, facts.types);

                let relative_path = self.make_relative_path(file_path, source_root);
                dispatch_sites.extend(
                    facts
                        .sites
                        .iter()
                        .map(|raw| raw.attribute(&name, &relative_path, git_hash)),
                );
                registrations.extend(
                    facts
                        .registrations
                        .iter()
                        .map(|raw| raw.attribute(&name, &relative_path, git_hash)),
                );
                argument_functions.extend(
                    facts
                        .argument_functions
                        .iter()
                        .map(|raw| raw.attribute(&name, &relative_path, git_hash)),
                );

                let macro_info = FunctionInfo::from_macro(MacroParams {
                    name,
                    file_path: self.make_relative_path(file_path, source_root),
                    git_file_hash: git_hash.to_string(),
                    line_start,
                    parameters: parameters.unwrap_or_default(),
                    definition,
                    calls: if macro_calls.is_empty() {
                        None
                    } else {
                        Some(macro_calls)
                    },
                    types: if macro_types.is_empty() {
                        None
                    } else {
                        Some(macro_types)
                    },
                    guard: macro_node.and_then(|node| Self::guard_of(node, source)),
                });

                // Function-like macros, and the object-like ones needed to
                // read a declaration. `} __packed;` and `} lru_gen;` parse
                // identically — a field_declaration with a field_identifier —
                // so the only way to tell an attribute from a member name is
                // to know what the identifier expands to, and that is written
                // in another file.
                let body_text = body.map(|b| &source[b.byte_range()]).unwrap_or("");
                if is_function_like || Self::expands_to_an_attribute(body_text) {
                    macros.push(macro_info);
                }
            }
        }

        Ok((
            macros,
            dispatch_sites,
            registrations,
            argument_functions,
            unresolved_edges,
        ))
    }

    /// Whether an object-like macro body is, or leads to, a compiler attribute.
    ///
    /// Kept wide on purpose. `__packed` states it outright, while
    /// `____cacheline_aligned_in_smp` expands to `____cacheline_aligned`,
    /// which states it, so an alias has to be kept to be followed later. The
    /// alias is one identifier; a body of anything else is not on the way to
    /// an attribute and is left out, which is what keeps this from meaning
    /// "every #define in the tree" — there are six million of those.
    fn expands_to_an_attribute(body: &str) -> bool {
        let body = body.trim();

        let is_identifier = || {
            let mut chars = body.chars();
            chars
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        };

        body.contains("__attribute__") || is_identifier()
    }

    fn parse_parameters_from_node(
        &self,
        node: tree_sitter::Node,
        source: &str,
    ) -> Vec<ParameterInfo> {
        if node.kind() == "parameters" {
            return Self::parse_zig_parameters(node, source);
        }

        let mut parameters = Vec::new();

        // Walk through the parameter_list node to find parameter_declaration children
        let mut cursor = node.walk();

        if cursor.goto_first_child() {
            loop {
                let current_node = cursor.node();

                // Look for parameter_declaration nodes
                if current_node.kind() == "parameter_declaration" {
                    let param_info = self.parse_single_parameter(current_node, source);
                    if let Some(param) = param_info {
                        parameters.push(param);
                    }
                }

                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        // If no parameters found through normal parsing, try alternative approach
        if parameters.is_empty() {
            parameters = self.parse_parameters_alternative(node, source);
        }

        parameters
    }

    /// Alternative parameter parsing for complex function signatures
    fn parse_parameters_alternative(
        &self,
        node: tree_sitter::Node,
        source: &str,
    ) -> Vec<ParameterInfo> {
        let mut parameters = Vec::new();
        let text = &source[node.byte_range()];

        // Remove newlines and normalize whitespace for easier parsing
        let normalized = text.replace(['\n', '\t'], " ");
        let normalized = Regex::new(r"\s+").unwrap().replace_all(&normalized, " ");

        // Split by commas but be careful about nested parentheses
        let param_parts = self.split_parameters(&normalized);

        for part in param_parts {
            let part = part.trim();
            if part.is_empty() || part == "void" {
                continue;
            }

            // Try to extract parameter name and type
            if let Some((type_name, param_name)) = self.extract_param_type_and_name(part) {
                parameters.push(ParameterInfo {
                    name: param_name,
                    type_name,
                    type_file_path: None,
                    type_git_file_hash: None,
                });
            }
        }

        parameters
    }

    /// Split parameter list by commas, being careful about nested structures
    fn split_parameters(&self, text: &str) -> Vec<String> {
        let mut parts = Vec::new();
        let mut current = String::new();
        let mut paren_depth = 0;
        let mut in_params = false;

        for ch in text.chars() {
            match ch {
                '(' => {
                    if !in_params {
                        in_params = true;
                        continue;
                    }
                    paren_depth += 1;
                    current.push(ch);
                }
                ')' => {
                    if paren_depth == 0 {
                        if !current.trim().is_empty() {
                            parts.push(current.trim().to_string());
                        }
                        break;
                    }
                    paren_depth -= 1;
                    current.push(ch);
                }
                ',' => {
                    if paren_depth == 0 && in_params {
                        parts.push(current.trim().to_string());
                        current.clear();
                    } else {
                        current.push(ch);
                    }
                }
                _ => {
                    if in_params {
                        current.push(ch);
                    }
                }
            }
        }

        parts
    }

    /// Extract parameter type and name from a parameter string
    fn extract_param_type_and_name(&self, param: &str) -> Option<(String, String)> {
        let param = param.trim();

        // Handle function pointers and complex cases later, for now focus on simple cases
        let words: Vec<&str> = param.split_whitespace().collect();
        if words.is_empty() {
            return None;
        }

        // Last word is usually the parameter name
        let param_name = words.last()?.trim_start_matches('*').to_string();

        // Everything else is the type
        let mut type_parts = words[..words.len() - 1].to_vec();

        // Count asterisks in the parameter name position to add to type
        let asterisks = words.last()?.chars().take_while(|&c| c == '*').count();
        if asterisks > 0 {
            type_parts.extend(std::iter::repeat_n("*", asterisks));
        }

        if type_parts.is_empty() {
            return None;
        }

        let type_name = type_parts.join(" ");

        Some((type_name, param_name))
    }

    fn parse_single_parameter(
        &self,
        node: tree_sitter::Node,
        source: &str,
    ) -> Option<ParameterInfo> {
        let type_node = node.child_by_field_name("type")?;
        let base_type = Self::render_declaration_type(node, type_node, source);

        let (name, shape) = match node.child_by_field_name("declarator") {
            Some(declarator) => match Self::innermost_declarator_name(declarator) {
                Some(name_node) => (
                    source[name_node.byte_range()].to_string(),
                    Self::abstract_declarator(declarator, name_node, source),
                ),
                // An abstract declarator names nothing: `int (*)(void)`, `char *`.
                None => (
                    String::new(),
                    collapse_whitespace(&source[declarator.byte_range()]),
                ),
            },
            None => (String::new(), String::new()),
        };

        let type_name = if shape.is_empty() {
            base_type
        } else {
            format!("{base_type} {shape}")
        };

        Some(ParameterInfo {
            name,
            type_name,
            type_file_path: None, // resolved later in the type resolution phase
            type_git_file_hash: None, // resolved later in the type resolution phase
        })
    }

    /// Where the next definition begins, which bounds how far a broken body
    /// may be read. Without a bound, a body holding an unbalanced brace inside
    /// a conditional would swallow the rest of the file. `usize::MAX` means no
    /// definition follows; the caller clamps to the source's length.
    fn next_definition_start(node: tree_sitter::Node) -> usize {
        let mut sibling = node.next_sibling();
        while let Some(current) = sibling {
            if current.kind() == "function_definition" {
                return current.start_byte();
            }
            sibling = current.next_sibling();
        }
        usize::MAX
    }

    /// The closing brace of the block opening at `open`, found by counting
    /// braces rather than by asking the parser, which is the point: the parser
    /// is what gave up.
    ///
    /// A declaration built by a macro -- `TRAILING_OVERLAP(...) x = {...};` --
    /// is not parseable C, so the grammar ends the function at that line and
    /// makes the remaining statements children of the translation unit. The
    /// function then records the calls above the break and none below it, and
    /// says nothing about the difference. 1,176 statements across the tree sit
    /// at file scope this way, holding 687 call sites, 451 of them outside
    /// tools/.
    ///
    /// Strings, character literals and comments are skipped, since a brace
    /// inside any of them is text rather than structure.
    fn body_end_by_braces(source: &str, open: usize, limit: usize) -> Option<usize> {
        let bytes = source.as_bytes();
        if bytes.get(open) != Some(&b'{') {
            return None;
        }
        let end = limit.min(bytes.len());
        let mut depth = 0usize;
        let mut index = open;
        while index < end {
            match bytes[index] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(index + 1);
                    }
                }
                b'"' | b'\'' => {
                    let quote = bytes[index];
                    index += 1;
                    while index < end && bytes[index] != quote {
                        index += if bytes[index] == b'\\' { 2 } else { 1 };
                    }
                }
                b'/' if bytes.get(index + 1) == Some(&b'/') => {
                    while index < end && bytes[index] != b'\n' {
                        index += 1;
                    }
                }
                b'/' if bytes.get(index + 1) == Some(&b'*') => {
                    index += 2;
                    while index + 1 < end && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                        index += 1;
                    }
                    index += 1;
                }
                _ => {}
            }
            index += 1;
        }
        None
    }

    /// A preprocessor conditional does not nest what it holds: a definition
    /// inside `#ifdef` belongs to the scope the `#ifdef` itself sits in.
    ///
    /// Every walk over a scope has to look through these nodes, and each one
    /// that decided so for itself spelled the set differently. Two listed four
    /// kinds by name and so dropped everything under `#elifdef` and
    /// `#elifndef`; a third matched every `preproc_` node. Three copies cost
    /// 345 initcalls, 16,223 `dev_dbg` call sites and 213 syscall bodies
    /// before this was one definition.
    fn is_conditional_group(kind: &str) -> bool {
        kind.starts_with("preproc_if") || kind.starts_with("preproc_el")
    }

    /// The configuration under which a definition exists: the condition of
    /// every conditional arm enclosing it, outermost first, joined by `&&`.
    /// `None` where no conditional encloses it, which is most definitions.
    ///
    /// `include/linux/sched.h` defines `_cond_resched()` four times, one per
    /// configuration, and the index keeps whichever the collapse prefers --
    /// `return 0;` -- so every route that does something is invisible and the
    /// query reports a clean dead end. Telling the four apart starts with
    /// being able to say which is which.
    ///
    /// The arms of one conditional are not siblings in this grammar: an
    /// `#elif` and an `#else` are children of the `#if` they belong to. So an
    /// arm's condition is its own **plus the negation of the arm above it**,
    /// which is what the measurement that missed this got wrong -- requiring
    /// the chains of two definitions to diverge reported 493 collapsed names
    /// instead of 9,778, and missed `_cond_resched` itself.
    fn guard_of(node: tree_sitter::Node, source: &str) -> Option<String> {
        let mut terms: Vec<String> = Vec::new();
        let mut child = node;
        let mut parent = node.parent();

        while let Some(current) = parent {
            if let Some(condition) = Self::arm_condition(current, source) {
                // Reached through the arm below this one: the condition that
                // got us here is that this one did not hold.
                let via_alternative = current
                    .child_by_field_name("alternative")
                    .is_some_and(|alternative| alternative.id() == child.id());
                terms.push(if via_alternative {
                    Self::negated(&condition)
                } else {
                    condition
                });
            }
            child = current;
            parent = current.parent();
        }

        match terms.len() {
            0 => None,
            1 => terms.pop(),
            _ => {
                terms.reverse();
                Some(
                    terms
                        .iter()
                        .map(|term| Self::as_conjunct(term))
                        .collect::<Vec<_>>()
                        .join(" && "),
                )
            }
        }
    }

    /// A condition as one operand of `&&`, parenthesized where it would
    /// otherwise come apart.
    ///
    /// `&&` binds tighter than `||` and `?:`, so an outer arm reading
    /// `!defined(CONFIG_PREEMPTION) || defined(CONFIG_PREEMPT_DYNAMIC)`
    /// joined bare to an inner `defined(CONFIG_HAVE_PREEMPT_DYNAMIC_CALL)`
    /// reads as "not preemptible, or dynamic with the call" -- a
    /// configuration no arm of `sched.h` states.
    fn as_conjunct(condition: &str) -> String {
        let bytes = condition.as_bytes();
        let mut depth = 0usize;
        let mut splits = false;
        for (at, byte) in bytes.iter().enumerate() {
            match byte {
                b'(' => depth += 1,
                b')' => depth = depth.saturating_sub(1),
                b'?' if depth == 0 => splits = true,
                b'|' if depth == 0 && bytes.get(at + 1) == Some(&b'|') => splits = true,
                _ => {}
            }
        }
        if splits {
            format!("({condition})")
        } else {
            condition.to_string()
        }
    }

    /// The condition a conditional node asserts, as the file writes it, with
    /// line continuations and runs of whitespace collapsed so that one arm
    /// reads as one predicate. `#else` asserts nothing of its own; what it
    /// means is the negation of the arm above, which its parent supplies.
    fn arm_condition(node: tree_sitter::Node, source: &str) -> Option<String> {
        let text_of = |field: &str| {
            node.child_by_field_name(field)
                .and_then(|child| child.utf8_text(source.as_bytes()).ok())
                .map(Self::one_line)
        };

        match node.kind() {
            "preproc_if" | "preproc_elif" => text_of("condition"),
            "preproc_ifdef" | "preproc_elifdef" => {
                let name = text_of("name")?;
                // One node kind spells both `#ifdef` and `#ifndef`; the
                // directive itself is the only thing that says which.
                let negated = node
                    .child(0)
                    .and_then(|directive| directive.utf8_text(source.as_bytes()).ok())
                    .is_some_and(|directive| directive.ends_with("ndef"));
                Some(if negated {
                    format!("!defined({name})")
                } else {
                    format!("defined({name})")
                })
            }
            _ => None,
        }
    }

    /// A condition with its sense reversed, spelled the way the file would.
    ///
    /// Parentheses are not decoration here: `defined(A) || defined(B)` also
    /// begins with `defined(` and ends with `)`, so reversing it by writing a
    /// `!` in front turns "neither A nor B" into "not A, or B" -- a different
    /// configuration, silently.
    fn negated(condition: &str) -> String {
        if let Some(inner) = condition.strip_prefix('!') {
            if Self::binds_tighter_than_not(inner) {
                return inner.to_string();
            }
            if let Some(unwrapped) = inner.strip_prefix('(').and_then(|r| r.strip_suffix(')')) {
                return unwrapped.to_string();
            }
        }
        if Self::binds_tighter_than_not(condition) {
            format!("!{condition}")
        } else {
            format!("!({condition})")
        }
    }

    /// Whether a condition is one term -- `defined(CONFIG_X)` or a bare name
    /// -- so that a `!` in front of it reverses the whole of it.
    fn binds_tighter_than_not(condition: &str) -> bool {
        let name = condition
            .strip_prefix("defined(")
            .and_then(|rest| rest.strip_suffix(')'))
            .unwrap_or(condition);
        !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_')
    }

    /// One predicate on one line: continuations and runs of whitespace
    /// become single spaces, so the same arm reads the same however the file
    /// wraps it.
    fn one_line(text: &str) -> String {
        text.split_whitespace()
            .filter(|piece| *piece != "\\")
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Whether the node sits at file scope, reading through conditionals.
    fn at_file_scope(node: tree_sitter::Node) -> bool {
        let mut parent = node.parent();
        while let Some(current) = parent {
            if !Self::is_conditional_group(current.kind()) {
                return current.kind() == "translation_unit";
            }
            parent = current.parent();
        }
        false
    }

    /// Every run of siblings at file scope: the translation unit's children,
    /// and the children of each conditional it holds, recursively.
    ///
    /// A pair of siblings is what identifies a body a macro opens, and a
    /// conditional makes the pair siblings of each other inside it rather than
    /// of the file, so the runs have to be kept apart rather than flattened.
    fn file_scope_sequences<'tree>(
        root: tree_sitter::Node<'tree>,
    ) -> Vec<Vec<tree_sitter::Node<'tree>>> {
        let mut groups = vec![root];
        let mut sequences: Vec<Vec<tree_sitter::Node>> = Vec::new();
        while let Some(parent) = groups.pop() {
            let mut cursor = parent.walk();
            let children: Vec<tree_sitter::Node> = parent.children(&mut cursor).collect();
            for child in &children {
                if Self::is_conditional_group(child.kind()) {
                    groups.push(*child);
                }
            }
            sequences.push(children);
        }
        sequences
    }

    /// The field declarations of a struct or union body, including the ones a
    /// preprocessor conditional holds.
    ///
    /// ```text
    /// struct task_struct {
    ///         int always;
    /// #ifdef CONFIG_SMP
    ///         int on_cpu;
    /// #endif
    /// ```
    ///
    /// The grammar puts that declaration inside a `preproc_ifdef` node rather
    /// than directly in the body, so reading only the body's own children
    /// drops every member a config option guards. task_struct declares 263
    /// members and 140 were recorded.
    ///
    /// Every arm is read. Which one a build takes is not knowable from the
    /// source, and a member declared in either is one the type can have.
    fn field_declarations<'tree>(body: tree_sitter::Node<'tree>) -> Vec<tree_sitter::Node<'tree>> {
        let mut declarations = Vec::new();
        let mut stack = vec![body];

        while let Some(node) = stack.pop() {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                match child.kind() {
                    "field_declaration" => declarations.push(child),
                    kind if Self::is_conditional_group(kind) => stack.push(child),
                    _ => {}
                }
            }
        }

        // A stack reverses each level; the source order is what a reader of
        // the type expects, and what an offset comparison needs.
        declarations.sort_by_key(|node| node.start_byte());
        declarations
    }

    fn parse_zig_parameters(node: tree_sitter::Node, source: &str) -> Vec<ParameterInfo> {
        let mut parameters = Vec::new();
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() != "parameter" {
                continue;
            }
            let name = child
                .child_by_field_name("name")
                .map(|n| source[n.byte_range()].to_string())
                .unwrap_or_default();
            let type_name = child
                .child_by_field_name("type")
                .map(|n| collapse_whitespace(&source[n.byte_range()]))
                .unwrap_or_default();
            if name.is_empty() && type_name.is_empty() {
                continue;
            }
            parameters.push(ParameterInfo {
                name,
                type_name,
                type_file_path: None,
                type_git_file_hash: None,
            });
        }
        parameters
    }

    fn parse_zig_container_fields(body_node: tree_sitter::Node, source: &str) -> Vec<FieldInfo> {
        let mut members = Vec::new();
        let mut cursor = body_node.walk();
        for child in body_node.children(&mut cursor) {
            if child.kind() != "container_field" {
                continue;
            }
            let name_node = child.child_by_field_name("name");
            let type_node = child.child_by_field_name("type");
            let (name, type_name) = match (name_node, type_node) {
                (Some(name), Some(ty)) => (
                    source[name.byte_range()].to_string(),
                    collapse_whitespace(&source[ty.byte_range()]),
                ),
                (Some(name), None) => (source[name.byte_range()].to_string(), String::new()),
                (None, Some(ty)) => (String::new(), collapse_whitespace(&source[ty.byte_range()])),
                (None, None) => continue,
            };
            if name.is_empty() && type_name.is_empty() {
                continue;
            }
            members.push(FieldInfo {
                name,
                type_name,
                offset: None,
            });
        }
        members
    }

    /// Fields of a Rust struct.
    ///
    /// The type is reduced to the aggregate it names, so that a chain like
    /// `self.inner.write()` can be walked: what a member is declared as has
    /// to match what a receiver is typed as, and receivers are recorded
    /// without their references or generic arguments.
    fn parse_rust_container_fields(body_node: tree_sitter::Node, source: &str) -> Vec<FieldInfo> {
        let mut members = Vec::new();
        let mut cursor = body_node.walk();
        for child in body_node.children(&mut cursor) {
            if child.kind() != "field_declaration" {
                continue;
            }
            let (Some(name), Some(type_node)) = (
                child.child_by_field_name("name"),
                child.child_by_field_name("type"),
            ) else {
                continue;
            };
            members.push(FieldInfo {
                name: source[name.byte_range()].to_string(),
                type_name: Self::rust_type_name(type_node, source)
                    .unwrap_or_else(|| collapse_whitespace(&source[type_node.byte_range()])),
                offset: None,
            });
        }
        members
    }

    fn parse_zig_error_members(body_node: tree_sitter::Node, source: &str) -> Vec<FieldInfo> {
        let mut members = Vec::new();
        let mut cursor = body_node.walk();
        for child in body_node.children(&mut cursor) {
            if child.kind() != "identifier" {
                continue;
            }
            let name = source[child.byte_range()].to_string();
            if name.is_empty() {
                continue;
            }
            members.push(FieldInfo {
                name,
                type_name: String::new(),
                offset: None,
            });
        }
        members
    }

    fn parse_struct_members_from_node(
        &self,
        body_node: tree_sitter::Node,
        source: &str,
        language: Language,
    ) -> Vec<FieldInfo> {
        match body_node.kind() {
            "error_set_declaration" => return Self::parse_zig_error_members(body_node, source),
            "struct_declaration" | "enum_declaration" | "union_declaration"
            | "opaque_declaration" => {
                return Self::parse_zig_container_fields(body_node, source);
            }
            // C names its struct body the same thing, and its fields carry a
            // declarator rather than a name.
            "field_declaration_list" if matches!(language, Language::Rust) => {
                return Self::parse_rust_container_fields(body_node, source);
            }
            _ => {}
        }

        let mut members = Vec::new();

        for declaration in Self::field_declarations(body_node) {
            if let Some(field_info) = self.parse_field_declaration_node(declaration, source, "") {
                members.extend(field_info);
            }
        }

        // Fallback to string-based parsing if Tree-sitter parsing didn't find anything
        if members.is_empty() {
            members = self.parse_struct_members_string_fallback(&source[body_node.byte_range()]);
        }

        members
    }

    fn parse_field_declaration_node(
        &self,
        field_decl_node: tree_sitter::Node,
        source: &str,
        prefix: &str,
    ) -> Option<Vec<FieldInfo>> {
        let type_node = field_decl_node.child_by_field_name("type")?;
        let base_type = Self::render_declaration_type(field_decl_node, type_node, source);
        let inline_body = Self::inline_aggregate_body(type_node);

        let mut fields = Vec::new();
        let mut cursor = field_decl_node.walk();
        let declarators: Vec<tree_sitter::Node> = field_decl_node
            .children_by_field_name("declarator", &mut cursor)
            .collect();

        // An anonymous member declares no name of its own: C makes its members
        // members of the enclosing struct, reachable as `parent->inner`.
        if declarators.is_empty() {
            let body = inline_body?;
            return Some(self.parse_struct_members_from_node_prefixed(body, source, prefix));
        }

        for declarator in declarators {
            let Some(name_node) = Self::innermost_declarator_name(declarator) else {
                continue;
            };
            let name = source[name_node.byte_range()].to_string();
            // Error recovery can leave a zero-width identifier behind.
            if name.is_empty() {
                continue;
            }
            let shape = Self::abstract_declarator(declarator, name_node, source);

            let type_name = if shape.is_empty() {
                base_type.clone()
            } else {
                format!("{base_type} {shape}")
            };

            fields.push(FieldInfo {
                name: format!("{prefix}{name}"),
                type_name,
                offset: None,
            });

            // An inline aggregate has no name to look its members up by, so
            // report them here, qualified by the member that holds them.
            if let Some(body) = inline_body {
                let nested_prefix = format!("{prefix}{name}.");
                fields.extend(self.parse_struct_members_from_node_prefixed(
                    body,
                    source,
                    &nested_prefix,
                ));
            }
        }

        if fields.is_empty() {
            None
        } else {
            Some(fields)
        }
    }

    /// The body of an inline `struct`/`union`/`enum` definition, if the type is
    /// spelled out here rather than referred to by name.
    fn inline_aggregate_body(type_node: tree_sitter::Node) -> Option<tree_sitter::Node> {
        match type_node.kind() {
            "struct_specifier" | "union_specifier" => type_node.child_by_field_name("body"),
            _ => None,
        }
    }

    fn parse_struct_members_from_node_prefixed(
        &self,
        body_node: tree_sitter::Node,
        source: &str,
        prefix: &str,
    ) -> Vec<FieldInfo> {
        let mut members = Vec::new();
        for declaration in Self::field_declarations(body_node) {
            if let Some(fields) = self.parse_field_declaration_node(declaration, source, prefix) {
                members.extend(fields);
            }
        }

        members
    }

    /// Render a declaration's type, including qualifiers that sit beside the
    /// type node rather than inside it (`const char *x` keeps its `const`).
    fn render_declaration_type(
        decl_node: tree_sitter::Node,
        type_node: tree_sitter::Node,
        source: &str,
    ) -> String {
        let mut parts = Vec::new();
        let mut cursor = decl_node.walk();
        for child in decl_node.children(&mut cursor) {
            if child.start_byte() >= type_node.start_byte() {
                break;
            }
            if matches!(child.kind(), "type_qualifier" | "storage_class_specifier") {
                parts.push(collapse_whitespace(&source[child.byte_range()]));
            }
        }
        parts.push(Self::render_type_node(type_node, source));

        parts.join(" ")
    }

    /// Render the type of a declaration, keeping an inline aggregate short.
    fn render_type_node(type_node: tree_sitter::Node, source: &str) -> String {
        let keyword = match type_node.kind() {
            "struct_specifier" => Some("struct"),
            "union_specifier" => Some("union"),
            "enum_specifier" => Some("enum"),
            _ => None,
        };

        if let Some(keyword) = keyword {
            if type_node.child_by_field_name("body").is_some() {
                return match type_node.child_by_field_name("name") {
                    Some(name) => format!("{keyword} {} {{...}}", &source[name.byte_range()]),
                    None => format!("{keyword} {{...}}"),
                };
            }
        }

        collapse_whitespace(&source[type_node.byte_range()])
    }

    /// Follow a declarator down to the identifier it declares, without
    /// descending into a function declarator's parameters.
    fn innermost_declarator_name(declarator: tree_sitter::Node) -> Option<tree_sitter::Node> {
        let mut node = declarator;

        loop {
            match node.kind() {
                "field_identifier" | "identifier" | "type_identifier" => return Some(node),
                "parenthesized_declarator" => node = node.named_child(0)?,
                _ => node = node.child_by_field_name("declarator")?,
            }
        }
    }

    /// The declarator with its identifier removed: `(*read)(struct file *f)`
    /// becomes `(*)(struct file *f)`, `*next` becomes `*`, `x[4]` becomes `[4]`.
    fn abstract_declarator(
        declarator: tree_sitter::Node,
        name_node: tree_sitter::Node,
        source: &str,
    ) -> String {
        let text = &source[declarator.byte_range()];
        let start = name_node.start_byte() - declarator.start_byte();
        let end = name_node.end_byte() - declarator.start_byte();

        collapse_whitespace(&format!("{}{}", &text[..start], &text[end..]))
    }

    fn parse_single_field_declaration_line(&self, line: &str) -> Vec<FieldInfo> {
        let mut fields = Vec::new();

        // Handle complex field declarations including pointers, arrays, and bit fields
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let last_part = parts.last().unwrap_or(&"");

            // Extract field name and modifiers from the last part
            let (field_name, field_modifiers) = self.extract_field_name_and_modifiers(last_part);

            if !field_name.is_empty() {
                // Build complete type string
                let base_type = parts[..parts.len() - 1].join(" ");
                let complete_type = if field_modifiers.is_empty() {
                    base_type
                } else {
                    format!("{base_type} {field_modifiers}")
                };

                fields.push(FieldInfo {
                    name: field_name,
                    type_name: complete_type,
                    offset: None,
                });
            }
        }

        fields
    }

    fn extract_field_name_and_modifiers(&self, declarator: &str) -> (String, String) {
        // Handle various patterns:
        // *name -> name, with pointer in modifiers
        // name[SIZE] -> name, with array in modifiers
        // name:bits -> name, with bit field info
        // *name[SIZE] -> name, with pointer and array

        let mut name = declarator.to_string();
        let mut modifiers = Vec::new();

        // Handle bit fields (name:bits)
        if let Some(colon_pos) = name.find(':') {
            let bits = name[colon_pos..].to_string();
            name = name[..colon_pos].to_string();
            modifiers.push(bits);
        }

        // Handle arrays (name[size] or name[])
        if let Some(bracket_start) = name.find('[') {
            let array_part = name[bracket_start..].to_string();
            name = name[..bracket_start].to_string();
            modifiers.insert(0, array_part); // Insert at beginning to maintain order
        }

        // Handle pointers (*name, **name, etc.)
        let mut pointer_count = 0;
        while name.starts_with('*') {
            pointer_count += 1;
            name = name[1..].to_string();
        }
        if pointer_count > 0 {
            modifiers.insert(0, "*".repeat(pointer_count));
        }

        // Clean up the name
        let clean_name = name.trim().to_string();

        // Only return valid identifiers
        if clean_name.chars().all(|c| c.is_alphanumeric() || c == '_') && !clean_name.is_empty() {
            (clean_name, modifiers.join(""))
        } else {
            (String::new(), String::new())
        }
    }

    fn parse_struct_members_string_fallback(&self, body_text: &str) -> Vec<FieldInfo> {
        let mut members = Vec::new();

        // Basic field parsing - look for declarations ending with semicolon
        for line in body_text.lines() {
            let line = line.trim();
            if line.ends_with(';')
                && !line.is_empty()
                && !line.starts_with("//")
                && !line.starts_with("/*")
            {
                let line = line.trim_end_matches(';').trim();

                // Skip empty lines and comments
                if line.is_empty() {
                    continue;
                }

                // Use the improved parsing logic
                let mut parsed_fields = self.parse_single_field_declaration_line(line);
                members.append(&mut parsed_fields);
            }
        }

        members
    }

    /// Extract return type from the full function definition text
    fn extract_return_type_from_function(
        &self,
        function_node: tree_sitter::Node,
        source: &str,
        function_name: &Option<String>,
    ) -> String {
        let function_text = &source[function_node.byte_range()];

        // Find the function name position to know where the return type ends
        if let Some(name) = function_name {
            if let Some(name_pos) = function_text.find(name) {
                let return_type_text = &function_text[..name_pos].trim();

                // Extract everything before the function name as the return type
                // Remove common storage class and function specifiers that aren't part of the return type
                let mut parts: Vec<&str> = return_type_text.split_whitespace().collect();

                // Remove storage class specifiers and function specifiers, but keep type-related keywords
                parts.retain(|&part| {
                    !matches!(part, "static" | "extern" | "inline" | "auto" | "register")
                });

                let return_type = parts.join(" ");

                if return_type.is_empty() {
                    "void".to_string()
                } else {
                    return_type
                }
            } else {
                "void".to_string()
            }
        } else {
            "void".to_string()
        }
    }

    fn parse_macro_parameters(&self, params_text: &str) -> Vec<String> {
        let cleaned = params_text
            .trim_start_matches('(')
            .trim_end_matches(')')
            .trim();
        if cleaned.is_empty() {
            return Vec::new();
        }

        cleaned
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()
    }

    // REMOVED: extract_call_relationships method
    // This method was removed because call relationships are now embedded directly
    // in function JSON columns during parsing, making separate call relationship
    // extraction unnecessary. The optimized approach stores calls as JSON arrays
    // within each FunctionInfo record rather than maintaining separate call tables.

    /// Analyze file with type resolution using a global type registry
    /// Resolve types for already-analyzed results without re-parsing the file
    pub fn resolve_types_for_analysis(
        &self,
        mut functions: Vec<FunctionInfo>,
        types: &[TypeInfo],
        global_types: &GlobalTypeRegistry,
    ) -> Vec<FunctionInfo> {
        // Build local type map from current file - typedefs are now included in types with kind="typedef"
        let mut local_types = HashMap::new();
        for type_info in types {
            local_types.insert(
                type_info.name.clone(),
                (type_info.file_path.clone(), type_info.git_file_hash.clone()),
            );
        }

        // Resolve function parameter types
        for function in &mut functions {
            function.parameters =
                self.resolve_parameter_types(&function.parameters, &local_types, global_types);
        }

        functions
    }

    pub fn analyze_file_with_type_resolution(
        &mut self,
        file_path: &Path,
        source_root: Option<&Path>,
        global_types: &GlobalTypeRegistry,
    ) -> Result<(Vec<FunctionInfo>, Vec<TypeInfo>, Vec<FunctionInfo>)> {
        // First do normal analysis
        let (mut functions, types, macros) =
            self.analyze_file_with_source_root(file_path, source_root)?;

        // Resolve types for functions - typedefs are now included in types
        functions = self.resolve_types_for_analysis(functions, &types, global_types);

        Ok((functions, types, macros))
    }

    /// Resolve parameter types using local and global type registries
    fn resolve_parameter_types(
        &self,
        parameters: &[ParameterInfo],
        local_types: &HashMap<String, (String, String)>,
        global_types: &GlobalTypeRegistry,
    ) -> Vec<ParameterInfo> {
        parameters
            .iter()
            .map(|param| {
                let (type_file_path, type_git_file_hash) =
                    self.lookup_parameter_type(&param.type_name, local_types, global_types);

                ParameterInfo {
                    name: param.name.clone(),
                    type_name: param.type_name.clone(),
                    type_file_path,
                    type_git_file_hash,
                }
            })
            .collect()
    }

    /// Look up type information for a parameter type name
    fn lookup_parameter_type(
        &self,
        type_name: &str,
        local_types: &HashMap<String, (String, String)>,
        global_types: &GlobalTypeRegistry,
    ) -> (Option<String>, Option<String>) {
        // Clean the type name by removing decorations
        let cleaned_name = self.clean_parameter_type_name(type_name);

        // First check local types (same file)
        if let Some((file_path, hash)) = local_types.get(&cleaned_name) {
            return (Some(file_path.clone()), Some(hash.clone()));
        }

        // Then check global types (other files)
        if let Some((file_path, hash)) = global_types.lookup_type(&cleaned_name) {
            return (Some(file_path), Some(hash));
        }

        // Check for common variations
        for variant in self.generate_type_name_variants(&cleaned_name) {
            if let Some((file_path, hash)) = local_types.get(&variant) {
                return (Some(file_path.clone()), Some(hash.clone()));
            }
            if let Some((file_path, hash)) = global_types.lookup_type(&variant) {
                return (Some(file_path), Some(hash));
            }
        }

        // Type not found - could be built-in type or external
        (None, None)
    }

    /// Clean type name for parameter lookup
    fn clean_parameter_type_name(&self, type_name: &str) -> String {
        let cleaned = type_name
            .trim()
            .replace("const ", "")
            .replace("volatile ", "")
            .replace("static ", "")
            .replace("extern ", "")
            .replace("inline ", "")
            .replace(" *", "")
            .replace("*", "")
            .replace(" &", "")
            .replace("&", "")
            .trim()
            .to_string();

        // Handle array syntax like "char[256]" or "unsigned long [ 2 ]"
        if let Some(bracket_pos) = cleaned.find('[') {
            cleaned[..bracket_pos].trim().to_string()
        } else {
            cleaned
        }
    }

    /// Generate common variations of type names for lookup
    fn generate_type_name_variants(&self, base_name: &str) -> Vec<String> {
        let mut variants = Vec::new();

        // Add struct prefix if not present
        if !base_name.starts_with("struct ")
            && !base_name.starts_with("union ")
            && !base_name.starts_with("enum ")
        {
            variants.push(format!("struct {base_name}"));
            variants.push(format!("union {base_name}"));
            variants.push(format!("enum {base_name}"));
        }

        // Remove struct/union/enum prefix if present
        if let Some(stripped) = base_name.strip_prefix("struct ") {
            variants.push(stripped.to_string());
        } else if let Some(stripped) = base_name.strip_prefix("union ") {
            variants.push(stripped.to_string());
        } else if let Some(stripped) = base_name.strip_prefix("enum ") {
            variants.push(stripped.to_string());
        }

        variants
    }

    /// Build a local type map from current file's types (typedefs are included as types with kind="typedef")
    pub fn build_local_type_map(&self, types: &[TypeInfo]) -> HashMap<String, (String, String)> {
        let mut local_types = HashMap::new();

        for type_info in types {
            local_types.insert(
                type_info.name.clone(),
                (type_info.file_path.clone(), type_info.git_file_hash.clone()),
            );
        }

        local_types
    }

    /// Extract types used by a function (parameters and return type)
    fn extract_function_types(
        &self,
        return_type: &str,
        parameters: &[ParameterInfo],
    ) -> Vec<String> {
        let mut types = Vec::new();

        // Extract from return type
        if let Some(cleaned_type) = self.extract_type_name_from_declaration(return_type) {
            if !self.is_primitive_type(&cleaned_type) {
                types.push(cleaned_type);
            }
        }

        // Extract from parameters
        for param in parameters {
            if let Some(cleaned_type) = self.extract_type_name_from_declaration(&param.type_name) {
                if !self.is_primitive_type(&cleaned_type) {
                    types.push(cleaned_type);
                }
            }
        }

        // Remove duplicates and sort
        types.sort();
        types.dedup();
        types
    }

    /// Extract types referenced by a type's members
    fn extract_type_referenced_types(&self, members: &[FieldInfo]) -> Vec<String> {
        let mut types = Vec::new();

        for member in members {
            if let Some(cleaned_type) = self.extract_type_name_from_declaration(&member.type_name) {
                if !self.is_primitive_type(&cleaned_type) {
                    types.push(cleaned_type);
                }
            }
        }

        // Remove duplicates and sort
        types.sort();
        types.dedup();
        types
    }

    /// Extract clean type name from a type declaration (removes pointers, const, etc.)
    fn extract_type_name_from_declaration(&self, type_declaration: &str) -> Option<String> {
        let cleaned = type_declaration
            .trim()
            .replace("const ", "")
            .replace("volatile ", "")
            .replace("static ", "")
            .replace("extern ", "")
            .replace("inline ", "")
            .replace(" *", "")
            .replace("*", "")
            .replace(" &", "")
            .replace("&", "");

        // Handle array syntax like "char[256]" or "unsigned long[2]"
        let array_cleaned = if let Some(bracket_pos) = cleaned.find('[') {
            cleaned[..bracket_pos].trim().to_string()
        } else {
            cleaned
        };

        let words: Vec<&str> = array_cleaned.split_whitespace().collect();
        if words.is_empty() {
            return None;
        }

        // Handle struct/union/enum types
        if words[0] == "struct" || words[0] == "union" || words[0] == "enum" {
            if words.len() >= 2 {
                Some(words[1].to_string())
            } else {
                None
            }
        } else {
            // Filter out compiler directives and return the main type
            let filtered_words: Vec<&str> = words
                .into_iter()
                .filter(|word| !word.starts_with("__"))
                .collect();

            if filtered_words.is_empty() {
                None
            } else {
                Some(filtered_words.join(" "))
            }
        }
    }

    /// Check if a type name is a primitive type
    fn is_primitive_type(&self, type_name: &str) -> bool {
        matches!(
            type_name,
            "void"
                | "char"
                | "short"
                | "int"
                | "long"
                | "long long"
                | "unsigned"
                | "unsigned long long"
                | "float"
                | "double"
                | "int8_t"
                | "int16_t"
                | "int32_t"
                | "int64_t"
                | "uint8_t"
                | "uint16_t"
                | "uint32_t"
                | "uint64_t"
                | "u8"
                | "u16"
                | "u32"
                | "u64"
                | "s8"
                | "s16"
                | "s32"
                | "s64"
                | "__u8"
                | "__u16"
                | "__u32"
                | "__u64"
                | "__s8"
                | "__s16"
                | "__s32"
                | "__s64"
                | "u_int"
                | "uint"
                | "U32"
                | "size_t"
                | "ssize_t"
                | "ptrdiff_t"
                | "intptr_t"
                | "uintptr_t"
                | "off_t"
                | "loff_t"
                | "bool"
                | "_Bool"
        )
    }

    /// Parse a macro body as C and report what it calls and which types it
    /// names.
    ///
    /// A `#define` body is not a translation unit — it can be an expression,
    /// a statement, a declaration or an initializer — so it is tried in each
    /// of those contexts and the cleanest parse wins.
    fn macro_body_calls_and_types(
        parser: &mut tree_sitter::Parser,
        queries: &LanguageQueries,
        body: &str,
    ) -> MacroBodyFacts {
        let body = body.trim();
        if body.is_empty() {
            return MacroBodyFacts::default();
        }

        let Some((tree, wrapped, prefix_len)) = Self::parse_macro_body(parser, body) else {
            return MacroBodyFacts {
                calls: Self::scan_macro_body_calls(body),
                ..Default::default()
            };
        };

        let mut calls = Vec::new();
        let mut any_call = false;
        let mut cursor = QueryCursor::new();
        let mut captures =
            cursor.captures(&queries.call_query, tree.root_node(), wrapped.as_bytes());
        while let Some((call_match, _)) = captures.next() {
            for capture in call_match.captures {
                match queries.call_query.capture_names()[capture.index as usize] {
                    "function_name" => {
                        let name = &wrapped[capture.node.byte_range()];
                        if !name.is_empty() {
                            calls.push(name.to_string());
                        }
                    }
                    // A call that names no function is still a call, and
                    // knowing one is there is what keeps the scan below off.
                    "call" | "method_call" | "deref_call" | "macro_call" => any_call = true,
                    _ => {}
                }
            }
        }

        let mut types = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            let mut walker = node.walk();
            for child in node.children(&mut walker) {
                stack.push(child);
            }

            match node.kind() {
                "struct_specifier" | "union_specifier" | "enum_specifier" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        types.push(wrapped[name.byte_range()].to_string());
                    }
                }
                "type_identifier" => types.push(wrapped[node.byte_range()].to_string()),
                _ => {}
            }
        }

        // Plenty of bodies are fragments that are not valid C on their own —
        // `"prefix: " fmt` and friends — and parse into something with no call
        // in it. Scanning finds the call there; the parse is what keeps the
        // scan from reading grouping parens as calls in the ordinary case.
        //
        // A body whose only call goes through a member has no function to
        // name, and scanning it reads the member as one: `(p)->func->target(p)`
        // is not a call to `target`. The dispatch is recorded as a site.
        if calls.is_empty() && !any_call {
            calls = Self::scan_macro_body_calls(body);
        }

        // The wrapper introduces names of its own; they are not the macro's.
        calls.retain(|name| !name.starts_with("__semcode_"));
        types.retain(|name| !name.starts_with("__semcode_"));

        calls.sort();
        calls.dedup();
        types.sort();
        types.dedup();

        // A macro body dispatches like any other code: `((o)->run())` is a
        // call through a member wherever it is written. Positions are in the
        // wrapped text, and the caller maps them back to the file.
        let mut sites =
            match Self::extract_all_calls_optimized(queries, &tree, &wrapped, Language::C) {
                Ok(extraction) => extraction.member_sites,
                Err(_) => Vec::new(),
            };

        // A macro body can install a function as well as call one, when it
        // declares the thing it initialises:
        //
        //     #define DEFINE_OPS(name, fn) struct ops name = { .run = fn }
        //
        // A bare `{ .run = fn }` states no type — the wrapper's type is the
        // wrapper's, not the macro's — so it registers nothing, as elsewhere.
        let mut registrations = Self::collect_registrations(tree.root_node(), &wrapped);
        registrations.extend(Self::collect_assignments(tree.root_node(), &wrapped));
        registrations.retain(|r| !r.container_type.starts_with("__semcode_"));

        // The wrapper sits on one line before the body, so a position maps
        // back by subtracting its length; a body spanning several lines keeps
        // its own line offsets.
        sites.retain(|site| site.byte_start >= prefix_len);
        for site in &mut sites {
            site.byte_start -= prefix_len;
        }
        registrations.retain(|r| r.byte_start >= prefix_len);
        for registration in &mut registrations {
            registration.byte_start -= prefix_len;
        }

        // A macro body hands a function over as well as calling one:
        //
        //     #define printk(fmt, ...) printk_index_wrap(_printk, fmt, ...)
        //
        // Reading the handover only outside macros is why `callers _printk`
        // named four functions in a tree where 5,729 call it.
        let mut argument_functions = Self::collect_argument_functions(tree.root_node(), &wrapped);
        argument_functions.retain(|argument| {
            !argument.callee.starts_with("__semcode_")
                && !argument.target.starts_with("__semcode_")
                && argument.byte_start >= prefix_len
        });
        for argument in &mut argument_functions {
            argument.byte_start -= prefix_len;
        }

        MacroBodyFacts {
            calls,
            types,
            sites,
            registrations,
            argument_functions,
        }
    }

    /// Parse a macro body in whichever context it fits: the tree, the text it
    /// was parsed in, and how far the wrapper pushed the body along, so node
    /// ranges can be read back into the file.
    ///
    /// A body that does not parse cleanly is used anyway, structure included.
    /// That is deliberate and measured: harvesting sites and registrations
    /// only from an error-free parse costs 819 registrations and 134 dispatch
    /// sites on a Linux tree, to remove 29 wrong rows. A body full of token
    /// pasting never parses cleanly, and its `.read = seq_read` says what it
    /// installs regardless.
    ///
    /// What error recovery does invent is filtered where it can be recognised
    /// rather than by refusing the tree: a member named after a keyword and a
    /// member call with no receiver are both impossible in C, and both are
    /// dropped. Between them they cover the assembler bodies, which is where
    /// invented structure was actually coming from.
    fn parse_macro_body(
        parser: &mut tree_sitter::Parser,
        body: &str,
    ) -> Option<(Tree, String, usize)> {
        const CONTEXTS: [(&str, &str); 3] = [
            ("void __semcode_body(void) { ", "; }"),
            ("", ""),
            ("struct __semcode_s __semcode_v = ", ";"),
        ];

        let mut best: Option<(Tree, String, usize, usize)> = None;

        for (prefix, suffix) in CONTEXTS {
            let wrapped = format!("{prefix}{body}{suffix}");
            let Some(tree) = parser.parse(&wrapped, None) else {
                continue;
            };

            let errors = Self::count_parse_errors(tree.root_node());
            if errors == 0 {
                return Some((tree, wrapped, prefix.len()));
            }

            match &best {
                Some((_, _, _, fewest)) if *fewest <= errors => {}
                _ => best = Some((tree, wrapped, prefix.len(), errors)),
            }
        }

        best.map(|(tree, wrapped, prefix_len, _)| (tree, wrapped, prefix_len))
    }

    fn count_parse_errors(node: tree_sitter::Node) -> usize {
        if !node.has_error() {
            return 0;
        }

        let mut errors = 0;
        let mut stack = vec![node];
        while let Some(node) = stack.pop() {
            if node.is_error() || node.is_missing() {
                errors += 1;
            }
            let mut walker = node.walk();
            for child in node.children(&mut walker) {
                stack.push(child);
            }
        }

        errors
    }

    /// Identifiers immediately before a '(' in a macro body, less the
    /// keywords that take a parenthesised operand without being a call.
    fn scan_macro_body_calls(body: &str) -> Vec<String> {
        const NOT_CALLS: [&str; 12] = [
            "if",
            "for",
            "while",
            "switch",
            "return",
            "sizeof",
            "typeof",
            "__typeof__",
            "defined",
            "case",
            "do",
            "else",
        ];

        let mut calls = Vec::new();
        for (offset, _) in body.match_indices('(') {
            let before = body[..offset].trim_end();
            // Step back over the delimiter by its own width: a body can hold
            // any UTF-8, and slicing at delimiter + 1 splits a character.
            let start = before
                .char_indices()
                .rev()
                .find(|(_, c)| !(c.is_alphanumeric() || *c == '_'))
                .map(|(i, c)| i + c.len_utf8())
                .unwrap_or(0);
            let name = &before[start..];

            let is_identifier = !name.is_empty()
                && !name.starts_with(|c: char| c.is_numeric())
                && name.chars().all(|c| c.is_alphanumeric() || c == '_');
            if is_identifier && !NOT_CALLS.contains(&name) {
                calls.push(name.to_string());
            }
        }

        calls
    }

    /// Deduplicate functions within a single file (no threading issues).
    ///
    /// One row per name **per preprocessor arm**: `_cond_resched()` is
    /// defined four times in `sched.h`, once per configuration, and those are
    /// four definitions, not four copies of one. Keyed on name alone, the
    /// preference below kept `return 0;` and hid every route that reaches the
    /// scheduler. Within one arm the preference is unchanged: definitions
    /// over declarations, then longer span, longer body, more parameters.
    fn deduplicate_functions_within_file(
        &self,
        raw_functions: Vec<FunctionInfo>,
    ) -> Vec<FunctionInfo> {
        use std::collections::HashMap;

        let mut seen_functions = HashMap::<(String, Option<String>), FunctionInfo>::new();

        for func in raw_functions {
            let key = (func.name.clone(), func.guard.clone());

            if let Some(existing) = seen_functions.get(&key) {
                // Skip if bodies are identical
                if existing.body == func.body {
                    continue;
                }

                // Prefer definitions over declarations
                let existing_span = existing.line_end.saturating_sub(existing.line_start);
                let new_span = func.line_end.saturating_sub(func.line_start);

                // Prefer functions with both parameters AND substantial body content
                let existing_has_body = existing_span > 0
                    && !existing.parameters.is_empty()
                    && !existing.body.trim().is_empty();
                let new_has_body =
                    new_span > 0 && !func.parameters.is_empty() && !func.body.trim().is_empty();

                let should_replace = if new_has_body && !existing_has_body {
                    true // New has body, existing doesn't
                } else if !new_has_body && existing_has_body {
                    false // Existing has body, new doesn't
                } else {
                    // Both have bodies or both don't, prefer longer/more detailed one
                    new_span > existing_span
                        || (new_span == existing_span && func.body.len() > existing.body.len())
                        || func.parameters.len() > existing.parameters.len()
                };

                if !should_replace {
                    continue; // Keep existing
                }
            }

            seen_functions.insert(key, func);
        }

        seen_functions.into_values().collect()
    }

    /// Deduplicate types within a single file
    /// Simple deduplication by (name, kind) - types should be unique within a file anyway
    fn deduplicate_types_within_file(&self, raw_types: Vec<TypeInfo>) -> Vec<TypeInfo> {
        use std::collections::HashMap;

        let mut seen_types = HashMap::<(String, String), TypeInfo>::new();

        for type_info in raw_types {
            let key = (type_info.name.clone(), type_info.kind.clone());

            if let Some(existing) = seen_types.get(&key) {
                // If definitions are identical, skip
                if existing.definition == type_info.definition {
                    continue;
                }

                // Prefer types with more members or longer definitions
                let should_replace = type_info.members.len() > existing.members.len()
                    || (type_info.members.len() == existing.members.len()
                        && type_info.definition.len() > existing.definition.len());

                if !should_replace {
                    continue;
                }
            }

            seen_types.insert(key, type_info);
        }

        seen_types.into_values().collect()
    }

    /// Deduplicate macros within a single file, one row per name per
    /// preprocessor arm.
    ///
    /// `dev_dbg()` has three arms, and keyed on name alone the longest body
    /// won: the `#else` arm a `CONFIG_DYNAMIC_DEBUG` build never uses. Arms
    /// are now distinct rows. A name redefined under the same arm (`pr_fmt`
    /// after each `#undef`) still collapses, and there the longer body wins
    /// as before.
    fn deduplicate_macros_within_file(&self, raw_macros: Vec<FunctionInfo>) -> Vec<FunctionInfo> {
        use std::collections::HashMap;

        let mut seen_macros = HashMap::<(String, Option<String>), FunctionInfo>::new();

        for macro_info in raw_macros {
            let key = (macro_info.name.clone(), macro_info.guard.clone());

            if let Some(existing) = seen_macros.get(&key) {
                // If bodies are identical, skip
                if existing.body == macro_info.body {
                    continue;
                }

                // Prefer longer/more detailed bodies
                let should_replace = macro_info.body.len() > existing.body.len();

                if !should_replace {
                    continue;
                }
            }

            seen_macros.insert(key, macro_info);
        }

        seen_macros.into_values().collect()
    }

    /// Fallback method to extract parameters by recursively searching for parameter_list nodes
    fn try_extract_parameters_from_node(
        &self,
        node: tree_sitter::Node,
        source: &str,
        parameters: &mut Vec<ParameterInfo>,
    ) -> bool {
        // Check if this node is a parameter_list (C) or parameters (Zig)
        if node.kind() == "parameter_list" || node.kind() == "parameters" {
            let extracted_params = self.parse_parameters_from_node(node, source);
            if !extracted_params.is_empty() {
                parameters.extend(extracted_params);
                return true;
            }
        }

        // Recursively search child nodes
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if self.try_extract_parameters_from_node(child, source, parameters) {
                return true;
            }
        }

        false
    }
}

/// Maximum number of non-blank lines allowed between a leading comment
/// block and the entity it documents. One forward declaration is the
/// common case; a long block of unrelated prototypes means the comment
/// documents the block, not the definition below it.
const MAX_INTERVENING_LINES: usize = 3;

/// Collect the comment block that documents the entity starting at
/// `start_line` (1-based), walking backwards through `comments`.
///
/// Shared by `extract_function_with_comments` and
/// `extract_type_with_comments`, which previously carried two verbatim
/// copies of this walk and therefore the same defect.
///
/// `comments` must be sorted ascending by start line, which
/// `extract_comments` guarantees.
fn collect_leading_comments(
    source: &str,
    start_line: u32,
    comments: &[(u32, u32, String)],
) -> Vec<String> {
    let lines: Vec<&str> = source.lines().collect();
    let mut top_comments: Vec<String> = Vec::new();
    // Last source line that may still hold a comment for this entity.
    let mut current_line = start_line.saturating_sub(1);

    for (comment_start_line, comment_end_line, comment_text) in comments.iter().rev() {
        // Comments at or below the entity are not leading comments.
        if *comment_end_line > current_line {
            continue;
        }
        if !gap_is_transparent(&lines, *comment_end_line, current_line) {
            break;
        }
        top_comments.insert(0, comment_text.clone());
        current_line = comment_start_line.saturating_sub(1);
    }

    top_comments
}

/// True when every line strictly after `comment_end_line` and up to and
/// including `current_line` (both 1-based) may sit between a comment and
/// the entity it documents without breaking the association.
fn gap_is_transparent(lines: &[&str], comment_end_line: u32, current_line: u32) -> bool {
    let mut non_blank = 0usize;
    // 1-based line N is index N-1, so lines (comment_end_line, current_line]
    // are indices comment_end_line ..= current_line - 1.
    for idx in (comment_end_line as usize)..(current_line as usize) {
        let Some(line) = lines.get(idx) else {
            return false;
        };
        if line.trim().is_empty() {
            continue;
        }
        non_blank += 1;
        if non_blank > MAX_INTERVENING_LINES || !line_is_association_transparent(line) {
            return false;
        }
    }
    true
}

/// A line that does not break the association between a comment above it
/// and a definition below it.
///
/// Continuation lines of the comment itself are transparent, and so is a
/// forward declaration. The kernel routinely places a prototype between a
/// comment and the definition it describes — `kernel/sched/fair.c` has
/// `dequeue_throttled_task()`'s explanatory comment separated from the
/// definition by `static void detach_task_cfs_rq(struct task_struct *p);`.
/// Treating that prototype as an unrelated statement silently dropped the
/// comment, which is the one artifact that says the behaviour is
/// intentional.
fn line_is_association_transparent(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
        return true;
    }
    is_forward_declaration(line.trim())
}

/// Recognise `<return type> <name>(<params>) <attrs>;` with no body.
///
/// Deliberately strict: one statement, no braces, no assignment, and a
/// parameter list. That admits prototypes (including attribute-decorated
/// ones such as `... __releases(&rq->lock);`) and rejects variable
/// definitions, macro invocations with initialisers, and anything that
/// opens a block.
fn is_forward_declaration(trimmed: &str) -> bool {
    let Some(body) = trimmed.strip_suffix(';') else {
        return false;
    };
    if body.contains('{') || body.contains('}') || body.contains(';') || body.contains('=') {
        return false;
    }
    let Some(open) = body.find('(') else {
        return false;
    };
    let Some(close) = body.rfind(')') else {
        return false;
    };
    if open == 0 || close <= open {
        return false;
    }

    // A declarator-shaped statement is also how a file-scope macro
    // expands — `static DEFINE_MUTEX(some_lock);` parses exactly like a
    // prototype. Those define an object, so a comment above one documents
    // the object, not whatever follows it. Two things separate them: the
    // declared name is not SHOUTY, and a prototype has a return type in
    // front of it.
    let head = &body[..open];
    let name = head
        .rsplit(|c: char| !(c.is_alphanumeric() || c == '_'))
        .next()
        .unwrap_or_default();
    if name.is_empty() || !name.chars().any(|c| c.is_lowercase()) {
        return false;
    }
    !head[..head.len() - name.len()].trim().is_empty()
}

#[cfg(test)]
mod leading_comment_tests {
    use super::*;

    fn comment(start: u32, end: u32, text: &str) -> (u32, u32, String) {
        (start, end, text.to_string())
    }

    #[test]
    fn adjacent_comment_is_collected() {
        let source = "/* doc */\nvoid f(void)\n{\n}\n";
        let comments = vec![comment(1, 1, "/* doc */")];
        assert_eq!(
            collect_leading_comments(source, 2, &comments),
            vec!["/* doc */".to_string()]
        );
    }

    /// The kernel/sched/fair.c:6642-6651 shape: comment, forward
    /// declaration, definition. Before the fix the prototype made the
    /// comment unreachable.
    #[test]
    fn forward_declaration_between_comment_and_definition_is_transparent() {
        let source = concat!(
            "/*\n",
            " * Task is throttled and someone wants to dequeue it again:\n",
            " * ... task sched class change etc.\n",
            " */\n",
            "static void detach_task_cfs_rq(struct task_struct *p);\n",
            "static void dequeue_throttled_task(struct task_struct *p, int flags)\n",
            "{\n",
            "}\n",
        );
        let doc = "/*\n * Task is throttled and someone wants to dequeue it again:\n * ... task sched class change etc.\n */";
        let comments = vec![comment(1, 4, doc)];
        assert_eq!(
            collect_leading_comments(source, 6, &comments),
            vec![doc.to_string()],
        );
    }

    #[test]
    fn blank_line_and_prototype_together_stay_transparent() {
        let source = concat!(
            "/* doc */\n",
            "static int helper(void);\n",
            "\n",
            "void f(void)\n",
            "{\n",
            "}\n",
        );
        let comments = vec![comment(1, 1, "/* doc */")];
        assert_eq!(
            collect_leading_comments(source, 4, &comments),
            vec!["/* doc */".to_string()]
        );
    }

    #[test]
    fn unrelated_statement_still_breaks_the_association() {
        let source = concat!(
            "/* doc for the include block */\n",
            "#include <linux/sched.h>\n",
            "void f(void)\n",
            "{\n",
            "}\n",
        );
        let comments = vec![comment(1, 1, "/* doc for the include block */")];
        assert!(collect_leading_comments(source, 3, &comments).is_empty());
    }

    #[test]
    fn variable_definition_breaks_the_association() {
        let source = concat!(
            "/* doc */\n",
            "static DEFINE_MUTEX(some_lock);\n",
            "void f(void)\n",
            "{\n",
            "}\n",
        );
        let comments = vec![comment(1, 1, "/* doc */")];
        assert!(collect_leading_comments(source, 3, &comments).is_empty());
    }

    #[test]
    fn a_long_block_of_prototypes_breaks_the_association() {
        let source = concat!(
            "/* doc for the whole group */\n",
            "static void a(void);\n",
            "static void b(void);\n",
            "static void c(void);\n",
            "static void d(void);\n",
            "void f(void)\n",
            "{\n",
            "}\n",
        );
        let comments = vec![comment(1, 1, "/* doc for the whole group */")];
        assert!(collect_leading_comments(source, 6, &comments).is_empty());
    }

    #[test]
    fn stacked_comment_blocks_are_collected_in_order() {
        let source = "/* first */\n/* second */\nvoid f(void)\n{\n}\n";
        let comments = vec![comment(1, 1, "/* first */"), comment(2, 2, "/* second */")];
        assert_eq!(
            collect_leading_comments(source, 3, &comments),
            vec!["/* first */".to_string(), "/* second */".to_string()]
        );
    }

    #[test]
    fn comments_below_the_entity_are_ignored() {
        let source = "void f(void)\n{\n}\n/* trailing */\n";
        let comments = vec![comment(4, 4, "/* trailing */")];
        assert!(collect_leading_comments(source, 1, &comments).is_empty());
    }

    #[test]
    fn attribute_decorated_prototype_is_a_forward_declaration() {
        assert!(is_forward_declaration(
            "static void f(struct rq *rq) __releases(rq->lock);"
        ));
        assert!(!is_forward_declaration("static int x = f(1);"));
        assert!(!is_forward_declaration("void f(void) { }"));
        assert!(!is_forward_declaration("static int counter;"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields_of(source: &str, type_name: &str) -> Vec<(String, String)> {
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        let analysis = analyzer
            .analyze_source_with_metadata(source, Path::new("test.c"), "testhash", None)
            .unwrap();
        let types = analysis.types;

        let ty = types
            .iter()
            .find(|t| t.name.ends_with(type_name))
            .unwrap_or_else(|| panic!("type {type_name} not extracted"));

        ty.members
            .iter()
            .map(|m| (m.name.clone(), m.type_name.clone()))
            .collect()
    }

    #[test]
    fn a_member_behind_a_config_option_is_extracted() {
        // task_struct declares 263 members and 140 were recorded: everything
        // a config option guards was dropped, so a field audit of the type
        // silently ignored half of it.
        let fields = fields_of(
            "struct task_struct {\n\
             \tint always;\n\
             #ifdef CONFIG_SMP\n\
             \tint on_cpu;\n\
             #endif\n\
             \tint after;\n\
             };\n",
            "task_struct",
        );

        let names: Vec<&str> = fields.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["always", "on_cpu", "after"], "{fields:?}");
    }

    #[test]
    fn both_arms_of_a_conditional_member_are_extracted() {
        // Which arm a build takes is not knowable from the source, and a
        // member declared in either is one the type can have.
        // An unguarded member is needed: with every member guarded, nothing
        // is found by the walk and a string fallback rescues the struct,
        // which is why a small test does not show the defect.
        let fields = fields_of(
            "struct t {\n\
             \tint plain;\n\
             #ifdef CONFIG_64BIT\n\
             \tlong wide;\n\
             #else\n\
             \tint narrow;\n\
             #endif\n\
             };\n",
            "t",
        );

        let names: Vec<&str> = fields.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"wide"), "{fields:?}");
        assert!(names.contains(&"narrow"), "{fields:?}");
    }

    #[test]
    fn a_member_behind_nested_conditionals_is_extracted() {
        let fields = fields_of(
            "struct t {\n\
             \tint plain;\n\
             #ifdef CONFIG_A\n\
             #ifdef CONFIG_B\n\
             \tint deep;\n\
             #endif\n\
             #endif\n\
             };\n",
            "t",
        );

        let names: Vec<&str> = fields.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["plain", "deep"], "{fields:?}");
    }

    fn analyze(source: &str, path: &str) -> (Vec<FunctionInfo>, Vec<DispatchSite>) {
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        let analysis = analyzer
            .analyze_source_with_metadata(source, Path::new(path), "testhash", None)
            .unwrap();
        (analysis.functions, analysis.dispatch_sites)
    }

    #[test]
    fn indirect_call_macro_names_its_candidates() {
        // The shape of ip_protocol_deliver_rcu: the macro states the targets
        // it expects, and the dispatch goes through a member.
        let (_functions, sites) = analyze(
            "struct net_protocol { int (*handler)(struct sk_buff *); };\n\
             int deliver(const struct net_protocol *ipprot, struct sk_buff *skb) {\n\
             \treturn INDIRECT_CALL_2(ipprot->handler, tcp_v4_rcv, udp_rcv, skb);\n\
             }\n",
            "test.c",
        );

        let declared: Vec<&DispatchSite> = sites
            .iter()
            .filter(|s| s.kind == DispatchKind::MacroDeclared)
            .collect();

        let targets: Vec<&str> = declared
            .iter()
            .filter_map(|s| s.target.as_deref())
            .collect();
        assert_eq!(targets, vec!["tcp_v4_rcv", "udp_rcv"], "sites: {sites:?}");

        // Both candidates describe the same dispatch, through the same member.
        assert!(declared.iter().all(|s| s.member == "handler"));
        assert!(declared
            .iter()
            .all(|s| s.receiver_expr.as_deref() == Some("ipprot->handler")));
        assert!(declared.iter().all(|s| s.caller_name == "deliver"));
    }

    #[test]
    fn an_ordinary_call_declares_no_candidates() {
        let (_functions, sites) = analyze(
            "int helper(int x);\n\
             int go(int x) { return helper(x); }\n",
            "test.c",
        );

        assert!(
            !sites.iter().any(|s| s.kind == DispatchKind::MacroDeclared),
            "ordinary call treated as an indirect-call macro: {sites:?}"
        );
    }

    #[test]
    fn call_through_a_dereferenced_pointer_is_recorded() {
        // `(*fp)(...)` matched no call pattern at all, so the call site was
        // simply absent from the index.
        let (_functions, sites) = analyze(
            "struct file;\n\
             int deref(int (*fp)(struct file *), struct file *f) { return (*fp)(f); }\n",
            "test.c",
        );

        let deref: Vec<&DispatchSite> = sites
            .iter()
            .filter(|s| s.kind == DispatchKind::PointerDeref)
            .collect();
        assert_eq!(deref.len(), 1, "expected the deref call: {sites:?}");
        assert_eq!(deref[0].receiver_expr.as_deref(), Some("fp"));
        assert_eq!(deref[0].caller_name, "deref");
    }

    #[test]
    fn call_through_a_pointer_variable_is_not_a_call_to_that_name() {
        let (functions, sites) = analyze(
            "struct file;\n\
             int my_read(struct file *f) { return 1; }\n\
             int fp(struct file *f) { return 2; }\n\
             int go(struct file *f) {\n\
             \tint (*fp)(struct file *) = my_read;\n\
             \treturn fp(f);\n\
             }\n",
            "test.c",
        );

        let go = functions.iter().find(|f| f.name == "go").unwrap();
        // A function named `fp` exists here, which is what made the variable
        // name resolve to a real, unrelated function.
        assert!(
            !go.calls
                .clone()
                .unwrap_or_default()
                .contains(&"fp".to_string()),
            "pointer variable recorded as a called function: {:?}",
            go.calls
        );

        let local: Vec<&DispatchSite> = sites
            .iter()
            .filter(|s| s.kind == DispatchKind::PointerLocal)
            .collect();
        assert_eq!(local.len(), 1, "expected the pointer call: {sites:?}");
        // The declaration says what it was initialised with.
        assert_eq!(local[0].target.as_deref(), Some("my_read"));
    }

    #[test]
    fn call_through_a_pointer_parameter_is_marked_as_one() {
        let (_functions, sites) = analyze(
            "int go(int (*cb)(int), int x) { return cb(x); }\n",
            "test.c",
        );

        let param: Vec<&DispatchSite> = sites
            .iter()
            .filter(|s| s.kind == DispatchKind::PointerParam)
            .collect();
        assert_eq!(param.len(), 1, "expected the parameter call: {sites:?}");
        assert_eq!(param[0].receiver_expr.as_deref(), Some("cb"));
        // Nothing in this function says what cb points at.
        assert_eq!(param[0].target, None);
    }

    fn macro_calls(source: &str, macro_name: &str) -> Vec<String> {
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        // Macros come back separately; the indexer merges them into the
        // functions table.
        let macros = analyzer
            .analyze_source_with_metadata(source, Path::new("test.c"), "testhash", None)
            .unwrap()
            .macros;

        macros
            .iter()
            .find(|f| f.name == macro_name)
            .unwrap_or_else(|| panic!("macro {macro_name} not extracted"))
            .calls
            .clone()
            .unwrap_or_default()
    }

    #[test]
    fn every_analyzer_shares_one_set_of_queries() {
        // Compiling them is the whole cost of an analyzer, and one is built
        // per file. Two analyzers must point at the same queries, not hold
        // two copies of them.
        let first = TreeSitterAnalyzer::new().unwrap();
        let second = TreeSitterAnalyzer::new().unwrap();

        assert!(std::ptr::eq(first.c_queries, second.c_queries));
        assert!(std::ptr::eq(first.rust_queries, second.rust_queries));
        assert!(std::ptr::eq(first.python_queries, second.python_queries));
    }

    #[test]
    fn a_receiver_declared_here_carries_its_type() {
        let (_functions, sites) = analyze(
            "struct file_operations { int (*read)(void); };\n\
             int probe(struct file_operations *ops) { return ops->read(); }\n",
            "test.c",
        );

        assert_eq!(sites.len(), 1, "{sites:?}");
        assert_eq!(sites[0].member, "read");
        assert_eq!(sites[0].receiver_type.as_deref(), Some("file_operations"));
    }

    #[test]
    fn a_local_declaration_types_the_receiver_too() {
        let (_functions, sites) = analyze(
            "struct ops { int (*run)(void); };\n\
             int probe(void) { struct ops *o = get(); return o->run(); }\n",
            "test.c",
        );

        assert_eq!(sites[0].receiver_type.as_deref(), Some("ops"));
    }

    #[test]
    fn an_undeclared_receiver_stays_untyped() {
        // `ops` comes from somewhere this file does not show. Guessing a type
        // here files the site against registrations it has nothing to do with.
        let (_functions, sites) = analyze("int probe(void) { return ops->read(); }\n", "test.c");

        assert_eq!(sites.len(), 1, "{sites:?}");
        assert_eq!(sites[0].receiver_type, None);
    }

    #[test]
    fn a_name_declared_as_two_types_in_one_function_stays_untyped() {
        let (_functions, sites) = analyze(
            "struct a { int (*run)(void); };\n\
             struct b { int (*run)(void); };\n\
             int probe(void) {\n\
                 { struct a *o = first(); o->run(); }\n\
                 { struct b *o = second(); return o->run(); }\n\
             }\n",
            "test.c",
        );

        assert_eq!(sites.len(), 2, "{sites:?}");
        assert!(
            sites.iter().all(|site| site.receiver_type.is_none()),
            "picked a type for a shadowed name: {sites:?}"
        );
    }

    #[test]
    fn a_receiver_declared_in_another_function_does_not_leak() {
        let (_functions, sites) = analyze(
            "struct ops { int (*run)(void); };\n\
             int typed(struct ops *o) { return o->run(); }\n\
             int untyped(void) { return o->run(); }\n",
            "test.c",
        );

        let typed = sites.iter().find(|s| s.caller_name == "typed").unwrap();
        let untyped = sites.iter().find(|s| s.caller_name == "untyped").unwrap();
        assert_eq!(typed.receiver_type.as_deref(), Some("ops"));
        assert_eq!(untyped.receiver_type, None);
    }

    #[test]
    fn a_field_chain_receiver_records_the_base_and_the_field() {
        // `inode->i_fop` is typed by what `i_fop` is declared as, which is in
        // whichever file declares struct inode. What this file proves is the
        // type of `inode` and the name of the field.
        let (_functions, sites) = analyze(
            "struct inode { struct file_operations *i_fop; };\n\
             int probe(struct inode *inode) { return inode->i_fop->read(); }\n",
            "test.c",
        );

        let read = sites.iter().find(|s| s.member == "read").unwrap();
        assert_eq!(read.receiver_expr.as_deref(), Some("inode->i_fop"));
        assert_eq!(read.receiver_type, None);
        assert_eq!(read.receiver_base_type.as_deref(), Some("inode"));
        assert_eq!(read.receiver_field.as_deref(), Some("i_fop"));
    }

    #[test]
    fn a_field_chain_on_an_undeclared_base_records_nothing() {
        let (_functions, sites) = analyze(
            "int probe(void) { return global->ops->read(); }\n",
            "test.c",
        );

        let read = sites.iter().find(|s| s.member == "read").unwrap();
        assert_eq!(read.receiver_base_type, None);
        assert_eq!(read.receiver_field, None);
    }

    #[test]
    fn a_longer_chain_records_every_step() {
        // `a->b->c` needs the type of `b` before the type of `c`. Both hops
        // are lookups in the types table, so record the path and let
        // resolution walk it.
        let (_functions, sites) = analyze(
            "struct outer { struct middle *b; };\n\
             int probe(struct outer *a) { return a->b->c->run(); }\n",
            "test.c",
        );

        let run = sites.iter().find(|s| s.member == "run").unwrap();
        assert_eq!(run.receiver_expr.as_deref(), Some("a->b->c"));
        assert_eq!(run.receiver_base_type.as_deref(), Some("outer"));
        assert_eq!(run.receiver_field.as_deref(), Some("b.c"));
    }

    #[test]
    fn a_path_keeps_every_field_however_long() {
        // Four fields, mixed arrow and dot, which is what a chain through an
        // embedded struct looks like.
        let (_functions, sites) = analyze(
            "struct l1 { int x; };\n\
             int probe(struct l1 *a) { return a->b.c->d->run(); }\n",
            "test.c",
        );

        let run = sites.iter().find(|s| s.member == "run").unwrap();
        assert_eq!(run.receiver_base_type.as_deref(), Some("l1"));
        assert_eq!(run.receiver_field.as_deref(), Some("b.c.d"));
    }

    #[test]
    fn a_registration_keeps_every_field_however_long() {
        let source = "struct l1 { int x; };\n\
                      int setup(struct l1 *a) {\n\
                      \ta->b->c->d->handler = my_handler;\n\
                      \treturn 0;\n\
                      }\n";
        let registrations = registration_rows(source, "test.c");

        assert_eq!(registrations.len(), 1, "{registrations:?}");
        assert_eq!(registrations[0].container_base_type.as_deref(), Some("l1"));
        assert_eq!(registrations[0].container_field.as_deref(), Some("b.c.d"));
        assert_eq!(registrations[0].member, "handler");
    }

    #[test]
    fn a_chain_through_a_call_records_nothing() {
        // `ath9k_hw_common(_ah)->ops` needs the return type of a function,
        // which is a different lookup; reading half the chain would file the
        // site under the wrong type.
        let (_functions, sites) = analyze(
            "struct ops { int (*run)(void); };\n\
             int probe(void *ah) { return common(ah)->ops->run(); }\n",
            "test.c",
        );

        let run = sites.iter().find(|s| s.member == "run").unwrap();
        assert_eq!(run.receiver_base_type, None);
    }

    #[test]
    fn assembly_in_a_macro_body_is_not_a_dispatch() {
        // arch/arm64/include/asm/asm-extable.h, under __ASSEMBLER__.
        let (_functions, sites) = analyze(
            "#define __ASM_EXTABLE_RAW(insn, fixup) \\\n\
             \t.pushsection __ex_table, \"a\";\\\n\
             \t.long ((insn) - .);\\\n\
             \t.short (fixup);\n",
            "test.c",
        );

        assert!(
            sites.is_empty(),
            "read assembler directives as members: {sites:?}"
        );
    }

    #[test]
    fn an_assignment_through_a_field_records_the_path() {
        // fs/super.c installs every superblock's shrinker this way. `s` is
        // declared here; what `s_shrink` points at is declared with struct
        // super_block, so the container is resolved later.
        let source = "struct super_block { struct shrinker *s_shrink; };\n\
                      int setup(struct super_block *s) {\n\
                      \ts->s_shrink->scan_objects = super_cache_scan;\n\
                      \treturn 0;\n\
                      }\n";
        let registrations = registration_rows(source, "super.c");

        assert_eq!(registrations.len(), 1, "{registrations:?}");
        let entry = &registrations[0];
        assert_eq!(entry.container_type, "");
        assert_eq!(entry.container_base_type.as_deref(), Some("super_block"));
        assert_eq!(entry.container_field.as_deref(), Some("s_shrink"));
        assert_eq!(entry.member, "scan_objects");
        assert_eq!(entry.target, "super_cache_scan");
    }

    #[test]
    fn an_assignment_on_a_declared_name_still_names_its_container() {
        // mm/workingset.c installs through a file-scope pointer, which the
        // file types on its own; nothing is deferred.
        let source = "static struct shrinker *workingset_shadow_shrinker;\n\
                      int init(void) {\n\
                      \tworkingset_shadow_shrinker->scan_objects = scan_shadow_nodes;\n\
                      \treturn 0;\n\
                      }\n";
        let registrations = registration_rows(source, "workingset.c");

        assert_eq!(registrations.len(), 1, "{registrations:?}");
        assert_eq!(registrations[0].container_type, "shrinker");
        assert_eq!(registrations[0].container_base_type, None);
    }

    #[test]
    fn an_assignment_through_an_undeclared_base_records_nothing() {
        let registrations = registration_rows(
            "int setup(void) { p->q->handler = my_handler; return 0; }\n",
            "test.c",
        );

        assert!(registrations.is_empty(), "{registrations:?}");
    }

    #[test]
    fn a_macro_that_declares_a_table_records_no_function() {
        // A macro that declares what it initialises does state the type, so
        // this used to be recorded as `ops::run = fn`. But `fn` is the
        // macro's own parameter: it names whatever a caller passes, which is
        // to say nothing, and a row claiming a function called `fn` was
        // installed is a claim about a function that does not exist.
        //
        // Over a Linux tree this shape recorded 16 rows across 12 macros, and
        // none of them installed a function: `TNUM(_v, _m)` fills
        // `tnum::value` with an integer, `XA_LIMIT(_min, _max)` fills
        // `xa_limit::min`, `UVC_INFO_QUIRK(q)` fills a bitmask. They are value
        // constructors, and what they fill is not callable.
        let found = registrations_of(
            "struct ops { int (*run)(void); };\n\
             #define DEFINE_OPS(name, fn) struct ops name = { .run = fn }\n",
            "test.c",
        );

        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn a_bare_initializer_macro_registers_nothing() {
        // `{ .run = impl }` states no type. Reading one off the context the
        // body was parsed in would file the registration under a type that
        // exists nowhere in the source.
        let found = registrations_of(
            "int impl(void);\n\
             #define OPS_BODY { .run = impl }\n\
             #define OPS_BODY_FN(f) { .run = f }\n",
            "test.c",
        );

        assert!(
            found.is_empty(),
            "registered against the wrapper: {found:?}"
        );
    }

    #[test]
    fn a_macro_that_only_dispatches_calls_no_function() {
        // drivers/gpu/drm/nouveau writes its accessors this way. The member
        // is not a function, and recording it as one is the defect the
        // dispatch sites exist to avoid.
        let source = "struct ops { int (*target)(void); };\n\
                      #define nvkm_memory_target(p) (p)->func->target(p)\n";
        let (_functions, sites) = analyze(source, "test.c");

        assert_eq!(
            macro_calls(source, "nvkm_memory_target"),
            Vec::<String>::new(),
            "member read as a call"
        );
        assert_eq!(sites.len(), 1, "dispatch not recorded: {sites:?}");
        assert_eq!(sites[0].member, "target");
    }

    #[test]
    fn a_macro_body_that_dispatches_records_a_site() {
        // Whole subsystems put their indirection in a macro:
        // include/linux/efi.h writes `((p)->f(args))`.
        let (_functions, sites) = analyze(
            "struct ops { int (*run)(void); };\n\
             #define CALL_RUN(o) ((o)->run())\n",
            "test.c",
        );

        assert_eq!(sites.len(), 1, "expected the site in the body: {sites:?}");
        assert_eq!(sites[0].member, "run");
        assert_eq!(sites[0].kind, DispatchKind::MemberArrow);
        // The site belongs to the macro, since that is where it is written.
        assert_eq!(sites[0].caller_name, "CALL_RUN");
        assert_eq!(sites[0].line, 2);
    }

    #[test]
    fn a_dispatching_macro_and_its_user_are_separate_sites() {
        let (_functions, sites) = analyze(
            "struct ops { int (*run)(void); };\n\
             #define CALL_RUN(o) ((o)->run())\n\
             int user(struct ops *o) { return CALL_RUN(o); }\n\
             int direct(struct ops *o) { return o->run(); }\n",
            "test.c",
        );

        let callers: Vec<&str> = sites.iter().map(|s| s.caller_name.as_str()).collect();
        assert!(
            callers.contains(&"CALL_RUN"),
            "macro site missing: {sites:?}"
        );
        assert!(callers.contains(&"direct"), "plain site missing: {sites:?}");
        // The expansion is not visible here, so the user of the macro has no
        // site of its own; it reaches the dispatch through the macro.
        assert!(!callers.contains(&"user"), "invented a site: {sites:?}");
    }

    #[test]
    fn macro_body_calls_come_from_a_real_parse() {
        // A scan can only match an identifier before a paren. A parse sees
        // the structure, so a call nested in an expression, a cast or a
        // statement expression is found, and a keyword taking a parenthesised
        // operand is not read as a call.
        let source = "int helper(int x) { return x; }\n\
                      int other(int x) { return x; }\n\
                      #define NESTED(x) helper(other(x) + 1)\n\
                      #define CAST(x) ((unsigned long)helper(x))\n\
                      #define STMT(x) ({ int __v = helper(x); __v; })\n\
                      #define GUARD(x) if (x) helper(x)\n";

        assert_eq!(
            macro_calls(source, "NESTED"),
            vec!["helper".to_string(), "other".to_string()]
        );
        assert_eq!(macro_calls(source, "CAST"), vec!["helper".to_string()]);
        assert_eq!(macro_calls(source, "STMT"), vec!["helper".to_string()]);
        assert_eq!(macro_calls(source, "GUARD"), vec!["helper".to_string()]);
    }

    #[test]
    fn an_initializer_macro_body_parses_as_one() {
        // `{ .read = wrap(f) }` is neither a statement nor an expression; it
        // parses only as an initializer, which is one of the contexts tried.
        let source = "int wrap(int (*f)(void));\n\
                      #define OPS_INIT(f) { .read = wrap(f), .write = 0 }\n";

        assert_eq!(macro_calls(source, "OPS_INIT"), vec!["wrap".to_string()]);
    }

    #[test]
    fn a_fragment_body_still_reports_its_call() {
        // `"prefix: " fmt` is not valid C alone, and the kernel is full of
        // it. The parse finds nothing, so the scan answers instead.
        let source = "int printk(const char *fmt, int x);\n\
                      #define pr_thing(x) printk(\"thing: \" \"%d\", x)\n";

        assert_eq!(macro_calls(source, "pr_thing"), vec!["printk".to_string()]);
    }

    #[test]
    fn macro_body_calls_are_found_without_a_space_before_the_paren() {
        // The kernel spelling. Before, only `helper ( x )` was recognised, so
        // a wrapper macro contributed no edges at all.
        let source = "int helper(int x) { return x; }\n\
                      void spin_lock_irq(int *lock) { }\n\
                      #define TIGHT(x) helper(x)\n\
                      #define SPACED(x) helper( x )\n\
                      #define xa_lock_irq(xa) spin_lock_irq(&(xa)->xa_lock)\n";

        assert_eq!(macro_calls(source, "TIGHT"), vec!["helper".to_string()]);
        assert_eq!(macro_calls(source, "SPACED"), vec!["helper".to_string()]);
        assert_eq!(
            macro_calls(source, "xa_lock_irq"),
            vec!["spin_lock_irq".to_string()]
        );
    }

    #[test]
    fn macro_body_with_multibyte_text_does_not_panic() {
        // Kernel headers carry UTF-8 in comments and strings; slicing the
        // body at a byte offset inside one of those characters panics, and a
        // panicking worker takes every file it had left with it.
        let source = "int helper(int x) { return x; }\n\
                      #define DEGREES(x) /* 45° turn */ helper(x)\n\
                      #define NAMED(x) \"café\" helper(x)\n";

        assert_eq!(macro_calls(source, "DEGREES"), vec!["helper".to_string()]);
        assert_eq!(macro_calls(source, "NAMED"), vec!["helper".to_string()]);
    }

    #[test]
    fn macro_body_parentheses_that_are_not_calls_record_nothing() {
        let source = "#define GROUPED(x) ((x) + 1)\n\
                      #define CASTED(x) ((unsigned long)(x))\n";

        assert!(
            macro_calls(source, "GROUPED").is_empty(),
            "grouping parens read as a call: {:?}",
            macro_calls(source, "GROUPED")
        );
        // A cast names a type, not a function; `(x)` has no identifier before it.
        assert!(
            !macro_calls(source, "CASTED").contains(&"x".to_string()),
            "cast operand read as a call: {:?}",
            macro_calls(source, "CASTED")
        );
    }

    /// Whole rows, for tests that care about what was deferred.
    fn registration_rows(source: &str, path: &str) -> Vec<crate::types::Registration> {
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        analyzer
            .analyze_source_with_metadata(source, Path::new(path), "testhash", None)
            .unwrap()
            .registrations
    }

    fn registrations_of(source: &str, path: &str) -> Vec<(String, String, String, String)> {
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        analyzer
            .analyze_source_with_metadata(source, Path::new(path), "testhash", None)
            .unwrap()
            .registrations
            .into_iter()
            .map(|r| (r.container_type, r.member, r.target, r.enclosing_function))
            .collect()
    }

    #[test]
    fn file_scope_ops_table_registers_its_functions() {
        let found = registrations_of(
            "struct file;\n\
             struct file_operations { int (*read)(struct file *); };\n\
             static int my_read(struct file *f) { return 0; }\n\
             static int my_write(struct file *f) { return 0; }\n\
             static const struct file_operations fops = {\n\
             \t.read = my_read,\n\
             \t.write = &my_write,\n\
             \t.owner = 0,\n\
             };\n",
            "test.c",
        );

        assert_eq!(
            found,
            vec![
                (
                    "file_operations".to_string(),
                    "read".to_string(),
                    "my_read".to_string(),
                    String::new()
                ),
                // `&f` and `f` install the same thing.
                (
                    "file_operations".to_string(),
                    "write".to_string(),
                    "my_write".to_string(),
                    String::new()
                ),
            ]
        );
    }

    #[test]
    fn compound_literal_inside_a_function_registers_with_its_cast_type() {
        // net/ipv4/af_inet.c: the registration issue #9 asks about is written
        // inside inet_init, as a compound literal assigned to a member.
        let found = registrations_of(
            "struct sk_buff;\n\
             struct net_protocol { int (*handler)(struct sk_buff *); int no_policy; };\n\
             struct hotdata { struct net_protocol tcp_protocol; };\n\
             static struct hotdata net_hotdata;\n\
             int tcp_v4_rcv(struct sk_buff *skb);\n\
             static int inet_init(void)\n\
             {\n\
             \tnet_hotdata.tcp_protocol = (struct net_protocol) {\n\
             \t\t.handler = tcp_v4_rcv,\n\
             \t\t.no_policy = 1,\n\
             \t};\n\
             \treturn 0;\n\
             }\n",
            "af_inet.c",
        );

        assert_eq!(
            found,
            vec![(
                "net_protocol".to_string(),
                "handler".to_string(),
                "tcp_v4_rcv".to_string(),
                "inet_init".to_string()
            )]
        );
    }

    #[test]
    fn assignment_to_a_member_registers_when_the_receiver_is_typed_here() {
        let found = registrations_of(
            "struct ops { int (*run)(void); };\n\
             int impl(void);\n\
             void setup(struct ops *o) { o->run = impl; }\n",
            "test.c",
        );

        assert_eq!(
            found,
            vec![(
                "ops".to_string(),
                "run".to_string(),
                "impl".to_string(),
                "setup".to_string()
            )]
        );
    }

    #[test]
    fn assignment_through_an_untyped_receiver_registers_nothing() {
        // `container_of(...)` returns something this file cannot type, and
        // guessing the type would file the registration against the wrong
        // dispatch sites.
        let found = registrations_of(
            "int impl(void);\n\
             void setup(void *p) { GET_OPS(p)->run = impl; }\n",
            "test.c",
        );

        assert!(
            found.is_empty(),
            "registered under a guessed type: {found:?}"
        );
    }

    #[test]
    fn a_nested_initializer_records_the_path_to_its_container() {
        // The inner member belongs to whatever `in` is declared as, which is
        // stated with struct outer rather than here. That used to be a reason
        // to record nothing; it is now the same field lookup a chained
        // receiver does, so record the outer type and the path.
        let found = registration_rows(
            "struct outer { struct inner { int (*run)(void); } in; };\n\
             int impl(void);\n\
             static struct outer o = { .in = { .run = impl } };\n",
            "test.c",
        );

        let run = found
            .iter()
            .find(|r| r.member == "run")
            .expect("nested initializer not recorded at all");
        assert_eq!(run.container_type, "");
        assert_eq!(run.container_base_type.as_deref(), Some("outer"));
        assert_eq!(run.container_field.as_deref(), Some("in"));
        assert_eq!(run.target, "impl");
    }

    #[test]
    fn a_positional_group_records_the_outer_type() {
        // A known limitation, pinned rather than fixed.
        //
        // `{ { .run = impl } }` initialises outer's first member, whose type
        // is inner, so filing run under outer is wrong here. It is right when
        // the member is an anonymous struct or union, which C flattens into
        // the outer type, and the two are indistinguishable from one file: the
        // member list lives with the type, elsewhere.
        //
        // Refusing every positional group costs far more than it saves. Over a
        // Linux tree it dropped ~95,000 registrations to remove 4,004 whose
        // container does not declare the member, because the great majority
        // are the anonymous case and correct. Deciding it needs the type,
        // which is why the fix belongs where types are known.
        let found = registration_rows(
            "struct inner { int (*run)(void); };\n\
             struct outer { struct inner in; };\n\
             int impl(void);\n\
             static struct outer o = { { .run = impl } };\n",
            "test.c",
        );

        let run = found.iter().find(|r| r.member == "run").unwrap();
        assert_eq!(run.container_type, "outer");
    }

    #[test]
    fn a_typedef_for_a_function_pointer_is_recorded() {
        // `typedef void (*bfa_isr_func_t)(struct bfa_s *)` puts the name
        // inside a function declarator, so a query wanting a bare
        // type_identifier matches nothing and the typedef is not recorded at
        // all. Every table declared through one is then unrecognisable.
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        let analysis = analyzer
            .analyze_source_with_metadata(
                "typedef void (*bfa_isr_func_t)(struct bfa_s *bfa);\n\
                 typedef unsigned long sector_t;\n",
                Path::new("bfa.h"),
                "testhash",
                None,
            )
            .unwrap();

        let typedefs: Vec<&TypeInfo> = analysis
            .types
            .iter()
            .filter(|t| t.kind == "typedef")
            .collect();
        let names: Vec<&str> = typedefs.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"bfa_isr_func_t"), "{names:?}");
        assert!(names.contains(&"sector_t"), "{names:?}");

        let pointer = typedefs
            .iter()
            .find(|t| t.name == "bfa_isr_func_t")
            .unwrap();
        assert!(
            pointer.definition.contains("(*)"),
            "a reader cannot tell it is a function pointer: {:?}",
            pointer.definition
        );
    }

    #[test]
    fn a_static_call_that_installs_nothing_records_nothing() {
        // `DEFINE_STATIC_CALL_NULL(name, type)` takes a prototype in the
        // second position and leaves the key NULL, so the name there is a
        // type and nothing is installed.
        let found = registration_rows(
            "typedef void (*amd_pmu_branch_reset_t)(void);\n\
             DEFINE_STATIC_CALL_NULL(amd_pmu_branch_reset, amd_pmu_branch_reset_t);\n",
            "core.c",
        );

        assert!(
            found.iter().all(|r| r.member != "()"),
            "a prototype was recorded as an installed function: {found:?}"
        );
    }

    #[test]
    fn a_macro_parameter_is_not_an_installed_function() {
        // `#define hypercall_update(hc) static_call_update(hv_hypercall, hc)`
        // installs whatever a caller passes; `hc` names that nowhere.
        let found = registration_rows(
            "#define hypercall_update(hc) static_call_update(hv_hypercall, hc)\n",
            "mshyperv.c",
        );

        assert!(
            found.iter().all(|r| r.target != "hc"),
            "a macro parameter was recorded as a function: {found:?}"
        );
    }

    #[test]
    fn a_static_call_key_holds_the_function_installed_in_it() {
        let found = registration_rows(
            "int vmx_vcpu_run(struct kvm_vcpu *vcpu);\n\
             DEFINE_STATIC_CALL(kvm_x86_run, vmx_vcpu_run);\n",
            "x86.c",
        );

        let row = found
            .iter()
            .find(|r| r.target == "vmx_vcpu_run")
            .unwrap_or_else(|| panic!("not recorded: {found:?}"));
        assert_eq!(row.container_type, "kvm_x86_run");
        assert_eq!(row.member, "()");
    }

    #[test]
    fn a_call_through_a_static_call_key_is_a_dispatch_site() {
        let (_functions, sites) = analyze(
            "int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu)\n\
             {\n\
             \tint r = 0;\n\
             \tr = static_call(kvm_x86_run)(vcpu);\n\
             \treturn r;\n\
             }\n",
            "x86.c",
        );

        let site = sites
            .iter()
            .find(|s| s.kind == DispatchKind::StaticCall)
            .unwrap_or_else(|| panic!("no static call site: {sites:?}"));
        assert_eq!(site.member, "()");
        assert_eq!(site.receiver_type.as_deref(), Some("kvm_x86_run"));
    }

    #[test]
    fn an_initcall_inside_a_conditional_is_recorded() {
        let (_functions, _sites) = analyze("int cgwb_init(void) { return 0; }\n", "bdi.c");
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        let analysis = analyzer
            .analyze_source_with_metadata(
                "#ifdef CONFIG_CGROUP_WRITEBACK\n\
                 static int cgwb_init(void) { return 0; }\n\
                 subsys_initcall(cgwb_init);\n\
                 #endif\n",
                std::path::Path::new("bdi.c"),
                "hash",
                None,
            )
            .unwrap();
        assert!(
            analysis
                .registrations
                .iter()
                .any(|r| r.target == "cgwb_init" && r.container_type == "subsys_initcall"),
            "{:?}",
            analysis.registrations
        );
    }

    #[test]
    fn a_pasted_static_call_key_is_not_guessed() {
        // `kvm_x86_call(op)` expands to `static_call(kvm_x86_##op)`; the name
        // does not exist until the preprocessor makes it.
        let (_functions, sites) = analyze(
            "int f(struct kvm_vcpu *vcpu)\n\
             {\n\
             \tint r = 0;\n\
             \tr = static_call(kvm_x86_##op)(vcpu);\n\
             \treturn r;\n\
             }\n",
            "x86.c",
        );

        assert!(
            sites.iter().all(|s| s.kind != DispatchKind::StaticCall),
            "{sites:?}"
        );
    }

    #[test]
    fn an_initcall_records_the_level_it_is_filed_under() {
        // Nothing calls `foo_init` and nothing assigns it: the macro puts a
        // pointer to it in a section, so without this it reads as dead code.
        let found = registration_rows(
            "static int foo_init(void)\n\
             {\n\
             \tint rc = 0;\n\
             \treturn rc;\n\
             }\n\
             device_initcall(foo_init);\n",
            "foo.c",
        );

        let row = found
            .iter()
            .find(|r| r.target == "foo_init")
            .unwrap_or_else(|| panic!("initcall not recorded: {found:?}"));
        assert_eq!(row.container_type, "device_initcall");
        assert_eq!(row.member, "[]");
    }

    #[test]
    fn a_call_that_merely_ends_in_init_is_not_an_initcall() {
        // `module_init` is one of these and `mutex_init` is not; a suffix
        // rule cannot tell them apart, which is why the family is spelled out.
        let found = registration_rows(
            "struct mutex { int x; };\n\
             static struct mutex lock;\n\
             int helper(void)\n\
             {\n\
             \tint value = 7;\n\
             \treturn value;\n\
             }\n\
             mutex_init(lock);\n",
            "foo.c",
        );

        assert!(
            found.iter().all(|r| r.container_type != "mutex_init"),
            "{found:?}"
        );
    }

    #[test]
    fn a_table_declared_through_a_typedef_is_a_claim_to_check() {
        // `static bfa_isr_func_t bfa_isrs[N] = { ... }` says only that this
        // is an array of something named elsewhere. Record the elements and
        // the name, so the reader can ask the typedef whether they are
        // functions; deciding here would need a file this one does not have.
        let found = registration_rows(
            "int bfa_isr_unhandled(void);\n\
             int bfa_fcdiag_intr(void);\n\
             static bfa_isr_func_t bfa_isrs[BFI_MC_MAX] = {\n\
             \tbfa_isr_unhandled,\n\
             \tbfa_fcdiag_intr,\n\
             };\n",
            "bfa_core.c",
        );

        assert_eq!(found.len(), 2, "{found:?}");
        for row in &found {
            assert_eq!(row.container_type, "bfa_isrs");
            assert_eq!(row.member, "[]");
            assert_eq!(
                row.container_base_type.as_deref(),
                Some("bfa_isr_func_t"),
                "the claim to check is missing: {row:?}"
            );
        }
    }

    #[test]
    fn a_table_that_spells_out_its_functions_makes_no_claim() {
        let found = registration_rows(
            "int handle_cpuid(struct kvm_vcpu *vcpu);\n\
             static int (*handlers[])(struct kvm_vcpu *vcpu) = {\n\
             \t[EXIT_REASON_CPUID] = handle_cpuid,\n\
             };\n",
            "vmx.c",
        );

        let row = found.first().expect("dropped");
        assert_eq!(row.container_type, "handlers");
        assert_eq!(row.container_base_type, None);
    }

    #[test]
    fn a_table_of_function_pointers_records_its_elements() {
        // kvm_vmx_exit_handlers is this shape. The declaration's type is
        // `int`, and the elements name an exit reason rather than a member,
        // so nothing else in the extractor sees these installations.
        let found = registration_rows(
            "int handle_cpuid(struct kvm_vcpu *vcpu);\n\
             int handle_vmx_instruction(struct kvm_vcpu *vcpu);\n\
             static int (*kvm_vmx_exit_handlers[])(struct kvm_vcpu *vcpu) = {\n\
             \t[EXIT_REASON_CPUID] = handle_cpuid,\n\
             \t[EXIT_REASON_VMCALL] = handle_vmx_instruction,\n\
             };\n",
            "vmx.c",
        );

        let targets: Vec<&str> = found.iter().map(|r| r.target.as_str()).collect();
        assert!(targets.contains(&"handle_cpuid"), "{found:?}");
        assert!(targets.contains(&"handle_vmx_instruction"), "{found:?}");
        for row in &found {
            assert_eq!(row.container_type, "kvm_vmx_exit_handlers");
            assert_eq!(row.member, "[]");
        }
    }

    #[test]
    fn a_positional_table_records_its_elements() {
        let found = registration_rows(
            "int first(void);\n\
             int second(void);\n\
             static int (*table[])(void) = { first, second };\n",
            "t.c",
        );

        let targets: Vec<&str> = found.iter().map(|r| r.target.as_str()).collect();
        assert_eq!(targets, vec!["first", "second"], "{found:?}");
    }

    #[test]
    fn an_array_of_structs_is_not_a_table_of_function_pointers() {
        // `.read = f` inside an array of ops structs still records the member
        // and the struct, not the array.
        let found = registration_rows(
            "struct ops { int (*read)(void); };\n\
             int impl(void);\n\
             static struct ops table[] = { [0] = { .read = impl } };\n",
            "t.c",
        );

        let read = found.iter().find(|r| r.target == "impl").expect("dropped");
        assert_eq!(read.member, "read");
        assert_eq!(read.container_type, "ops");
    }

    #[test]
    fn a_table_held_in_a_field_is_keyed_by_the_type_and_the_field() {
        // `chip->get_delay[i]()` dispatches through an array a struct holds.
        // The array has no name of its own, so the key is the type and the
        // field, which is what the initializer of such a field records.
        let (_functions, sites) = analyze(
            "int azx_get_position(struct azx *chip, int i)\n\
             {\n\
             \treturn chip->get_delay[i](chip);\n\
             }\n",
            "hda.c",
        );

        let site = sites
            .iter()
            .find(|s| s.kind == DispatchKind::ArrayElement)
            .expect("no array dispatch site");
        assert_eq!(site.receiver_expr.as_deref(), Some("chip->get_delay"));
        assert_eq!(site.receiver_type.as_deref(), Some("azx.get_delay"));
    }

    #[test]
    fn a_field_table_on_an_untyped_base_names_no_container() {
        // Nothing here says what `chip` is, and a key built from a guess
        // joins with whatever else guessed the same way.
        let (_functions, sites) = analyze(
            "int azx_get_position(int i)\n\
             {\n\
             \treturn chip->get_delay[i](chip);\n\
             }\n",
            "hda.c",
        );

        let site = sites
            .iter()
            .find(|s| s.kind == DispatchKind::ArrayElement)
            .expect("no array dispatch site");
        assert_eq!(site.receiver_type, None, "{site:?}");
    }

    #[test]
    fn a_call_through_a_table_is_a_dispatch_site() {
        let (_functions, sites) = analyze(
            "int __vmx_handle_exit(struct kvm_vcpu *vcpu, int r)\n\
             {\n\
             \tint i = exit_reason.basic;\n\
             \tif (!kvm_vmx_exit_handlers[i])\n\
             \t\treturn 0;\n\
             \treturn kvm_vmx_exit_handlers[i](vcpu);\n\
             }\n",
            "vmx.c",
        );

        let site = sites
            .iter()
            .find(|s| s.kind == DispatchKind::ArrayElement)
            .expect("no array dispatch site");
        assert_eq!(site.member, "[]");
        assert_eq!(site.receiver_type.as_deref(), Some("kvm_vmx_exit_handlers"));
        assert_eq!(site.caller_name, "__vmx_handle_exit");
    }

    #[test]
    fn an_array_slot_keeps_the_element_type() {
        // Every slot of an array holds the array's element type, so passing
        // through `[0]` changes nothing about which struct owns the member.
        let found = registration_rows(
            "struct entry { int (*run)(void); };\n\
             int impl(void);\n\
             static struct entry table[] = { [0] = { .run = impl } };\n",
            "test.c",
        );

        let run = found
            .iter()
            .find(|r| r.member == "run")
            .expect("array slot recorded nothing");
        assert_eq!(run.container_type, "entry");
        assert_eq!(run.container_base_type, None);
    }

    #[test]
    fn an_array_slot_inside_a_field_keeps_the_path() {
        let found = registration_rows(
            "struct entry { int (*run)(void); };\n\
             struct holder { struct entry table[4]; };\n\
             int impl(void);\n\
             static struct holder h = { .table = { [0] = { .run = impl } } };\n",
            "test.c",
        );

        let run = found.iter().find(|r| r.member == "run").unwrap();
        assert_eq!(run.container_base_type.as_deref(), Some("holder"));
        assert_eq!(run.container_field.as_deref(), Some("table"));
    }

    #[test]
    fn a_member_behind_a_config_option_is_recorded() {
        // net/ipv4/tcp_ipv4.c guards half of tcp_sock_ipv4_specific this way.
        // Which arm a build takes is not knowable here, and a function
        // installed by either is one something can dispatch to.
        let found = registration_rows(
            "struct ops { int (*plain)(void); int (*guarded)(void); int (*other)(void); };\n\
             int plain_impl(void);\n\
             int guarded_impl(void);\n\
             int other_impl(void);\n\
             static struct ops o = {\n\
             \t.plain = plain_impl,\n\
             #ifdef CONFIG_SOMETHING\n\
             \t.guarded = guarded_impl,\n\
             #else\n\
             \t.other = other_impl,\n\
             #endif\n\
             };\n",
            "test.c",
        );

        let members: Vec<&str> = found.iter().map(|r| r.member.as_str()).collect();
        assert!(members.contains(&"plain"), "{found:?}");
        assert!(
            members.contains(&"guarded"),
            "the arm before #else was lost: {found:?}"
        );
        assert!(members.contains(&"other"), "{found:?}");
        assert!(found.iter().all(|r| r.container_type == "ops"), "{found:?}");
        let guarded = found.iter().find(|r| r.member == "guarded").unwrap();
        assert_eq!(guarded.target, "guarded_impl");
    }

    #[test]
    fn typedef_container_is_recorded_by_its_name() {
        let found = registrations_of(
            "typedef struct { int (*run)(void); } Ops;\n\
             int impl(void);\n\
             static Ops ops = { .run = impl };\n",
            "test.c",
        );

        assert_eq!(
            found,
            vec![(
                "Ops".to_string(),
                "run".to_string(),
                "impl".to_string(),
                String::new()
            )]
        );
    }

    #[test]
    fn member_call_is_a_dispatch_site_not_a_call_to_the_member() {
        let (functions, sites) = analyze(
            "struct file;\n\
             struct ops { int (*read)(struct file *); };\n\
             int read(struct file *f) { return 0; }\n\
             int go(struct ops *o, struct file *f) { return o->read(f); }\n",
            "test.c",
        );

        let go = functions.iter().find(|f| f.name == "go").unwrap();
        // A real function named `read` exists, which is exactly how a member
        // name became a confident wrong answer before.
        assert!(
            !go.calls
                .clone()
                .unwrap_or_default()
                .contains(&"read".to_string()),
            "member name recorded as a called function: {:?}",
            go.calls
        );

        assert_eq!(sites.len(), 1, "expected one dispatch site: {sites:?}");
        let site = &sites[0];
        assert_eq!(site.caller_name, "go");
        assert_eq!(site.member, "read");
        assert_eq!(site.receiver_expr.as_deref(), Some("o"));
        assert_eq!(site.kind, DispatchKind::MemberArrow);
        assert_eq!(site.line, 4);
    }

    #[test]
    fn dot_and_arrow_are_distinguished() {
        let (_functions, sites) = analyze(
            "struct ops { int (*run)(void); };\n\
             int go(struct ops *p, struct ops v) { return p->run() + v.run(); }\n",
            "test.c",
        );

        let kinds: Vec<DispatchKind> = sites.iter().map(|s| s.kind).collect();
        assert_eq!(
            kinds,
            vec![DispatchKind::MemberArrow, DispatchKind::MemberDot]
        );
    }

    #[test]
    fn dispatch_outside_any_function_is_still_recorded() {
        // Python module level and class bodies run code; a site there belongs
        // to no function, and dropping it is how it stays invisible today.
        let (_functions, sites) = analyze(
            "class Handler:\n\
             \tdef handle(self):\n\
             \t\treturn 1\n\
             \n\
             h = Handler()\n\
             h.handle()\n",
            "test.py",
        );

        let module_level: Vec<&DispatchSite> =
            sites.iter().filter(|s| s.caller_name.is_empty()).collect();
        assert_eq!(
            module_level.len(),
            1,
            "expected the module-level dispatch: {sites:?}"
        );
        assert_eq!(module_level[0].member, "handle");
        assert_eq!(module_level[0].line, 6);
    }

    #[test]
    fn function_pointer_field_keeps_its_own_name() {
        let fields = fields_of(
            "struct file;\n\
             struct file_operations {\n\
             \tint (*read)(struct file *f, char *buf);\n\
             \tint (*write)(struct file *f, const char *buf);\n\
             };\n",
            "file_operations",
        );

        assert_eq!(
            fields,
            vec![
                (
                    "read".to_string(),
                    "int (*)(struct file *f, char *buf)".to_string()
                ),
                (
                    "write".to_string(),
                    "int (*)(struct file *f, const char *buf)".to_string()
                ),
            ]
        );
    }

    fn params_of(source: &str, func_name: &str) -> Vec<(String, String)> {
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        let functions = analyzer
            .analyze_source_with_metadata(source, Path::new("test.c"), "testhash", None)
            .unwrap()
            .functions;

        let func = functions
            .iter()
            .find(|f| f.name == func_name)
            .unwrap_or_else(|| panic!("function {func_name} not extracted"));

        func.parameters
            .iter()
            .map(|p| (p.name.clone(), p.type_name.clone()))
            .collect()
    }

    #[test]
    fn function_pointer_parameter_keeps_its_name() {
        let params = params_of(
            "struct file;\n\
             int deref(int (*fp)(struct file *, char *), struct file *f) { return 0; }\n",
            "deref",
        );

        assert_eq!(
            params,
            vec![
                (
                    "fp".to_string(),
                    "int (*)(struct file *, char *)".to_string()
                ),
                ("f".to_string(), "struct file *".to_string()),
            ]
        );
    }

    #[test]
    fn parameter_shapes_round_trip() {
        let params = params_of(
            "struct file;\n\
             int shapes(int plain, const char *name, char buf[16], struct file *f,\n\
             \t   void (**pp)(int), int) { return 0; }\n",
            "shapes",
        );

        let actual: Vec<(&str, &str)> = params
            .iter()
            .map(|(n, t)| (n.as_str(), t.as_str()))
            .collect();

        assert_eq!(
            actual,
            vec![
                ("plain", "int"),
                ("name", "const char *"),
                ("buf", "char [16]"),
                ("f", "struct file *"),
                ("pp", "void (**)(int)"),
                ("", "int"),
            ]
        );
    }

    #[test]
    fn anonymous_members_belong_to_the_enclosing_struct() {
        // C makes the members of an anonymous union members of the parent.
        let fields = fields_of(
            "struct wrapper {\n\
             \tint tag;\n\
             \tunion { int u1; long u2; };\n\
             \tunion { int v1; long v2; } named;\n\
             };\n",
            "wrapper",
        );

        let actual: Vec<(&str, &str)> = fields
            .iter()
            .map(|(n, t)| (n.as_str(), t.as_str()))
            .collect();

        assert_eq!(
            actual,
            vec![
                ("tag", "int"),
                // anonymous: reachable as wrapper.u1
                ("u1", "int"),
                ("u2", "long"),
                // named inline aggregate: the member, then what it holds
                ("named", "union {...}"),
                ("named.v1", "int"),
                ("named.v2", "long"),
            ]
        );
    }

    #[test]
    fn declarator_shapes_round_trip() {
        let fields = fields_of(
            "struct file;\n\
             struct tricky {\n\
             \tint plain;\n\
             \tint a, b;\n\
             \tchar *ptr;\n\
             \tconst char * const cptr;\n\
             \tint arr[4];\n\
             \tint matrix[2][3];\n\
             \tunsigned int bits : 3;\n\
             \tvoid (**pptr)(int);\n\
             \tint (*table[8])(void);\n\
             \tstruct file *next;\n\
             \tstruct { int inner; } nested;\n\
             };\n",
            "tricky",
        );

        let expected = vec![
            ("plain", "int"),
            ("a", "int"),
            ("b", "int"),
            ("ptr", "char *"),
            ("cptr", "const char * const"),
            ("arr", "int [4]"),
            ("matrix", "int [2][3]"),
            ("bits", "unsigned int"),
            ("pptr", "void (**)(int)"),
            ("table", "int (*[8])(void)"),
            ("next", "struct file *"),
            ("nested", "struct {...}"),
            ("nested.inner", "int"),
        ];

        let actual: Vec<(&str, &str)> = fields
            .iter()
            .map(|(n, t)| (n.as_str(), t.as_str()))
            .collect();

        assert_eq!(actual, expected);
    }
}

#[cfg(test)]
mod attribute_macros {
    use super::TreeSitterAnalyzer;

    #[test]
    fn a_macro_stating_an_attribute_is_kept() {
        assert!(TreeSitterAnalyzer::expands_to_an_attribute(
            "__attribute__((packed))"
        ));
    }

    #[test]
    fn an_alias_is_kept_so_it_can_be_followed() {
        // ____cacheline_aligned_in_smp expands to ____cacheline_aligned, which
        // is where the attribute is stated. Dropping the alias loses the
        // chain.
        assert!(TreeSitterAnalyzer::expands_to_an_attribute(
            "____cacheline_aligned"
        ));
    }

    #[test]
    fn a_value_is_not_an_attribute() {
        // Six million #defines in a kernel; keeping the ones that cannot lead
        // to an attribute is what makes this affordable.
        assert!(!TreeSitterAnalyzer::expands_to_an_attribute("(1 << 4)"));
        assert!(!TreeSitterAnalyzer::expands_to_an_attribute("0x40"));
        assert!(!TreeSitterAnalyzer::expands_to_an_attribute(""));
    }
}

#[cfg(test)]
mod zig_tests {
    use super::*;

    const ZIG_016: &str = r#"
const std = @import("std");

const Point = struct {
    x: i32,
    y: i32,

    pub fn add(self: Point, other: Point) Point {
        return .{ .x = self.x + other.x, .y = self.y + other.y };
    }
};

const Color = enum(u8) {
    red,
    green,
    blue,
};

const Bits = packed union(u2) {
    a: i2,
    b: u2,
};

const Handle = opaque {};

const IoError = error{
    Timeout,
    Reset,
};

const Width = @Int(.unsigned, 10);
const Pair = @Tuple(&.{ i32, bool });
const Tag = @EnumLiteral();

pub fn sum(a: i32, b: i32) i32 {
    const Int8 = @Int(.unsigned, 8);
    const p = Point{ .x = a, .y = b };
    const q = p.add(Point{ .x = 1, .y = 1 });
    _ = Int8;
    return helper(q.x);
}

fn helper(v: i32) i32 {
    return v;
}

pub extern fn imported(x: u32) void;

test "sum" {
    _ = sum(1, 2);
}

test "helper ok" {
    _ = helper(0);
}
"#;

    fn analyze_zig(source: &str) -> FileAnalysis {
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        analyzer
            .analyze_source_with_metadata(source, Path::new("sample.zig"), "testhash", None)
            .unwrap()
    }

    #[test]
    fn zig_016_functions_have_names_params_and_return_types() {
        let analysis = analyze_zig(ZIG_016);
        let names: Vec<&str> = analysis.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"sum"), "{names:?}");
        assert!(names.contains(&"helper"), "{names:?}");
        assert!(names.contains(&"add"), "{names:?}");
        assert!(names.contains(&"imported"), "{names:?}");
        assert!(names.contains(&"\"sum\""), "{names:?}");
        assert!(names.contains(&"\"helper ok\""), "{names:?}");

        let sum = analysis.functions.iter().find(|f| f.name == "sum").unwrap();
        assert_eq!(sum.return_type, "i32");
        assert_eq!(sum.parameters.len(), 2, "{:?}", sum.parameters);
        assert_eq!(sum.parameters[0].name, "a");
        assert_eq!(sum.parameters[0].type_name, "i32");
        assert_eq!(sum.parameters[1].name, "b");
        assert_eq!(sum.parameters[1].type_name, "i32");
        assert!(
            sum.calls
                .as_ref()
                .is_some_and(|c| c.iter().any(|n| n == "helper")),
            "sum calls: {:?}",
            sum.calls
        );
    }

    #[test]
    fn zig_016_types_include_packed_union_backing_int_and_type_builtins() {
        let analysis = analyze_zig(ZIG_016);
        let by_name: std::collections::HashMap<&str, &TypeInfo> = analysis
            .types
            .iter()
            .map(|t| (t.name.as_str(), t))
            .collect();

        let point = by_name.get("Point").expect("Point");
        assert_eq!(point.kind, "struct");
        let fields: Vec<&str> = point.members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(fields, vec!["x", "y"], "{:?}", point.members);
        assert_eq!(point.members[0].type_name, "i32");

        let bits = by_name.get("Bits").expect("Bits");
        assert_eq!(bits.kind, "union");
        assert!(
            bits.definition.contains("packed union(u2)"),
            "{}",
            bits.definition
        );

        let color = by_name.get("Color").expect("Color");
        assert_eq!(color.kind, "enum");
        let variants: Vec<&str> = color.members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(
            variants,
            vec!["red", "green", "blue"],
            "{:?}",
            color.members
        );

        assert_eq!(by_name.get("Handle").expect("Handle").kind, "opaque");

        let err = by_name.get("IoError").expect("IoError");
        assert_eq!(err.kind, "error");
        let errors: Vec<&str> = err.members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(errors, vec!["Timeout", "Reset"], "{:?}", err.members);

        assert_eq!(by_name.get("Width").expect("Width").kind, "type");
        assert!(by_name.get("Width").unwrap().definition.contains("@Int"));
        assert_eq!(by_name.get("Pair").expect("Pair").kind, "type");
        assert_eq!(by_name.get("Tag").expect("Tag").kind, "type");
        assert!(
            !by_name.contains_key("std"),
            "std = @import is not a type builtin"
        );
    }

    #[test]
    fn zig_016_records_method_and_builtin_calls() {
        let analysis = analyze_zig(ZIG_016);
        let sum = analysis.functions.iter().find(|f| f.name == "sum").unwrap();
        let member_calls: Vec<&str> = analysis
            .dispatch_sites
            .iter()
            .filter(|s| s.caller_name == "sum")
            .map(|s| s.member.as_str())
            .collect();
        assert!(
            member_calls.contains(&"add"),
            "dispatch sites for sum: {member_calls:?}"
        );

        assert!(
            sum.calls
                .as_ref()
                .is_some_and(|c| c.iter().any(|n| n == "@Int")),
            "sum builtin calls: {:?}",
            sum.calls
        );
    }

    #[test]
    fn language_detects_zig_extension() {
        assert_eq!(
            Language::from_path(Path::new("src/main.zig")),
            Some(Language::Zig)
        );
        assert_eq!(
            Language::from_path(Path::new("src/main.rs")),
            Some(Language::Rust)
        );
    }
}

#[cfg(test)]
mod parameter_fate_tests {
    use super::{ParameterFate, TreeSitterAnalyzer};

    #[test]
    fn a_parameter_written_into_a_member_is_stored() {
        let body = "int request_threaded_irq(unsigned int irq, irq_handler_t handler)\n\
                    {\n\
                    \tstruct irqaction *action = kzalloc(sizeof(*action));\n\
                    \taction->handler = handler;\n\
                    \treturn 0;\n\
                    }\n";
        let fates = TreeSitterAnalyzer::parameter_fate(body, "handler");
        assert!(
            fates.iter().any(|fate| matches!(
                fate,
                ParameterFate::StoredIn { container_type, member }
                    if container_type == "irqaction" && member == "handler"
            )),
            "{fates:?}"
        );
    }

    #[test]
    fn a_wrapper_hands_its_parameter_on() {
        let body = "static inline int request_irq(unsigned int irq, irq_handler_t handler,\n\
                    \t\tunsigned long flags, const char *name, void *dev)\n\
                    {\n\
                    \treturn request_threaded_irq(irq, handler, NULL, flags, name, dev);\n\
                    }\n";
        let fates = TreeSitterAnalyzer::parameter_fate(body, "handler");
        assert_eq!(
            fates,
            vec![ParameterFate::HandedOn {
                callee: "request_threaded_irq".to_string(),
                argument_index: 1,
            }],
            "{fates:?}"
        );
    }

    #[test]
    fn a_parameter_that_is_called_is_invoked() {
        let body = "static void run(void (*fn)(void)) { fn(); }\n";
        assert_eq!(
            TreeSitterAnalyzer::parameter_fate(body, "fn"),
            vec![ParameterFate::Invoked]
        );
    }

    #[test]
    fn a_parameter_only_read_has_no_fate() {
        let body = "static int add(int a, int b) { return a + b; }\n";
        assert!(TreeSitterAnalyzer::parameter_fate(body, "a").is_empty());
    }
}

#[cfg(test)]
mod rust_receiver_tests {
    use super::*;

    fn sites_of(source: &str) -> Vec<RawDispatchSite> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let queries = TreeSitterAnalyzer::rust_queries().unwrap();
        let mut extraction =
            TreeSitterAnalyzer::extract_all_calls_optimized(queries, &tree, source, Language::Rust)
                .unwrap();
        std::mem::take(&mut extraction.member_sites)
    }

    fn receiver_type_of(sites: &[RawDispatchSite], member: &str) -> Option<String> {
        sites
            .iter()
            .find(|site| site.member == member)
            .and_then(|site| site.receiver_type.clone())
    }

    #[test]
    fn a_rust_struct_records_its_fields() {
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        let analysis = analyzer
            .analyze_source_with_metadata(
                "struct GenDisk {\n\
                 \ttagset: Arc<TagSet>,\n\
                 \tcount: u32,\n\
                 }\n",
                std::path::Path::new("x.rs"),
                "hash",
                None,
            )
            .unwrap();
        let disk = analysis
            .types
            .iter()
            .find(|t| t.name == "GenDisk")
            .unwrap_or_else(|| panic!("{:?}", analysis.types));
        let members: Vec<(&str, &str)> = disk
            .members
            .iter()
            .map(|m| (m.name.as_str(), m.type_name.as_str()))
            .collect();
        // The member's type is reduced the same way a receiver's is, so the
        // two can be compared when walking a chain.
        assert_eq!(members, vec![("tagset", "TagSet"), ("count", "u32")]);
    }

    #[test]
    fn self_is_the_type_the_impl_names() {
        let sites = sites_of(
            "struct VmallocPageIter;\n\
             impl<'a> Iterator for VmallocPageIter<'a> {\n\
             \tfn next(&mut self) -> Option<u32> { self.size() }\n\
             }\n",
        );
        assert_eq!(
            receiver_type_of(&sites, "size").as_deref(),
            Some("VmallocPageIter"),
            "{sites:?}"
        );
    }

    #[test]
    fn a_parameter_is_typed_from_its_declaration() {
        let sites = sites_of("fn show(fmt: &mut fmt::Formatter<'_>) { fmt.write_str(\"x\"); }\n");
        assert_eq!(
            receiver_type_of(&sites, "write_str").as_deref(),
            Some("Formatter"),
            "{sites:?}"
        );
    }

    #[test]
    fn a_field_chain_records_the_base_and_the_path() {
        let sites = sites_of(
            "impl GenDisk {\n\
             \tfn go(&self) { self.inner.write(); }\n\
             }\n",
        );
        let site = sites.iter().find(|s| s.member == "write").unwrap();
        assert_eq!(
            site.receiver_base_type.as_deref(),
            Some("GenDisk"),
            "{site:?}"
        );
        assert_eq!(site.receiver_field.as_deref(), Some("inner"), "{site:?}");
    }

    #[test]
    fn a_smart_pointer_is_the_type_it_holds() {
        let sites = sites_of("fn f(tagset: Arc<TagSet<T>>) { tagset.raw_tag_set(); }\n");
        assert_eq!(
            receiver_type_of(&sites, "raw_tag_set").as_deref(),
            Some("TagSet"),
            "{sites:?}"
        );
    }

    #[test]
    fn a_container_is_not_the_type_it_holds() {
        // Vec has methods of its own; `.len()` is one of them.
        let sites = sites_of("fn f(items: Vec<Request>) { items.len(); }\n");
        assert_eq!(
            receiver_type_of(&sites, "len").as_deref(),
            Some("Vec"),
            "{sites:?}"
        );
    }

    #[test]
    fn a_raw_pointer_is_not_its_pointee() {
        // `.cast()` belongs to the pointer. Typing the receiver as `request`
        // would claim a member that struct does not have.
        let sites = sites_of("fn f(ptr: *mut request) { ptr.cast(); }\n");
        assert_eq!(receiver_type_of(&sites, "cast"), None, "{sites:?}");
    }
}

#[cfg(test)]
mod argument_subject_tests {
    use super::*;

    fn parse(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_c::LANGUAGE.into())
            .unwrap();
        parser.parse(source, None).unwrap()
    }

    #[test]
    fn the_whole_file_shape_still_types_the_base() {
        let source = "struct inode { int i_state; struct rcu_head i_rcu; };\n\
                      static void i_callback(struct rcu_head *head) { }\n\
                      static void destroy_inode(struct inode *inode)\n\
                      {\n\
                      \tcall_rcu(&inode->i_rcu, i_callback);\n\
                      }\n";
        let tree = parse(source);
        let locals = TreeSitterAnalyzer::collect_local_struct_types(tree.root_node(), source);
        println!("locals: {locals:?}");
        let found = TreeSitterAnalyzer::collect_argument_functions(tree.root_node(), source);
        println!("rows: {found:?}");
        let row = found.iter().find(|r| r.target == "i_callback").unwrap();
        assert_eq!(row.subject_type.as_deref(), Some("inode"), "{row:?}");
    }

    #[test]
    fn the_analysis_keeps_the_subject() {
        let source = "struct inode { int i_state; struct rcu_head i_rcu; };\n\
                      static void i_callback(struct rcu_head *head) { }\n\
                      static void destroy_inode(struct inode *inode)\n\
                      {\n\
                      \tcall_rcu(&inode->i_rcu, i_callback);\n\
                      }\n";
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        let analysis = analyzer
            .analyze_source_with_metadata(source, std::path::Path::new("rcu.c"), "hash", None)
            .unwrap();
        println!("argument_functions: {:?}", analysis.argument_functions);
        let row = analysis
            .argument_functions
            .iter()
            .find(|r| r.target == "i_callback")
            .unwrap();
        assert_eq!(row.subject_type.as_deref(), Some("inode"), "{row:?}");
    }

    #[test]
    fn a_callback_is_attached_to_the_object_holding_the_head() {
        let source = "static void destroy_inode(struct inode *inode)\n\
                      {\n\
                      \tcall_rcu(&inode->i_rcu, i_callback);\n\
                      }\n";
        let tree = parse(source);
        let found = TreeSitterAnalyzer::collect_argument_functions(tree.root_node(), source);
        let row = found
            .iter()
            .find(|row| row.target == "i_callback")
            .unwrap_or_else(|| panic!("i_callback not recorded: {found:?}"));
        assert_eq!(row.subject_type.as_deref(), Some("inode"), "{row:?}");
        assert_eq!(row.subject_member.as_deref(), Some("i_rcu"), "{row:?}");
    }
}

#[cfg(test)]
mod held_table_tests {
    use super::*;

    #[test]
    fn a_table_held_in_a_field_joins_its_sites() {
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        let analysis = analyzer
            .analyze_source_with_metadata(
                "struct ngene_info {\n\
                 \tint (*demod_attach[4])(struct ngene_channel *);\n\
                 };\n\
                 static int demod_attach_stv0900(struct ngene_channel *c) { return 0; }\n\
                 static struct ngene_info ngene_info_duoflex = {\n\
                 \t.demod_attach = { demod_attach_stv0900, demod_attach_stv0900 },\n\
                 };\n\
                 static int probe(struct ngene_info *info, struct ngene_channel *c, int i)\n\
                 {\n\
                 \treturn info->demod_attach[i](c);\n\
                 }\n",
                std::path::Path::new("ngene.c"),
                "hash",
                None,
            )
            .unwrap();

        let installed: Vec<&crate::types::Registration> = analysis
            .registrations
            .iter()
            .filter(|r| r.target == "demod_attach_stv0900")
            .collect();
        assert_eq!(installed.len(), 2, "{:?}", analysis.registrations);
        assert_eq!(installed[0].container_type, "ngene_info.demod_attach");
        assert_eq!(installed[0].member, ARRAY_ELEMENT_MEMBER);

        // The site has to arrive at the same key or the two never meet.
        let site = analysis
            .dispatch_sites
            .iter()
            .find(|s| s.member == ARRAY_ELEMENT_MEMBER)
            .unwrap_or_else(|| panic!("{:?}", analysis.dispatch_sites));
        assert_eq!(
            site.receiver_type.as_deref(),
            Some("ngene_info.demod_attach"),
            "{site:?}"
        );
    }
}

#[cfg(test)]
mod macro_defined_tests {
    use super::*;

    #[test]
    fn a_syscall_body_becomes_a_function() {
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        let analysis = analyzer
            .analyze_source_with_metadata(
                "SYSCALL_DEFINE3(old_readdir, unsigned int, fd,\n\
                 \t\tstruct old_linux_dirent __user *, dirent, unsigned int, count)\n\
                 {\n\
                 \tint error;\n\
                 \terror = iterate_dir(f, &buf.ctx);\n\
                 \treturn error;\n\
                 }\n",
                std::path::Path::new("readdir.c"),
                "hash",
                None,
            )
            .unwrap();

        let syscall = analysis
            .functions
            .iter()
            .find(|f| f.name == "sys_old_readdir")
            .unwrap_or_else(|| {
                panic!(
                    "{:?}",
                    analysis
                        .functions
                        .iter()
                        .map(|f| &f.name)
                        .collect::<Vec<_>>()
                )
            });

        // The body's calls are what make everything below the syscall
        // reachable from it, in both directions.
        assert!(
            syscall
                .calls
                .as_ref()
                .is_some_and(|c| c.iter().any(|n| n == "iterate_dir")),
            "{syscall:?}"
        );
    }

    #[test]
    fn a_macro_body_records_the_function_it_hands_over() {
        // `printk(fmt, ...)` hands `_printk` to `printk_index_wrap`, which
        // calls it. Reading handovers only outside macro bodies is why
        // `callers _printk` named four functions in a tree where 5,729 call it.
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        let analysis = analyzer
            .analyze_source_with_metadata(
                "#define printk_index_wrap(_p_func, fmt, ...) _p_func(fmt, ##__VA_ARGS__)\n\
                 #define printk(fmt, ...) printk_index_wrap(_printk, fmt, ##__VA_ARGS__)\n",
                std::path::Path::new("printk.h"),
                "hash",
                None,
            )
            .unwrap();

        let handover = analysis
            .argument_functions
            .iter()
            .find(|a| a.target == "_printk")
            .unwrap_or_else(|| panic!("{:?}", analysis.argument_functions));
        assert_eq!(handover.callee, "printk_index_wrap", "{handover:?}");
        assert_eq!(handover.enclosing_function, "printk", "{handover:?}");
        assert_eq!(handover.line, 2, "{handover:?}");
    }

    #[test]
    fn a_fact_inside_a_macro_defined_body_is_recorded_once() {
        // The body a SYSCALL_DEFINE opens is not a function_definition, so the
        // walk that collects what no function encloses finds this assignment
        // too. Two rows for one place in one file is what the database calls
        // an ambiguous merge, and it refuses the whole batch.
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        let analysis = analyzer
            .analyze_source_with_metadata(
                "SYSCALL_DEFINE2(clone3, struct clone_args __user *, uargs, size_t, size)\n\
                 {\n\
                 \tstruct kernel_clone_args kargs;\n\
                 \n\
                 \tkargs.set_tid = set_tid;\n\
                 \treturn kernel_clone(&kargs);\n\
                 }\n",
                std::path::Path::new("fork.c"),
                "hash",
                None,
            )
            .unwrap();

        let rows: Vec<_> = analysis
            .registrations
            .iter()
            .filter(|r| r.target == "set_tid")
            .collect();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].enclosing_function, "sys_clone3", "{rows:?}");
    }

    #[test]
    fn a_macro_that_calls_its_parameter_records_where_to_look() {
        // The call is real and its callee is whatever the invocation passed.
        // Recording `_p_func` as a callee names a function no tree has.
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        let analysis = analyzer
            .analyze_source_with_metadata(
                "#define printk_index_wrap(_p_func, fmt, ...) _p_func(fmt, ##__VA_ARGS__)\n",
                std::path::Path::new("printk.h"),
                "hash",
                None,
            )
            .unwrap();

        let edge = analysis
            .unresolved_edges
            .iter()
            .find(|e| e.name == "printk_index_wrap")
            .unwrap_or_else(|| panic!("{:?}", analysis.unresolved_edges));
        assert_eq!(edge.direction, "out", "{edge:?}");
        assert_eq!(edge.kind, "c:macro_parameter_call", "{edge:?}");
        assert!(edge.evidence.contains("_p_func"), "{edge:?}");
        // A reason with no place to look is a shrug.
        assert!(!edge.locations.is_empty(), "{edge:?}");
        assert_eq!(edge.locations[0].role, "definition", "{edge:?}");
        assert_eq!(edge.locations[0].line, 1, "{edge:?}");

        let macro_row = analysis
            .macros
            .iter()
            .find(|m| m.name == "printk_index_wrap")
            .unwrap();
        assert!(
            !macro_row
                .calls
                .clone()
                .unwrap_or_default()
                .iter()
                .any(|c| c == "_p_func"),
            "{macro_row:?}"
        );
    }

    #[test]
    fn a_macro_parameter_is_not_a_handover() {
        // `_p_func` is the macro's own parameter: whatever a caller passes is
        // named nowhere in this file.
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        let analysis = analyzer
            .analyze_source_with_metadata(
                "#define call_it(_p_func, fmt) helper(_p_func, fmt)\n",
                std::path::Path::new("wrap.h"),
                "hash",
                None,
            )
            .unwrap();
        assert!(
            !analysis
                .argument_functions
                .iter()
                .any(|a| a.target == "_p_func"),
            "{:?}",
            analysis.argument_functions
        );
    }

    #[test]
    fn a_body_the_parser_abandoned_keeps_its_calls() {
        // `TRAILING_OVERLAP(...) x = {...};` is not parseable C. The grammar
        // ends the function at that line and makes the statements after it
        // children of the translation unit, so the calls below the break
        // belong to nobody and nothing says so.
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        let analysis = analyzer
            .analyze_source_with_metadata(
                "static int freeze(struct nvdimm *nvdimm)\n\
                 {\n\
                 \tstruct nfit_mem *mem = provider_data(nvdimm);\n\
                 \tTRAILING_OVERLAP(struct nd_cmd_pkg, pkg, nd_payload,\n\
                 \t\tstruct nd_intel_freeze_lock cmd;\n\
                 \t) nd_cmd = {\n\
                 \t\t.pkg = { .nd_size_out = 4, },\n\
                 \t};\n\
                 \n\
                 \tif (!test_bit(0, &mem->dsm_mask))\n\
                 \t\treturn -ENOTTY;\n\
                 \treturn nvdimm_ctl(nvdimm, &nd_cmd);\n\
                 }\n",
                std::path::Path::new("intel.c"),
                "hash",
                None,
            )
            .unwrap();

        let freeze = analysis
            .functions
            .iter()
            .find(|f| f.name == "freeze")
            .unwrap();
        let calls = freeze.calls.clone().unwrap_or_default();
        for expected in ["provider_data", "test_bit", "nvdimm_ctl"] {
            assert!(calls.iter().any(|c| c == expected), "{calls:?}");
        }
    }

    #[test]
    fn a_body_the_parser_read_whole_is_unchanged() {
        // The recovery must not extend a function whose body parsed, or every
        // range in the file would drift by whatever follows it.
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        let analysis = analyzer
            .analyze_source_with_metadata(
                "static int first(void)\n\
                 {\n\
                 \treturn one();\n\
                 }\n\
                 \n\
                 static int second(void)\n\
                 {\n\
                 \treturn two();\n\
                 }\n",
                std::path::Path::new("plain.c"),
                "hash",
                None,
            )
            .unwrap();
        let first = analysis
            .functions
            .iter()
            .find(|f| f.name == "first")
            .unwrap();
        assert_eq!(first.line_end, 4, "{first:?}");
        let calls = first.calls.clone().unwrap_or_default();
        assert!(calls.iter().any(|c| c == "one"), "{calls:?}");
        assert!(!calls.iter().any(|c| c == "two"), "{calls:?}");
    }

    #[test]
    fn a_body_under_elifdef_becomes_a_function() {
        // `#elifdef` is a conditional like any other, and a walk that lists
        // conditional kinds by name rather than asking one question drops
        // whatever the list omits.
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        let analysis = analyzer
            .analyze_source_with_metadata(
                "#ifdef CONFIG_A\n\
                 SYSCALL_DEFINE1(alpha, int, x)\n\
                 {\n\
                 \treturn one(x);\n\
                 }\n\
                 #elifdef CONFIG_B\n\
                 SYSCALL_DEFINE1(beta, int, x)\n\
                 {\n\
                 \treturn two(x);\n\
                 }\n\
                 #endif\n",
                std::path::Path::new("alpha.c"),
                "hash",
                None,
            )
            .unwrap();

        let names: Vec<&String> = analysis.functions.iter().map(|f| &f.name).collect();
        assert!(names.iter().any(|n| *n == "sys_alpha"), "{names:?}");
        assert!(names.iter().any(|n| *n == "sys_beta"), "{names:?}");
        let beta = analysis
            .functions
            .iter()
            .find(|f| f.name == "sys_beta")
            .unwrap();
        assert!(
            beta.calls
                .as_ref()
                .is_some_and(|c| c.iter().any(|n| n == "two")),
            "{beta:?}"
        );
    }

    #[test]
    fn an_initcall_under_elifdef_is_recorded() {
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        let analysis = analyzer
            .analyze_source_with_metadata(
                "#ifdef CONFIG_A\n\
                 static int early_init(void) { return 0; }\n\
                 subsys_initcall(early_init);\n\
                 #elifdef CONFIG_B\n\
                 static int late_init(void) { return 0; }\n\
                 subsys_initcall(late_init);\n\
                 #endif\n",
                std::path::Path::new("init.c"),
                "hash",
                None,
            )
            .unwrap();
        assert!(
            analysis
                .registrations
                .iter()
                .any(|r| r.target == "late_init" && r.container_type == "subsys_initcall"),
            "{:?}",
            analysis.registrations
        );
    }

    #[test]
    fn a_macro_opening_an_initializer_is_not_a_function() {
        // `define_machine(pseries) { .memory_block_size = ... }` is the same
        // shape with a struct in the braces.
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        let analysis = analyzer
            .analyze_source_with_metadata(
                "define_machine(pseries) {\n\
                 \t.name = \"pSeries\",\n\
                 };\n",
                std::path::Path::new("setup.c"),
                "hash",
                None,
            )
            .unwrap();
        assert!(
            !analysis
                .functions
                .iter()
                .any(|f| f.name.starts_with("sys_")),
            "{:?}",
            analysis
                .functions
                .iter()
                .map(|f| &f.name)
                .collect::<Vec<_>>()
        );
    }
}

#[cfg(test)]
mod preproc_error_recovery_tests {
    //! What an unparseable construct does to the `#define`s after it.
    //!
    //! A construct tree-sitter-c cannot read -- an attribute macro between
    //! the storage class and the return type, `static inline __printf(3, 4)`
    //! -- yields an `ERROR` node that does not stop at the declaration. It
    //! runs on and swallows every following directive, so no
    //! `preproc_function_def` exists for the extraction query to match.
    //! `include/linux/dev_printk.h` contributes one of its 41 function-like
    //! macros to the index for this reason, and nothing is logged: the file
    //! indexes "successfully".
    //!
    //! Measured on Linux 50d05c7c76c9 with tree-sitter 0.26.11 and
    //! tree-sitter-c 0.24.2: 1,224 function-like `#define`s across 435 files
    //! do not exist in the index. The parser version is part of that
    //! measurement.
    //!
    //! These fixtures are the shapes, reduced until each is the smallest
    //! source that still reproduces what the tree does. The tests that hold
    //! today record what is lost and where recovery must not go; the ones
    //! marked `ignore` are the recovery's own gates, and they fail until it
    //! exists (`cargo test -- --ignored`).

    use super::*;

    /// The defect, minimised. `before` is indexed; `after` is not.
    const ATTRIBUTE_SWALLOW: &str = "#define before(x) x\n\
         \n\
         static inline __printf(3, 4)\n\
         void plain_printk(const char *level, const char *fmt, ...)\n\
         {}\n\
         \n\
         #define after(x) x\n";

    /// `dev_printk.h`'s shape: one macro, then the unreadable declaration,
    /// then everything the header exists to define -- including a macro
    /// whose body continues over a line and one defined once per branch.
    const LOGGING_HEADER: &str = "#define dev_fmt(fmt) fmt\n\
         \n\
         static inline __printf(3, 4)\n\
         void dev_printk_emit(int level, const struct device *dev, const char *fmt, ...)\n\
         {}\n\
         \n\
         #define dev_printk(level, dev, fmt, ...) \\\n\
         \tdev_printk_emit(level, dev, fmt, ##__VA_ARGS__)\n\
         \n\
         #define dev_err(dev, fmt, ...) dev_printk(3, dev, fmt, ##__VA_ARGS__)\n\
         \n\
         #ifdef CONFIG_DYNAMIC_DEBUG\n\
         #define dev_dbg(dev, fmt, ...) dynamic_dev_dbg(dev, fmt, ##__VA_ARGS__)\n\
         #elif defined(DEBUG)\n\
         #define dev_dbg(dev, fmt, ...) dev_printk(7, dev, fmt, ##__VA_ARGS__)\n\
         #else\n\
         #define dev_dbg(dev, fmt, ...) dev_no_printk(dev, fmt)\n\
         #endif\n";

    /// A commented-out `#define` inside the swallowed span. Recovery works
    /// by blanking what an `ERROR` covers, which can strip the comment
    /// delimiters around this one and leave a directive the file never
    /// declared.
    const SWALLOWED_COMMENT: &str = "#define kept(x) x\n\
         \n\
         static inline __printf(3, 4)\n\
         void plain_printk(const char *level, const char *fmt, ...)\n\
         {\n\
         \tif (level) {\n\
         \n\
         /*\n\
          * #define GHOST(x) x\n\
          */\n\
         #define real(x) x\n";

    /// A `#define` between the members of an `enum`. The grammar reports a
    /// missing comma and produces no node for the directive, and the span
    /// covers only the directive's own lines, so the file's later macros are
    /// unaffected. Recovery blanks code lines, not directives, so this one
    /// is out of its reach by construction.
    const DEFINE_INSIDE_ENUM: &str = "enum thing {\n\
         \tFIRST,\n\
         #define IN_ENUM(x) x\n\
         \tSECOND\n\
         #define SECOND_IN_ENUM(x) x\n\
         };\n\
         \n\
         #define after_enum(x) x\n";

    fn macros_in(source: &str) -> Vec<(String, u32)> {
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        let analysis = analyzer
            .analyze_source_with_metadata(source, std::path::Path::new("fixture.h"), "hash", None)
            .unwrap();
        let mut found: Vec<(String, u32)> = analysis
            .macros
            .iter()
            .map(|entry| (entry.name.clone(), entry.line_start))
            .collect();
        found.sort();
        found
    }

    /// Somewhere for a test to read what the analyzer said.
    #[derive(Clone, Default)]
    struct Recorded(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Recorded {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Recorded {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// What the analyzer logs while reading one file. The subscriber is
    /// thread-local, so tests running beside each other do not read each
    /// other's lines.
    fn log_of(source: &str) -> String {
        let recorded = Recorded::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(recorded.clone())
            .with_max_level(tracing::Level::INFO)
            .without_time()
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let _ = macros_in(source);
        });
        let bytes = recorded.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    fn macro_names(source: &str) -> Vec<String> {
        let mut names: Vec<String> = macros_in(source)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        names.dedup();
        names
    }

    #[test]
    fn a_define_between_enum_members_is_lost_and_takes_nothing_with_it() {
        // Both directives inside the braces are gone, and the macro after
        // the enum is not, which is what bounds this case: the span does not
        // run on. Recovery must not claim it.
        assert_eq!(
            macros_in(DEFINE_INSIDE_ENUM),
            vec![("after_enum".to_string(), 8)]
        );
    }

    #[test]
    fn a_commented_out_define_is_never_a_definition() {
        // The guard against a phantom: a count that goes up is not evidence
        // that what was gained was ever declared. This holds now because
        // nothing in the swallowed span is read at all, and it must still
        // hold once the span is recovered.
        for source in [
            ATTRIBUTE_SWALLOW,
            LOGGING_HEADER,
            SWALLOWED_COMMENT,
            DEFINE_INSIDE_ENUM,
        ] {
            assert!(
                !macro_names(source).contains(&"GHOST".to_string()),
                "a macro inside a comment was extracted"
            );
        }
    }

    #[test]
    fn what_parses_today_is_the_baseline_recovery_may_not_lose() {
        // Recovery replaces a parse with one of a blanked file, and blanking
        // is not semantics-preserving: a prototype turned dce_hwseq.h from
        // 59 definitions into 35 by blanking a struct whose tokens the
        // extraction depended on. Every pair here must survive, so the
        // baseline is stated rather than recomputed from whatever the
        // recovered tree happens to return. Recovery adds rows, so this
        // states what may not go missing and not what the whole list is --
        // the lists themselves are the gates below.
        for (source, baseline) in [
            (SWALLOWED_COMMENT, ("kept", 1u32)),
            (ATTRIBUTE_SWALLOW, ("before", 1)),
            (LOGGING_HEADER, ("dev_fmt", 1)),
            (DEFINE_INSIDE_ENUM, ("after_enum", 8)),
        ] {
            let found = macros_in(source);
            assert!(
                found
                    .iter()
                    .any(|(name, line)| name == baseline.0 && *line == baseline.1),
                "the directive above the unreadable line: {baseline:?} not in {found:?}"
            );
        }
    }

    #[test]
    fn recovery_finds_the_directive_after_an_unreadable_declaration() {
        assert_eq!(
            macros_in(ATTRIBUTE_SWALLOW),
            vec![("after".to_string(), 7), ("before".to_string(), 1)]
        );
    }

    #[test]
    fn recovery_finds_every_name_a_logging_header_defines() {
        // Names, not directive lines: dev_dbg is defined three times here
        // and the index holds one row per name per file. Which arm that row
        // comes from is a separate question, and the answer today is
        // whichever body is longest.
        let mut names = macro_names(LOGGING_HEADER);
        names.sort();
        assert_eq!(names, vec!["dev_dbg", "dev_err", "dev_fmt", "dev_printk"]);
    }

    #[test]
    fn recovery_finds_the_real_directive_beside_a_commented_out_one() {
        let names = macro_names(SWALLOWED_COMMENT);
        assert!(names.contains(&"real".to_string()), "{names:?}");
        assert!(!names.contains(&"GHOST".to_string()), "{names:?}");
    }

    /// A `//` comment whose row ends in a backslash. The splice happens
    /// before comments are read, so the `#define` below it is comment text
    /// and not a definition -- but it is directive-shaped, so blanking
    /// leaves it alone while destroying the `//` above it, and the healed
    /// tree holds a real node for it.
    const SPLICED_COMMENT: &str = "#define kept(x) x\n\
         static inline __printf(3, 4)\n\
         int broken(const char *fmt, ...);\n\
         // this comment continues over the row below \\\n\
         #define PHANTOM(x) x\n\
         #define REAL(x) x\n";

    /// A name defined once above the unreadable construct and once inside
    /// the span it swallows, with a longer body. One row per name survives
    /// deduplication and the longer body wins it, so the row the original
    /// parse read is not in the healed parse's deduplicated set.
    const REPEATED_NAME: &str = "#define DUP(x) x\n\
         static inline __printf(3, 4)\n\
         int broken(const char *fmt, ...);\n\
         #define DUP(x) a_longer_expansion_of(x, x, x)\n\
         #define NEWFOUND(x) x\n";

    #[test]
    fn a_spliced_comment_hides_the_directive_below_it() {
        // Blanking destroys the `//` and leaves the row under it, which is
        // where a phantom comes from that the masked scan of the original
        // has to refuse. The real directive below it is still recovered.
        let names = macro_names(SPLICED_COMMENT);
        assert!(!names.contains(&"PHANTOM".to_string()), "{names:?}");
        assert!(names.contains(&"REAL".to_string()), "{names:?}");
        assert!(names.contains(&"kept".to_string()), "{names:?}");
    }

    #[test]
    fn a_name_defined_twice_does_not_forfeit_the_others() {
        // The losslessness guard asks whether the healed tree still *reads*
        // every original definition, which it must ask before one row per
        // name survives. Asking it afterwards rejects this whole graft and
        // forfeits a macro that was recovered correctly -- and a logging
        // header defining one name once per `#if` arm is exactly this shape.
        let names = macro_names(REPEATED_NAME);
        assert!(names.contains(&"NEWFOUND".to_string()), "{names:?}");
        assert!(names.contains(&"DUP".to_string()), "{names:?}");
    }

    /// A string literal spliced over a row, then a commented-out
    /// `#define`. Counting the spliced newline as no row at all puts every
    /// row after it out of step, and the comment's row then reads as code.
    const SPLICED_STRING: &str = "#define before(x) \"a\\\nb\"\n\
         static inline __printf(3, 4)\n\
         int broken(const char *fmt, ...);\n\
         /*\n\
         #define GHOST(x) x */\n\
         #define real(x) x\n";

    /// An apostrophe in prose the compiler never compiles, above a
    /// commented-out `#define`. A scan that lets a literal run past the end
    /// of its row is inside a string from there on, so the comment below
    /// looks like code.
    const UNTERMINATED_QUOTE: &str = "#define before(x) x\n\
         static inline __printf(3, 4)\n\
         int broken(const char *fmt, ...);\n\
         #if 0\n\
         this doesn't build\n\
         #endif\n\
         /* it's gone\n\
         #define GHOST(x) x\n\
          */\n\
         #define real(x) x\n";

    /// A row inside a spliced comment that defines the same name as a real
    /// swallowed definition below it, with a longer body. One row per name
    /// survives, and the longer body wins, so choosing the survivor before
    /// the file has been asked which rows are comments hands the name to
    /// the row that was never a definition.
    const PHANTOM_TAKES_A_NAME: &str = "#define kept(x) x\n\
         static inline __printf(3, 4)\n\
         int broken(const char *fmt, ...);\n\
         // this comment continues over the row below \\\n\
         #define shared(x) a_much_longer_expansion_of(x, x, x, x)\n\
         #define shared(x) x\n";

    #[test]
    fn a_phantom_cannot_take_the_name_of_a_real_definition() {
        // The real definition is on row 6 and the comment's row 5 carries
        // the longer body. Recovering row 5 would be inventing a macro; not
        // recovering row 6 because row 5 outbid it loses a real one.
        let found = macros_in(PHANTOM_TAKES_A_NAME);
        assert!(
            found.contains(&("shared".to_string(), 6)),
            "the real definition was not recovered: {found:?}"
        );
        assert!(
            !found
                .iter()
                .any(|(name, line)| name == "shared" && *line == 5),
            "a row the file writes as a comment was read as a definition: {found:?}"
        );
    }

    #[test]
    fn a_file_whose_macros_were_recovered_says_which_and_how_many() {
        // The defect stood as long as it did because a file that indexes
        // without the macros it defines indexes "successfully": 41
        // directives in one logging header, one row, nothing logged.
        let said = log_of(LOGGING_HEADER);
        // Five: dev_printk, dev_err, and each of dev_dbg's three arms.
        assert!(
            said.contains("read 5 function-like macros"),
            "the count of what was recovered is not in the log: {said}"
        );
        assert!(said.contains("fixture.h"), "{said}");
    }

    #[test]
    fn a_file_where_a_definition_was_refused_says_that_too() {
        // Recovery declining is as much a fact about the file as recovery
        // working. Here one row looked like a definition once the construct
        // around it was blanked, and the file states it is the continuation
        // of a comment.
        let said = log_of(SPLICED_COMMENT);
        assert!(said.contains("refused=1"), "{said}");
    }

    #[test]
    fn a_file_the_parser_reads_whole_says_nothing() {
        // Silence is the answer for the file with nothing to recover, or the
        // log is noise: 1,639 files on one kernel tree enter recovery and
        // 139 of them gain anything.
        let said = log_of("#define fine(x) x\n\nvoid plain(void)\n{}\n");
        assert!(said.is_empty(), "{said}");
    }

    #[test]
    fn a_recovered_macro_brings_what_its_body_does() {
        // A row for the definition is half of it. The body of a recovered
        // macro calls through a parameter, and that edge has to arrive with
        // it -- a definition whose calls are dropped is the same silence one
        // hop along.
        let source = "#define kept(x) x\n\
             static inline __printf(3, 4)\n\
             int broken(const char *fmt, ...);\n\
             #define call_through(f) f(1)\n";
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        let analysis = analyzer
            .analyze_source_with_metadata(source, std::path::Path::new("fixture.h"), "hash", None)
            .unwrap();
        assert!(
            analysis
                .macros
                .iter()
                .any(|entry| entry.name == "call_through"),
            "the definition itself was not recovered"
        );
        assert!(
            analysis
                .unresolved_edges
                .iter()
                .any(|edge| edge.name == "call_through"),
            "recovered the definition and dropped what it calls: {:?}",
            analysis
                .unresolved_edges
                .iter()
                .map(|edge| (&edge.name, &edge.kind))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_spliced_string_keeps_the_rows_after_it_in_step() {
        // Counting the spliced newline as no row puts the block comment one
        // row off, and the commented-out `#define` is then believed. The
        // real macro below it stays unread either way -- blanking leaves the
        // comment's closing `*/` behind and the fresh ERROR over it is the
        // tail this does not reach -- so what this pins is that being unable
        // to recover a row is never an excuse to invent one.
        let names = macro_names(SPLICED_STRING);
        assert!(!names.contains(&"GHOST".to_string()), "{names:?}");
        assert_eq!(names, vec!["before".to_string()]);
    }

    #[test]
    fn an_unterminated_literal_ends_with_its_row() {
        let names = macro_names(UNTERMINATED_QUOTE);
        assert!(!names.contains(&"GHOST".to_string()), "{names:?}");
        assert!(names.contains(&"real".to_string()), "{names:?}");
    }

    #[test]
    fn a_round_with_nothing_left_to_blank_does_not_reparse() {
        // An ERROR that survives blanking covers the same rows every round.
        // Where those rows are empty there is no text to change, and a round
        // that hands back what it was given makes the file parse again for
        // nothing, up to the round cap.
        let source = "#if A\n\n#elif B\n\n";
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        let tree = analyzer
            .get_parser(Language::C)
            .parse(source, None)
            .unwrap();
        assert!(
            TreeSitterAnalyzer::blank_error_lines(source, &tree).is_none(),
            "a round rewrote rows that were already blank"
        );
    }

    #[test]
    fn a_comment_does_not_stop_a_row_from_opening_a_directive() {
        // A comment is whitespace by the time directives are read, so a
        // `#define` after one on the same row is a definition and the masked
        // scan may not refuse it as a gain.
        // A byte-order mark leads the file, not the row, which is why it is
        // on the first of these.
        let source =
            "\u{feff}#define after_a_byte_order_mark(x) x\n/* c */ #define after_comment(x) x\n";
        let mut rows: Vec<u32> = TreeSitterAnalyzer::define_rows_in_code_region(source)
            .into_iter()
            .collect();
        rows.sort();
        assert_eq!(rows, vec![1, 2]);
    }

    #[test]
    fn a_file_the_parser_reads_whole_is_never_reparsed() {
        // The pre-gate. Recovery costs a second parse of the file, so a file
        // whose parse holds no ERROR over a directive must not enter it --
        // and neither must one whose ERROR covers only code.
        let clean = "#define fine(x) x\n\nvoid plain(void)\n{}\n";
        let error_over_code_only = "void plain(void)\n{\n\tint x = = 1;\n}\n";
        for source in [clean, error_over_code_only] {
            let mut analyzer = TreeSitterAnalyzer::new().unwrap();
            let tree = analyzer
                .get_parser(Language::C)
                .parse(source, None)
                .unwrap();
            assert!(
                analyzer
                    .heal_swallowed_directives(source, &tree, Language::C)
                    .is_none(),
                "recovery ran on a file it cannot help: {source:?}"
            );
        }
    }

    #[test]
    fn a_continuation_line_is_part_of_the_directive_it_continues() {
        // Blanking a continuation line destroys the body of every multi-line
        // macro, which is the difference between reading 25 of a logging
        // header's 41 directives and all of them. A backslash on a line of
        // code continues nothing.
        let source = "#define two(x) \\\n\tuse(x)\n\nint code = 1; \\\nstill_code;\n";
        assert_eq!(
            TreeSitterAnalyzer::directive_lines(source),
            vec![true, true, false, false, false]
        );
    }

    #[test]
    fn blanking_keeps_every_offset_outside_the_rows_it_blanks() {
        // The recovered rows are reported at their original line and byte
        // offset, which holds only because blanking is whole-row and
        // byte-for-byte the same length.
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        let tree = analyzer
            .get_parser(Language::C)
            .parse(ATTRIBUTE_SWALLOW, None)
            .unwrap();
        let (healed, _, _) = analyzer
            .heal_swallowed_directives(ATTRIBUTE_SWALLOW, &tree, Language::C)
            .expect("the fixture is the case recovery exists for");
        assert_eq!(healed.len(), ATTRIBUTE_SWALLOW.len());
        assert_eq!(
            healed.lines().count(),
            ATTRIBUTE_SWALLOW.lines().count(),
            "a blanked row is still a row"
        );
        for (blanked, original) in healed.lines().zip(ATTRIBUTE_SWALLOW.lines()) {
            assert!(
                blanked == original || blanked.trim().is_empty(),
                "a row was rewritten rather than blanked: {blanked:?}"
            );
            assert_eq!(blanked.len(), original.len());
        }
    }

    #[test]
    fn a_directive_inside_a_comment_or_a_string_is_not_one() {
        // What separates a recovered directive from an invented one. The
        // scan runs on the original source, before any blanking, so the
        // commented-out `#define` is never in code region.
        let source = "#define first(x) x\n\
             /*\n\
              * #define in_block(x) x\n\
              */\n\
             // #define in_line(x) x\n\
             const char *s = \"\\n#define in_string(x) x\";\n\
             #define last(x) x\n";
        let declared = TreeSitterAnalyzer::define_rows_in_code_region(source);
        let mut rows: Vec<u32> = declared.into_iter().collect();
        rows.sort();
        assert_eq!(rows, vec![1, 7]);
    }
}

#[cfg(test)]
mod config_variant_tests {
    //! Which configuration a definition belongs to.
    //!
    //! `include/linux/sched.h` defines `_cond_resched()` four times, one per
    //! configuration; the index keeps one of them and the other three are
    //! invisible, so `cond_resched()` reports a dead end rather than a
    //! missing answer. Reading the arm a definition sits under is the first
    //! half of telling them apart.

    use super::*;

    /// Every arm shape one conditional can have, and a nested one.
    const ARMS: &str = "#if defined(CONFIG_A) || defined(CONFIG_B)\n\
         #define pick(x) one(x)\n\
         #elif defined(DEBUG)\n\
         #define pick(x) two(x)\n\
         #else\n\
         #define pick(x) three(x)\n\
         #endif\n\
         \n\
         #ifndef HAVE_IT\n\
         #define plain(x) x\n\
         #endif\n\
         \n\
         #ifdef CONFIG_OUTER\n\
         #if defined(CONFIG_INNER)\n\
         #define nested(x) x\n\
         #endif\n\
         #endif\n\
         \n\
         #define unguarded(x) x\n";

    /// The guard of every macro the source defines, by name.
    fn guards_in(source: &str) -> Vec<(String, Option<String>)> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_c::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();

        let mut found = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "preproc_function_def" {
                let name = node
                    .child_by_field_name("name")
                    .and_then(|child| child.utf8_text(source.as_bytes()).ok())
                    .unwrap_or_default()
                    .to_string();
                found.push((name, TreeSitterAnalyzer::guard_of(node, source)));
            }
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                stack.push(child);
            }
        }
        found.sort();
        found
    }

    #[test]
    fn each_arm_of_one_conditional_reads_as_its_own_configuration() {
        // The three arms of one `#if` are not three copies of one condition:
        // the second holds only where the first did not, and the third only
        // where neither did. An `#else` states nothing of its own.
        let mut guards: Vec<String> = guards_in(ARMS)
            .into_iter()
            .filter(|(name, _)| name == "pick")
            .filter_map(|(_, guard)| guard)
            .collect();
        guards.sort();
        let mut expected = vec![
            "defined(CONFIG_A) || defined(CONFIG_B)".to_string(),
            "!(defined(CONFIG_A) || defined(CONFIG_B)) && defined(DEBUG)".to_string(),
            "!(defined(CONFIG_A) || defined(CONFIG_B)) && !defined(DEBUG)".to_string(),
        ];
        expected.sort();
        assert_eq!(guards, expected);
    }

    #[test]
    fn the_four_arms_of_cond_resched_read_as_four_configurations() {
        // `include/linux/sched.h`'s shape, and the motivating case: four
        // definitions of one name, one per configuration, of which the index
        // keeps `return 0;` -- so the three that do something, including the
        // route through `__cond_resched()` to `rcu_all_qs()`, are invisible.
        let sched = "#ifdef CONFIG_PREEMPT_DYNAMIC
             #if defined(CONFIG_HAVE_PREEMPT_DYNAMIC_CALL)
             #define _cond_resched(x) static_call_mod(cond_resched)(x)
             #elif defined(CONFIG_HAVE_PREEMPT_DYNAMIC_KEY)
             #define _cond_resched(x) dynamic_cond_resched(x)
             #endif
             #else
             #ifndef CONFIG_PREEMPTION
             #define _cond_resched(x) __cond_resched(x)
             #else
             #define _cond_resched(x) 0
             #endif
             #endif
";
        let mut guards: Vec<String> = guards_in(sched)
            .into_iter()
            .filter_map(|(name, guard)| (name == "_cond_resched").then_some(guard).flatten())
            .collect();
        guards.sort();
        let mut expected = vec![
            "defined(CONFIG_PREEMPT_DYNAMIC) && defined(CONFIG_HAVE_PREEMPT_DYNAMIC_CALL)"
                .to_string(),
            "defined(CONFIG_PREEMPT_DYNAMIC) && !defined(CONFIG_HAVE_PREEMPT_DYNAMIC_CALL) && \
             defined(CONFIG_HAVE_PREEMPT_DYNAMIC_KEY)"
                .replace("             ", "")
                .to_string(),
            "!defined(CONFIG_PREEMPT_DYNAMIC) && !defined(CONFIG_PREEMPTION)".to_string(),
            "!defined(CONFIG_PREEMPT_DYNAMIC) && defined(CONFIG_PREEMPTION)".to_string(),
        ];
        expected.sort();
        assert_eq!(guards.len(), 4, "{guards:?}");
        assert_eq!(guards, expected);
    }

    #[test]
    fn a_definition_no_conditional_holds_has_no_guard() {
        // Most definitions in a tree are this, and a guard on all of them
        // would make the column useless as a discriminator.
        let guards = guards_in(ARMS);
        assert_eq!(
            guards
                .iter()
                .find(|(name, _)| name == "unguarded")
                .map(|(_, guard)| guard.clone()),
            Some(None)
        );
    }

    #[test]
    fn ifndef_is_the_negation_and_nesting_reads_outermost_first() {
        let guards = guards_in(ARMS);
        let guard_of = |wanted: &str| {
            guards
                .iter()
                .find(|(name, _)| name == wanted)
                .and_then(|(_, guard)| guard.clone())
        };
        assert_eq!(guard_of("plain"), Some("!defined(HAVE_IT)".to_string()));
        assert_eq!(
            guard_of("nested"),
            Some("defined(CONFIG_OUTER) && defined(CONFIG_INNER)".to_string())
        );
    }

    #[test]
    fn an_arm_reads_the_same_however_the_file_wraps_it() {
        // Kernel headers wrap long conditions over a continuation, and two
        // definitions under the same arm have to compare equal whether or
        // not the file wrapped it.
        let wrapped = "#if defined(CONFIG_DYNAMIC_DEBUG) || \\\n\
             \t(defined(CONFIG_DYNAMIC_DEBUG_CORE) && defined(DYNAMIC_DEBUG_MODULE))\n\
             #define wrapped(x) x\n\
             #endif\n";
        let inline = "#if defined(CONFIG_DYNAMIC_DEBUG) || (defined(CONFIG_DYNAMIC_DEBUG_CORE) && defined(DYNAMIC_DEBUG_MODULE))\n\
             #define wrapped(x) x\n\
             #endif\n";
        assert_eq!(guards_in(wrapped), guards_in(inline));
    }

    #[test]
    fn an_outer_disjunction_stays_whole_under_an_inner_arm() {
        // `&&` binds tighter than `||`: joined bare, the outer arm's
        // disjunction would absorb the inner condition into its second half.
        let source = "#if !defined(CONFIG_PREEMPTION) || defined(CONFIG_PREEMPT_DYNAMIC)\n\
             #if defined(CONFIG_HAVE_PREEMPT_DYNAMIC_CALL)\n\
             #define inner(x) x\n\
             #endif\n\
             #define outer(x) x\n\
             #endif\n";
        assert_eq!(
            guards_in(source),
            vec![
                (
                    "inner".to_string(),
                    Some(
                        "(!defined(CONFIG_PREEMPTION) || defined(CONFIG_PREEMPT_DYNAMIC)) && \
                         defined(CONFIG_HAVE_PREEMPT_DYNAMIC_CALL)"
                            .to_string()
                    ),
                ),
                (
                    "outer".to_string(),
                    Some(
                        "!defined(CONFIG_PREEMPTION) || defined(CONFIG_PREEMPT_DYNAMIC)"
                            .to_string()
                    ),
                ),
            ]
        );
    }

    /// A row of `_cond_resched` under `guard`, with a body of `body_len`.
    fn arm(guard: Option<&str>, body_len: usize) -> FunctionInfo {
        FunctionInfo {
            name: "_cond_resched".to_string(),
            file_path: "include/linux/sched.h".to_string(),
            git_file_hash: "abc".to_string(),
            line_start: 1,
            line_end: 2,
            return_type: "void".to_string(),
            parameters: Vec::new(),
            body: "x".repeat(body_len),
            calls: None,
            types: None,
            guard: guard.map(str::to_string),
        }
    }

    #[test]
    fn each_arm_survives_with_its_own_guard() {
        // Three arms of one name are three definitions: none of them is
        // collapsed into another, whatever their bodies.
        let analyzer = TreeSitterAnalyzer::new().unwrap();
        let rows = analyzer.deduplicate_functions_within_file(vec![
            arm(Some("defined(CONFIG_A)"), 100),
            arm(Some("!defined(CONFIG_A) && defined(CONFIG_B)"), 50),
            arm(Some("!defined(CONFIG_A) && !defined(CONFIG_B)"), 60),
        ]);
        let mut guards: Vec<Option<String>> = rows.into_iter().map(|row| row.guard).collect();
        guards.sort();
        assert_eq!(
            guards,
            vec![
                Some("!defined(CONFIG_A) && !defined(CONFIG_B)".to_string()),
                Some("!defined(CONFIG_A) && defined(CONFIG_B)".to_string()),
                Some("defined(CONFIG_A)".to_string()),
            ]
        );
    }

    #[test]
    fn within_one_arm_the_old_preference_still_decides() {
        // The key changed which rows are distinct, not which row wins a
        // genuine tie: two definitions under one arm still collapse to the
        // longer one, and file scope is an arm of its own.
        let analyzer = TreeSitterAnalyzer::new().unwrap();
        let mut rows = analyzer.deduplicate_functions_within_file(vec![
            arm(Some("defined(CONFIG_A)"), 10),
            arm(Some("defined(CONFIG_A)"), 30),
            arm(None, 5),
            arm(None, 20),
        ]);
        rows.sort_by_key(|row| row.body.len());
        let kept: Vec<(Option<&str>, usize)> = rows
            .iter()
            .map(|row| (row.guard.as_deref(), row.body.len()))
            .collect();
        assert_eq!(kept, vec![(None, 20), (Some("defined(CONFIG_A)"), 30)]);
    }

    /// `include/linux/sched.h`, the four `_cond_resched()` arms verbatim.
    const COND_RESCHED: &str =
        "#if !defined(CONFIG_PREEMPTION) || defined(CONFIG_PREEMPT_DYNAMIC)\n\
         extern int __cond_resched(void);\n\
         \n\
         #if defined(CONFIG_PREEMPT_DYNAMIC) && defined(CONFIG_HAVE_PREEMPT_DYNAMIC_CALL)\n\
         \n\
         DECLARE_STATIC_CALL(cond_resched, __cond_resched);\n\
         \n\
         static __always_inline int _cond_resched(void)\n\
         {\n\
         \treturn static_call_mod(cond_resched)();\n\
         }\n\
         \n\
         #elif defined(CONFIG_PREEMPT_DYNAMIC) && defined(CONFIG_HAVE_PREEMPT_DYNAMIC_KEY)\n\
         \n\
         extern int dynamic_cond_resched(void);\n\
         \n\
         static __always_inline int _cond_resched(void)\n\
         {\n\
         \treturn dynamic_cond_resched();\n\
         }\n\
         \n\
         #else /* !CONFIG_PREEMPTION */\n\
         \n\
         static inline int _cond_resched(void)\n\
         {\n\
         \treturn __cond_resched();\n\
         }\n\
         \n\
         #endif /* PREEMPT_DYNAMIC && CONFIG_HAVE_PREEMPT_DYNAMIC_CALL */\n\
         \n\
         #else /* CONFIG_PREEMPTION && !CONFIG_PREEMPT_DYNAMIC */\n\
         \n\
         static inline int _cond_resched(void)\n\
         {\n\
         \treturn 0;\n\
         }\n\
         \n\
         #endif /* !CONFIG_PREEMPTION || CONFIG_PREEMPT_DYNAMIC */\n";

    /// `include/linux/dev_printk.h`, the three `dev_dbg()` arms verbatim.
    const DEV_DBG: &str = "#if defined(CONFIG_DYNAMIC_DEBUG) || \\\n\
         \t(defined(CONFIG_DYNAMIC_DEBUG_CORE) && defined(DYNAMIC_DEBUG_MODULE))\n\
         #define dev_dbg(dev, fmt, ...)\t\t\t\t\t\t\\\n\
         \tdynamic_dev_dbg(dev, dev_fmt(fmt), ##__VA_ARGS__)\n\
         #elif defined(DEBUG)\n\
         #define dev_dbg(dev, fmt, ...)\t\t\t\t\t\t\\\n\
         \tdev_printk(KERN_DEBUG, dev, dev_fmt(fmt), ##__VA_ARGS__)\n\
         #else\n\
         #define dev_dbg(dev, fmt, ...)\t\t\t\t\t\t\\\n\
         \tdev_no_printk(KERN_DEBUG, dev, dev_fmt(fmt), ##__VA_ARGS__)\n\
         #endif\n";

    /// Every row the file analysis keeps for `name`, functions and macros
    /// alike, ordered by line.
    fn kept_definitions(source: &str, path: &str, name: &str) -> Vec<FunctionInfo> {
        let mut analyzer = TreeSitterAnalyzer::new().unwrap();
        let analysis = analyzer
            .analyze_source_with_metadata(source, Path::new(path), "testhash", None)
            .unwrap();
        let mut rows: Vec<FunctionInfo> = analysis
            .functions
            .into_iter()
            .chain(analysis.macros)
            .filter(|row| row.name == name)
            .collect();
        rows.sort_by_key(|row| row.line_start);
        rows
    }

    /// What each kept row of `name` does and under which arm, by line.
    fn arms_of(source: &str, path: &str, name: &str) -> Vec<(Option<String>, String)> {
        kept_definitions(source, path, name)
            .into_iter()
            .map(|row| (row.guard, row.body))
            .collect()
    }

    #[test]
    fn cond_resched_keeps_all_four_arms() {
        // The case this exists for: all four arms are indexed, each under
        // its own configuration, so the route through `__cond_resched()` is
        // there to follow instead of a clean dead end at `return 0;`.
        let arms = arms_of(COND_RESCHED, "include/linux/sched.h", "_cond_resched");
        let outer = "(!defined(CONFIG_PREEMPTION) || defined(CONFIG_PREEMPT_DYNAMIC))";
        let call = "defined(CONFIG_PREEMPT_DYNAMIC) && defined(CONFIG_HAVE_PREEMPT_DYNAMIC_CALL)";
        let key = "defined(CONFIG_PREEMPT_DYNAMIC) && defined(CONFIG_HAVE_PREEMPT_DYNAMIC_KEY)";
        let expected = [
            (
                format!("{outer} && {call}"),
                "static_call_mod(cond_resched)",
            ),
            (
                format!("{outer} && !({call}) && {key}"),
                "dynamic_cond_resched()",
            ),
            (
                format!("{outer} && !({call}) && !({key})"),
                "__cond_resched()",
            ),
            (format!("!{outer}"), "return 0;"),
        ];
        assert_eq!(arms.len(), expected.len(), "{arms:#?}");
        for ((guard, body), (want_guard, want_body)) in arms.iter().zip(expected.iter()) {
            assert_eq!(guard.as_deref(), Some(want_guard.as_str()), "{arms:#?}");
            assert!(body.contains(want_body), "{body}");
        }
    }

    #[test]
    fn dev_dbg_keeps_the_dynamic_debug_arm() {
        // Swallowed-directive recovery pointed 16,125 call sites at `dev_dbg`, and the row they reached
        // was the `#else` arm. Every arm is now there, the one a
        // CONFIG_DYNAMIC_DEBUG build uses included.
        let arms = arms_of(DEV_DBG, "include/linux/dev_printk.h", "dev_dbg");
        let bodies: Vec<&str> = arms.iter().map(|(_, body)| body.as_str()).collect();
        assert_eq!(arms.len(), 3, "{arms:#?}");
        assert!(bodies[0].contains("dynamic_dev_dbg("), "{bodies:#?}");
        assert!(bodies[1].contains("dev_printk("), "{bodies:#?}");
        assert!(bodies[2].contains("dev_no_printk("), "{bodies:#?}");
        let guards: HashSet<&Option<String>> = arms.iter().map(|(guard, _)| guard).collect();
        assert_eq!(guards.len(), 3, "{arms:#?}");
    }

    #[test]
    fn a_macro_redefined_under_one_arm_stays_one_row() {
        // `arch/x86/kernel/cpu/bugs.c` redefines `pr_fmt` 19 times at file
        // scope, one per section. Those share an arm, so they are not
        // configurations and must stay collapsed: that is a different defect
        // from the one keying on the arm fixes.
        let source = "#undef pr_fmt\n\
             #define pr_fmt(fmt)\t\"mitigations: \" fmt\n\
             \n\
             #undef pr_fmt\n\
             #define pr_fmt(fmt)\t\"MDS: \" fmt\n\
             \n\
             #undef pr_fmt\n\
             #define pr_fmt(fmt)\t\"Spectre V1 : \" fmt\n";
        let arms = arms_of(source, "arch/x86/kernel/cpu/bugs.c", "pr_fmt");
        assert_eq!(arms.len(), 1, "{arms:#?}");
        assert_eq!(arms[0].0, None);
    }
}
