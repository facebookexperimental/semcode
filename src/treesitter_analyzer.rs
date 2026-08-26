// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;
use streaming_iterator::StreamingIterator;
use tree_sitter::{Parser, Query, QueryCursor, Tree};

use crate::types::{
    DispatchKind, DispatchSite, FieldInfo, FunctionInfo, GlobalTypeRegistry, MacroParams,
    ParameterInfo, Registration, RegistrationKind, TypeInfo, ARRAY_ELEMENT_MEMBER,
    STATIC_CALL_MEMBER,
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
}

/// What a macro body yields once parsed.
#[derive(Debug, Default)]
struct MacroBodyFacts {
    calls: Vec<String>,
    types: Vec<String>,
    sites: Vec<RawDispatchSite>,
    registrations: Vec<RawRegistration>,
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
        let (extracted_macros, _macro_sites, _macro_registrations) = self.extract_macros(
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
        let macros = self.deduplicate_macros_within_file(raw_macros);

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

        // Single-pass extraction with optimized call analysis
        let FileAnalysis {
            functions: raw_functions,
            types: mut raw_types,
            macros: raw_macros,
            dispatch_sites,
            registrations,
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
        let macros = self.deduplicate_macros_within_file(raw_macros);

        // Call relationships are now embedded in function/macro JSON columns

        Ok(FileAnalysis {
            functions,
            types,
            macros,
            dispatch_sites,
            registrations,
        })
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
        let extraction =
            Self::extract_all_calls_optimized(self.get_queries(language), tree, source_code)?;

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
        let (functions, mut dispatch_sites, mut registrations) =
            self.extract_functions_with_calls(&ctx, &extraction)?;

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
        let (macros, macro_sites, macro_registrations) = self.extract_macros_with_embedded_data(
            tree,
            source_code,
            file_path,
            git_hash,
            source_root,
            language,
        )?;
        dispatch_sites.extend(macro_sites);
        registrations.extend(macro_registrations);

        Ok(FileAnalysis {
            functions,
            types,
            macros,
            dispatch_sites,
            registrations,
        })
    }

    /// Extract all calls in a single tree traversal and return with byte positions
    fn extract_all_calls_optimized(
        queries: &LanguageQueries,
        tree: &Tree,
        source_code: &str,
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
        extraction
            .registrations
            .extend(Self::collect_assignments(tree.root_node(), source_code));

        Self::type_receivers(tree.root_node(), source_code, &mut extraction.member_sites);

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

            // The innermost enclosing scope, not the first one found: a body
            // tree-sitter cannot close spans every function below it, and its
            // declarations would otherwise stand in for the real one's.
            let scope = scopes
                .iter()
                .filter(|(start, end, _)| site.byte_start >= *start && site.byte_start < *end)
                .min_by_key(|(start, end, _)| end - start)
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
                    site.receiver_base_type = Some(base_type);
                    site.receiver_field = Some(fields);
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
        // File scope: an initcall inside a function is something else.
        if node.kind() != "expression_statement" || node.parent()?.kind() != "translation_unit" {
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
        if !Self::is_initcall_macro(level) {
            return None;
        }

        let arguments = call.child_by_field_name("arguments")?;
        let mut cursor = arguments.walk();
        let named: Vec<tree_sitter::Node> = arguments.named_children(&mut cursor).collect();
        let [target] = named[..] else {
            return None;
        };
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
    fn is_initcall_macro(name: &str) -> bool {
        const LEVELS: &[&str] = &[
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
            "module_init",
            "module_exit",
            "subsys_initcall_entry",
        ];
        LEVELS.contains(&name)
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

    /// The name of the innermost function whose extent encloses a byte offset,
    /// or `None` when no function does.
    ///
    /// Innermost, rather than the first whose range covers it: a body the
    /// parser cannot close runs to the end of the file, and `net/core/dev.c`
    /// has one — the `#define` inside `netdev_cmd_to_name`'s switch leaves its
    /// node spanning the 11,000 lines below it. Attributing in file order gave
    /// that name to every dispatch site in the rest of the file, so a caller
    /// query for anything reached through `packet_type::func` answered with a
    /// function that only stringifies notifier commands.
    fn innermost_function(spans: &[(usize, usize, String)], byte_start: usize) -> Option<&str> {
        spans
            .iter()
            .filter(|(start, end, _)| byte_start >= *start && byte_start < *end)
            .min_by_key(|(start, end, _)| end - start)
            .map(|(_, _, name)| name.as_str())
    }

    /// Extract functions with pre-computed call data (avoids per-function tree traversals)
    fn extract_functions_with_calls(
        &self,
        ctx: &ExtractionContext,
        extraction: &CallExtraction,
    ) -> Result<(Vec<FunctionInfo>, Vec<DispatchSite>, Vec<Registration>)> {
        let mut dispatch_sites: Vec<DispatchSite> = Vec::new();
        let mut registrations: Vec<Registration> = Vec::new();
        // Where every function the query matched begins and ends. Sites and
        // registrations are attributed once the whole file is known, so that
        // the innermost enclosing function claims each one.
        let mut function_spans: Vec<(usize, usize, String)> = Vec::new();
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
                    }
                    "function" | "function_ptr" | "function_ptr2" => {
                        // All function types with bodies - process fully
                        function_start_byte = node.start_byte();
                        function_end_byte = node.end_byte();
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
                    let pointers: std::collections::HashMap<&str, &PointerVar> = extraction
                        .pointer_vars
                        .iter()
                        .filter(|var| {
                            var.byte_start >= function_start_byte
                                && var.byte_start < function_end_byte
                        })
                        .map(|var| (var.name.as_str(), var))
                        .collect();

                    let mut function_calls: Vec<String> = Vec::new();
                    for (call_name, call_start, call_end) in &extraction.calls {
                        if *call_start < function_start_byte || *call_end > function_end_byte {
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
                            None => function_calls.push(call_name.clone()),
                        }
                    }

                    // Remove duplicates and sort
                    let mut unique_calls = function_calls;
                    unique_calls.sort();
                    unique_calls.dedup();

                    // Extract types used by this function (parameters and return type)
                    let default_void = "void".to_string();
                    let return_type_str = return_type.as_ref().unwrap_or(&default_void);
                    let function_types = self.extract_function_types(return_type_str, &parameters);

                    (unique_calls, function_types)
                } else {
                    // For declarations only, don't extract calls or types from body
                    (Vec::new(), Vec::new())
                };

                if function_end_byte > function_start_byte {
                    function_spans.push((function_start_byte, function_end_byte, name.clone()));
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

        // Attribute each one now that every function's extent is known. An
        // empty name means no function encloses it: most ops tables sit at file
        // scope, and Python module level and class bodies run code there too.
        //
        // The function query yields several captures per function, so a site
        // can be reached more than once; a site is one row regardless.
        let relative_path = self.make_relative_path(ctx.file_path, ctx.source_root);

        let mut seen_registrations: std::collections::HashSet<usize> = Default::default();
        for raw in extraction.registrations.iter() {
            if !seen_registrations.insert(raw.byte_start) {
                continue;
            }
            let enclosing =
                Self::innermost_function(&function_spans, raw.byte_start).unwrap_or_default();
            registrations.push(raw.attribute(enclosing, &relative_path, ctx.git_hash));
        }

        let mut seen_sites: std::collections::HashSet<usize> = Default::default();
        for raw in extraction
            .member_sites
            .iter()
            .chain(pointer_call_sites.iter())
        {
            if !seen_sites.insert(raw.byte_start) {
                continue;
            }
            let enclosing =
                Self::innermost_function(&function_spans, raw.byte_start).unwrap_or_default();
            dispatch_sites.push(raw.attribute(enclosing, &relative_path, ctx.git_hash));
        }

        Ok((functions, dispatch_sites, registrations))
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
    ) -> Result<(Vec<FunctionInfo>, Vec<DispatchSite>, Vec<Registration>)> {
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
            Self::extract_all_calls_optimized(self.get_queries(language), tree, source)?;
        let ctx = ExtractionContext {
            tree,
            source,
            file_path,
            git_hash,
            source_root,
            language,
        };
        let (functions, _dispatch_sites, _registrations) =
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
                        members = self.parse_struct_members_from_node(node, source);
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
    ) -> Result<(Vec<FunctionInfo>, Vec<DispatchSite>, Vec<Registration>)> {
        // Macro bodies are re-parsed as C; one parser serves the whole file.
        let mut body_parser = tree_sitter::Parser::new();
        body_parser.set_language(&tree_sitter_c::LANGUAGE.into())?;
        let mut dispatch_sites: Vec<DispatchSite> = Vec::new();
        let mut registrations: Vec<Registration> = Vec::new();
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
                        }
                        for registration in &mut facts.registrations {
                            registration.byte_start += body_start;
                            registration.line = body_line + registration.line.saturating_sub(1);
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

        Ok((macros, dispatch_sites, registrations))
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
                    kind if kind.starts_with("preproc_") => stack.push(child),
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
    ) -> Vec<FieldInfo> {
        match body_node.kind() {
            "error_set_declaration" => return Self::parse_zig_error_members(body_node, source),
            "struct_declaration" | "enum_declaration" | "union_declaration"
            | "opaque_declaration" => {
                return Self::parse_zig_container_fields(body_node, source);
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
        let mut sites = match Self::extract_all_calls_optimized(queries, &tree, &wrapped) {
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

        MacroBodyFacts {
            calls,
            types,
            sites,
            registrations,
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

    /// Deduplicate functions within a single file (no threading issues)
    /// Prefers definitions over declarations, longer bodies over shorter ones
    fn deduplicate_functions_within_file(
        &self,
        raw_functions: Vec<FunctionInfo>,
    ) -> Vec<FunctionInfo> {
        use std::collections::HashMap;

        let mut seen_functions = HashMap::<String, FunctionInfo>::new();

        for func in raw_functions {
            let key = func.name.clone();

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

    /// Deduplicate macros within a single file  
    /// Simple deduplication by name - macros should be unique within a file anyway
    fn deduplicate_macros_within_file(&self, raw_macros: Vec<FunctionInfo>) -> Vec<FunctionInfo> {
        use std::collections::HashMap;

        let mut seen_macros = HashMap::<String, FunctionInfo>::new();

        for macro_info in raw_macros {
            let key = macro_info.name.clone();

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
    fn a_table_held_in_a_field_is_recorded_without_inventing_a_container() {
        // `chip->get_delay[i]()` dispatches through an array a struct holds.
        // The site is worth recording; the container is not knowable from
        // the array name, because there is not one.
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
        assert_eq!(
            site.receiver_type, None,
            "a field is not a table name: {site:?}"
        );
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
    fn a_site_belongs_to_the_innermost_function_that_encloses_it() {
        // The spans net/core/dev.c produces. The `#define` inside
        // netdev_cmd_to_name's switch leaves tree-sitter unable to close the
        // body, so its extent runs from line 1860 to the end of the file and
        // covers every function below. Claiming sites in file order gave that
        // name to every dispatch site in the rest of dev.c, so `callers` for
        // anything reached through packet_type::func answered with a function
        // that only stringifies notifier commands.
        let spans = vec![
            (100, 10_000, "netdev_cmd_to_name".to_string()),
            (500, 600, "deliver_skb".to_string()),
            (700, 800, "dev_queue_xmit_nit".to_string()),
        ];

        assert_eq!(
            TreeSitterAnalyzer::innermost_function(&spans, 550),
            Some("deliver_skb")
        );
        assert_eq!(
            TreeSitterAnalyzer::innermost_function(&spans, 750),
            Some("dev_queue_xmit_nit")
        );

        // The wide one still answers where nothing narrower encloses the site.
        assert_eq!(
            TreeSitterAnalyzer::innermost_function(&spans, 200),
            Some("netdev_cmd_to_name")
        );

        // Nothing when no function encloses it: a file-scope ops table, or a
        // Python module-level call.
        assert_eq!(TreeSitterAnalyzer::innermost_function(&spans, 20), None);
        assert_eq!(TreeSitterAnalyzer::innermost_function(&spans, 20_000), None);
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
