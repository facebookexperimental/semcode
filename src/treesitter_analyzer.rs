// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;
use streaming_iterator::StreamingIterator;
use tree_sitter::{Parser, Query, QueryCursor, Tree};

use crate::types::{
    FieldInfo, FunctionInfo, GlobalTypeRegistry, MacroInfo, ParameterInfo, TypeInfo,
};
// TemporaryCallRelationship import removed - call relationships are now embedded in function JSON columns
use crate::hash::compute_file_hash;

pub struct TreeSitterAnalyzer {
    parser: Parser,
    function_query: Query,
    comment_query: Query,
    type_query: Query,
    typedef_query: Query,
    macro_query: Query,
    call_query: Query,
}

impl TreeSitterAnalyzer {
    pub fn new() -> Result<Self> {
        let language = tree_sitter_c::LANGUAGE.into();
        let mut parser = Parser::new();
        parser.set_language(&language)?;

        // Query for function definitions - handles both regular and inline functions
        let function_query = Query::new(
            &language,
            r#"
            ; Standard function definitions with bodies
            (function_definition
                declarator: (function_declarator
                    declarator: (identifier) @function_name
                    parameters: (parameter_list) @parameters
                )
                body: (compound_statement) @body
            ) @function

            ; Function pointers with bodies
            (function_definition
                declarator: (pointer_declarator
                    declarator: (function_declarator
                        declarator: (identifier) @function_name
                        parameters: (parameter_list) @parameters
                    )
                )
                body: (compound_statement) @body
            ) @function_ptr

            ; Function declarations without bodies (prototypes only)
            (declaration
                (function_declarator
                    declarator: (identifier) @function_name
                    parameters: (parameter_list) @parameters
                )
            ) @declaration
        "#,
        )?;

        // Query for comments
        let comment_query = Query::new(
            &language,
            r#"
            (comment) @comment
        "#,
        )?;

        // Query for struct/union/enum definitions
        let type_query = Query::new(
            &language,
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
            &language,
            r#"
            (type_definition
                type: (_) @underlying_type
                declarator: (type_identifier) @typedef_name
            ) @typedef
        "#,
        )?;

        // Query for macro definitions
        let macro_query = Query::new(
            &language,
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
            &language,
            r#"
            (call_expression
                function: (identifier) @function_name
            ) @call

            (call_expression
                function: (field_expression
                    field: (field_identifier) @function_name
                )
            ) @method_call
        "#,
        )?;

        Ok(TreeSitterAnalyzer {
            parser,
            function_query,
            comment_query,
            type_query,
            typedef_query,
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

    pub fn analyze_file(
        &mut self,
        file_path: &Path,
    ) -> Result<(Vec<FunctionInfo>, Vec<TypeInfo>, Vec<MacroInfo>)> {
        self.analyze_file_with_source_root(file_path, None)
    }

    pub fn analyze_file_with_source_root(
        &mut self,
        file_path: &Path,
        source_root: Option<&Path>,
    ) -> Result<(Vec<FunctionInfo>, Vec<TypeInfo>, Vec<MacroInfo>)> {
        let source_code = std::fs::read_to_string(file_path)?;
        let tree = self
            .parser
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
        )?);

        // Extract types
        raw_types.extend(self.extract_types(
            &tree,
            &source_code,
            file_path,
            &git_hash,
            source_root,
        )?);

        // Extract typedefs as TypeInfo with kind="typedef" and add to types
        raw_types.extend(self.extract_typedefs_as_typeinfo(
            &tree,
            &source_code,
            file_path,
            &git_hash,
            source_root,
        )?);

        // Extract macros
        raw_macros.extend(self.extract_macros(
            &tree,
            &source_code,
            file_path,
            &git_hash,
            source_root,
        )?);

        // Call relationships are now embedded in function/macro JSON columns during parsing

        // Perform intra-file deduplication (no thread contention since this is per-file)
        let functions = self.deduplicate_functions_within_file(raw_functions);
        let types = self.deduplicate_types_within_file(raw_types);
        let macros = self.deduplicate_macros_within_file(raw_macros);

        Ok((functions, types, macros))
    }

    /// Parse a code snippet and extract function definitions
    pub fn analyze_code_snippet(&mut self, code: &str) -> Result<Vec<FunctionInfo>> {
        let tree = self
            .parser
            .parse(code, None)
            .ok_or_else(|| anyhow::anyhow!("Failed to parse code snippet"))?;

        // Use a dummy path for the snippet and compute hash of the code content
        let dummy_path = Path::new("snippet.c");
        let git_hash = crate::hash::compute_content_hash(code);
        // No git SHA for code snippets
        self.extract_functions(&tree, code, dummy_path, &git_hash, None)
    }

    /// Analyze source code directly with specified file path and git hash
    /// This is used for processing git blob content without writing to disk
    pub fn analyze_source_with_metadata(
        &mut self,
        source_code: &str,
        file_path: &Path,
        git_hash: &str,
        source_root: Option<&Path>,
    ) -> Result<(Vec<FunctionInfo>, Vec<TypeInfo>, Vec<MacroInfo>)> {
        let tree = self.parser.parse(source_code, None).ok_or_else(|| {
            anyhow::anyhow!("Failed to parse source code for: {}", file_path.display())
        })?;

        // Single-pass extraction with optimized call analysis
        let (raw_functions, mut raw_types, raw_macros) = self.extract_all_with_embedded_data(
            &tree,
            source_code,
            file_path,
            git_hash,
            source_root,
        )?;

        // Extract typedefs as TypeInfo with kind="typedef" and add to types
        raw_types.extend(self.extract_typedefs_as_typeinfo(
            &tree,
            source_code,
            file_path,
            git_hash,
            source_root,
        )?);

        // Perform intra-file deduplication (no thread contention since this is per-file)
        let functions = self.deduplicate_functions_within_file(raw_functions);
        let types = self.deduplicate_types_within_file(raw_types);
        let macros = self.deduplicate_macros_within_file(raw_macros);

        // Call relationships are now embedded in function/macro JSON columns

        Ok((functions, types, macros))
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
    ) -> Result<(Vec<FunctionInfo>, Vec<TypeInfo>, Vec<MacroInfo>)> {
        // Single pass: extract all calls once and map them to functions by byte ranges
        let all_calls = self.extract_all_calls_optimized(tree, source_code)?;

        // Extract functions with embedded call data
        let functions = self.extract_functions_with_calls(
            tree,
            source_code,
            file_path,
            git_hash,
            source_root,
            &all_calls,
        )?;

        // Extract types (single traversal as before)
        let types = self.extract_types(tree, source_code, file_path, git_hash, source_root)?;

        // Extract macros with embedded data (single traversal)
        let macros = self.extract_macros_with_embedded_data(
            tree,
            source_code,
            file_path,
            git_hash,
            source_root,
        )?;

        Ok((functions, types, macros))
    }

    /// Extract all calls in a single tree traversal and return with byte positions
    fn extract_all_calls_optimized(
        &self,
        tree: &Tree,
        source_code: &str,
    ) -> Result<Vec<(String, usize, usize)>> {
        let mut calls = Vec::new();
        let mut cursor = QueryCursor::new();
        let mut captures =
            cursor.captures(&self.call_query, tree.root_node(), source_code.as_bytes());

        while let Some((call_match, _)) = captures.next() {
            for capture in call_match.captures {
                let capture_name = &self.call_query.capture_names()[capture.index as usize];

                if *capture_name == "function_name" {
                    let node = capture.node;
                    let function_name = node
                        .utf8_text(source_code.as_bytes())
                        .unwrap_or("")
                        .to_string();

                    // Skip empty function names or obvious non-functions
                    if !function_name.is_empty() && !function_name.chars().all(|c| c.is_numeric()) {
                        calls.push((function_name, node.start_byte(), node.end_byte()));
                    }
                }
            }
        }

        Ok(calls)
    }

    /// Extract functions with pre-computed call data (avoids per-function tree traversals)
    fn extract_functions_with_calls(
        &self,
        tree: &Tree,
        source: &str,
        file_path: &Path,
        git_hash: &str,
        source_root: Option<&Path>,
        all_calls: &[(String, usize, usize)],
    ) -> Result<Vec<FunctionInfo>> {
        let mut cursor = QueryCursor::new();
        let mut captures =
            cursor.captures(&self.function_query, tree.root_node(), source.as_bytes());
        let mut functions = Vec::new();

        // Extract all comments once (used by extract_function_with_comments)
        let comments = self.extract_comments(tree, source)?;

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
                let text = &source[node.byte_range()];
                let capture_name = self.function_query.capture_names()[capture.index as usize];

                match capture_name {
                    "function_name" => {
                        function_name = Some(text.to_string());
                        line_start = node.start_position().row as u32 + 1;
                    }
                    "return_type" => {
                        return_type = Some(text.to_string());
                    }
                    "parameters" => {
                        parameters = self.parse_parameters_from_node(node, source);
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
                    "function" | "function_ptr" => {
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
                                source,
                                &function_name,
                            ));
                        }
                    }
                    "declaration" => {
                        // Function declaration without body - skip call/type extraction
                        // Set minimal bounds for declaration-only functions
                        if function_start_byte == 0 {
                            function_start_byte = node.start_byte();
                            function_end_byte = node.end_byte();
                            if line_end == 0 {
                                line_end = node.end_position().row as u32 + 1;
                            }
                            if line_start == 0 {
                                line_start = node.start_position().row as u32 + 1;
                            }
                        }
                    }
                    _ => {}
                }
            }

            if let Some(name) = function_name {
                // Track which capture patterns were matched to determine if function has body
                let mut matched_patterns = std::collections::HashSet::new();
                for capture in m.captures {
                    let capture_name = self.function_query.capture_names()[capture.index as usize];
                    matched_patterns.insert(capture_name);
                }

                // Fallback parameter extraction if TreeSitter query didn't capture them
                if parameters.is_empty() && !matched_patterns.contains("parameters") {
                    // Try to manually find parameter_list nodes in the function AST
                    for capture in m.captures {
                        let node = capture.node;
                        if self.try_extract_parameters_from_node(node, source, &mut parameters) {
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
                    || matched_patterns.contains("function_ptr");

                // Extract complete function text including top comments
                let complete_body = self.extract_function_with_comments(
                    source,
                    function_start_byte,
                    function_end_byte,
                    line_start,
                    &comments,
                );

                // Only extract calls and types for functions with bodies (not just declarations)
                let (unique_calls, function_types) = if has_body {
                    // Extract calls within this function from pre-computed list (O(m) instead of O(n))
                    let function_calls: Vec<String> = all_calls
                        .iter()
                        .filter(|(_, call_start, call_end)| {
                            *call_start >= function_start_byte && *call_end <= function_end_byte
                        })
                        .map(|(call_name, _, _)| call_name.clone())
                        .collect();

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

                let func = FunctionInfo {
                    name: name.clone(),
                    file_path: self.make_relative_path(file_path, source_root),
                    git_file_hash: git_hash.to_string(),
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

        Ok(functions)
    }

    /// Extract macros with embedded call/type data (optimized)
    fn extract_macros_with_embedded_data(
        &self,
        tree: &Tree,
        source: &str,
        file_path: &Path,
        git_hash: &str,
        source_root: Option<&Path>,
    ) -> Result<Vec<MacroInfo>> {
        // This is the same as extract_macros but named differently for clarity
        // Macros are not as performance-critical as functions since they're fewer in number
        self.extract_macros(tree, source, file_path, git_hash, source_root)
    }

    /// Legacy extract_functions method for backward compatibility with older analyze methods
    fn extract_functions(
        &self,
        tree: &Tree,
        source: &str,
        file_path: &Path,
        git_hash: &str,
        source_root: Option<&Path>,
    ) -> Result<Vec<FunctionInfo>> {
        // Use the optimized approach but without pre-computed calls (for compatibility)
        let all_calls = self.extract_all_calls_optimized(tree, source)?;
        self.extract_functions_with_calls(
            tree,
            source,
            file_path,
            git_hash,
            source_root,
            &all_calls,
        )
    }

    fn extract_comments(&self, tree: &Tree, source: &str) -> Result<Vec<(u32, u32, String)>> {
        let mut cursor = QueryCursor::new();
        let mut captures =
            cursor.captures(&self.comment_query, tree.root_node(), source.as_bytes());
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
        // Find top-of-function comments (comments immediately before the function)
        let mut top_comments = Vec::new();
        let mut current_line = function_start_line.saturating_sub(1);

        // Work backwards to find contiguous comments before the function
        for comment in comments.iter().rev() {
            let (comment_start_line, comment_end_line, comment_text) = comment;

            // Check if this comment is immediately before the current line we're looking at
            if *comment_end_line == current_line || (*comment_end_line + 1) == current_line {
                // Check if the line between comment and function contains only whitespace
                let lines: Vec<&str> = source.lines().collect();
                let mut has_non_whitespace = false;

                for line_idx in *comment_end_line as usize..function_start_line as usize - 1 {
                    if line_idx < lines.len() && !lines[line_idx].trim().is_empty() {
                        // Stop if we hit a non-comment, non-whitespace line (like #include)
                        if !lines[line_idx].trim_start().starts_with("//")
                            && !lines[line_idx].trim_start().starts_with("/*")
                            && !lines[line_idx].trim_start().starts_with("*")
                        {
                            has_non_whitespace = true;
                            break;
                        }
                    }
                }

                if !has_non_whitespace {
                    top_comments.insert(0, comment_text.clone());
                    current_line = comment_start_line.saturating_sub(1);
                } else {
                    break;
                }
            } else if *comment_end_line < current_line {
                break;
            }
        }

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
    ) -> Result<Vec<TypeInfo>> {
        let mut cursor = QueryCursor::new();
        let mut captures = cursor.captures(&self.type_query, tree.root_node(), source.as_bytes());
        let mut types = Vec::new();

        // Extract all comments with their positions
        let comments = self.extract_comments(tree, source)?;

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
                let capture_name = self.type_query.capture_names()[capture.index as usize];

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
        let mut cursor = QueryCursor::new();
        let mut captures =
            cursor.captures(&self.typedef_query, tree.root_node(), source.as_bytes());
        let mut typedef_types = Vec::new();

        while let Some((m, _)) = captures.next() {
            let mut typedef_name = None;
            let mut underlying_type = None;
            let mut line_start = 0;
            let mut typedef_start_byte = 0;
            let mut typedef_end_byte = 0;

            for capture in m.captures {
                let node = capture.node;
                let text = &source[node.byte_range()];
                let capture_name = self.typedef_query.capture_names()[capture.index as usize];

                match capture_name {
                    "typedef_name" => {
                        typedef_name = Some(text.to_string());
                        line_start = node.start_position().row as u32 + 1;
                    }
                    "underlying_type" => {
                        underlying_type = Some(text.to_string());
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
        // Find top-of-type comments (comments immediately before the type definition)
        let mut top_comments = Vec::new();
        let mut current_line = type_start_line.saturating_sub(1);

        // Work backwards to find contiguous comments before the type
        for comment in comments.iter().rev() {
            let (comment_start_line, comment_end_line, comment_text) = comment;

            // Check if this comment is immediately before the current line we're looking at
            if *comment_end_line == current_line || (*comment_end_line + 1) == current_line {
                // Check if the line between comment and type contains only whitespace
                let lines: Vec<&str> = source.lines().collect();
                let mut has_non_whitespace = false;

                for line_idx in *comment_end_line as usize..type_start_line as usize - 1 {
                    if line_idx < lines.len() && !lines[line_idx].trim().is_empty() {
                        // Stop if we hit a non-comment, non-whitespace line (like #include)
                        if !lines[line_idx].trim_start().starts_with("//")
                            && !lines[line_idx].trim_start().starts_with("/*")
                            && !lines[line_idx].trim_start().starts_with("*")
                        {
                            has_non_whitespace = true;
                            break;
                        }
                    }
                }

                if !has_non_whitespace {
                    top_comments.insert(0, comment_text.clone());
                    current_line = comment_start_line.saturating_sub(1);
                } else {
                    break;
                }
            } else if *comment_end_line < current_line {
                break;
            }
        }

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
    ) -> Result<Vec<MacroInfo>> {
        let mut cursor = QueryCursor::new();
        let mut captures = cursor.captures(&self.macro_query, tree.root_node(), source.as_bytes());
        let mut macros = Vec::new();

        while let Some((m, _)) = captures.next() {
            let mut macro_name = None;
            let mut parameters = None;
            let mut definition = String::new();
            let mut line_start = 0;
            let mut is_function_like = false;

            for capture in m.captures {
                let node = capture.node;
                let text = &source[node.byte_range()];
                let capture_name = self.macro_query.capture_names()[capture.index as usize];

                match capture_name {
                    "macro_name" => {
                        macro_name = Some(text.to_string());
                        line_start = node.start_position().row as u32 + 1;
                    }
                    "parameters" => {
                        parameters = Some(self.parse_macro_parameters(text));
                        is_function_like = true;
                    }
                    "value" => {
                        // Skip the value capture since we don't use expansion anymore
                    }
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
                let (macro_calls, macro_types) = self.extract_macro_calls_and_types(&definition);

                let macro_info = MacroInfo {
                    name,
                    file_path: self.make_relative_path(file_path, source_root),
                    git_file_hash: git_hash.to_string(),
                    line_start,
                    is_function_like,
                    parameters,
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
                };

                // Only add function-like macros (consistent with libclang mode)
                if macro_info.is_function_like {
                    macros.push(macro_info);
                }
            }
        }

        Ok(macros)
    }

    fn parse_parameters_from_node(
        &self,
        node: tree_sitter::Node,
        source: &str,
    ) -> Vec<ParameterInfo> {
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
            for _ in 0..asterisks {
                type_parts.push("*");
            }
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
        let mut type_parts = Vec::new();
        let mut param_name = String::new();

        // Walk through the parameter_declaration to extract type and name
        let mut cursor = node.walk();
        cursor.goto_first_child();

        loop {
            let current_node = cursor.node();
            let node_kind = current_node.kind();
            let text = &source[current_node.byte_range()];

            match node_kind {
                // Type specifiers
                "primitive_type" | "type_identifier" | "sized_type_specifier" => {
                    type_parts.push(text.to_string());
                }
                // Storage class specifiers
                "storage_class_specifier" => {
                    type_parts.push(text.to_string());
                }
                // Type qualifiers (const, volatile, etc.)
                "type_qualifier" => {
                    type_parts.push(text.to_string());
                }
                // Struct/union/enum specifiers
                "struct_specifier" | "union_specifier" | "enum_specifier" => {
                    type_parts.push(text.to_string());
                }
                // Declarators (contain the parameter name)
                "identifier" => {
                    // This is likely the parameter name
                    if param_name.is_empty() {
                        param_name = text.to_string();
                    }
                }
                "pointer_declarator" => {
                    // Parse pointer declarator to extract both pointer info and name
                    self.parse_pointer_declarator(
                        current_node,
                        source,
                        &mut type_parts,
                        &mut param_name,
                    );
                }
                "array_declarator" => {
                    // Parse array declarator
                    self.parse_array_declarator(
                        current_node,
                        source,
                        &mut type_parts,
                        &mut param_name,
                    );
                }
                "function_declarator" => {
                    // Function pointer parameter
                    self.parse_function_declarator(
                        current_node,
                        source,
                        &mut type_parts,
                        &mut param_name,
                    );
                }
                // Skip punctuation and whitespace
                "," | "(" | ")" => {}
                _ => {
                    // For any other node types, include the text as part of the type
                    if !text.trim().is_empty() && text != "," && text != "(" && text != ")" {
                        type_parts.push(text.to_string());
                    }
                }
            }

            if !cursor.goto_next_sibling() {
                break;
            }
        }

        // If we have type information, create a ParameterInfo
        if !type_parts.is_empty() || !param_name.is_empty() {
            let type_name = if type_parts.is_empty() {
                "int".to_string() // Default type in C
            } else {
                type_parts.join(" ")
            };

            Some(ParameterInfo {
                name: param_name,
                type_name,
                type_file_path: None, // Will be resolved later in type resolution phase
                type_git_file_hash: None, // Will be resolved later in type resolution phase
            })
        } else {
            None
        }
    }

    fn parse_pointer_declarator(
        &self,
        node: tree_sitter::Node,
        source: &str,
        type_parts: &mut Vec<String>,
        param_name: &mut String,
    ) {
        let mut cursor = node.walk();
        cursor.goto_first_child();

        // Count asterisks and find the identifier
        loop {
            let current_node = cursor.node();
            let text = &source[current_node.byte_range()];

            match current_node.kind() {
                "*" => {
                    type_parts.push("*".to_string());
                }
                "identifier" => {
                    if param_name.is_empty() {
                        *param_name = text.to_string();
                    }
                }
                "pointer_declarator" => {
                    // Nested pointer, recurse
                    self.parse_pointer_declarator(current_node, source, type_parts, param_name);
                }
                _ => {}
            }

            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    fn parse_array_declarator(
        &self,
        node: tree_sitter::Node,
        source: &str,
        type_parts: &mut Vec<String>,
        param_name: &mut String,
    ) {
        let mut cursor = node.walk();
        cursor.goto_first_child();

        loop {
            let current_node = cursor.node();
            let text = &source[current_node.byte_range()];

            match current_node.kind() {
                "identifier" => {
                    if param_name.is_empty() {
                        *param_name = text.to_string();
                    }
                }
                "[" | "]" => {
                    type_parts.push(text.to_string());
                }
                "number_literal" => {
                    type_parts.push(text.to_string());
                }
                _ => {}
            }

            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    fn parse_function_declarator(
        &self,
        node: tree_sitter::Node,
        source: &str,
        type_parts: &mut Vec<String>,
        param_name: &mut String,
    ) {
        // For function pointer parameters, we'll capture the basic structure

        // Extract the identifier if present
        let mut cursor = node.walk();
        cursor.goto_first_child();

        loop {
            let current_node = cursor.node();
            if current_node.kind() == "identifier" && param_name.is_empty() {
                *param_name = source[current_node.byte_range()].to_string();
                break;
            }

            if !cursor.goto_next_sibling() {
                break;
            }
        }

        // For now, just add the function pointer syntax to type
        type_parts.push("(*)".to_string());
    }

    fn parse_struct_members_from_node(
        &self,
        body_node: tree_sitter::Node,
        source: &str,
    ) -> Vec<FieldInfo> {
        let mut members = Vec::new();

        // Walk through all child nodes of the struct/union body
        let mut cursor = body_node.walk();
        for child in body_node.children(&mut cursor) {
            if child.kind() == "field_declaration" {
                if let Some(field_info) = self.parse_field_declaration_node(child, source) {
                    members.extend(field_info);
                }
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
    ) -> Option<Vec<FieldInfo>> {
        let mut fields = Vec::new();

        // Simple approach: just parse the entire field declaration as text
        // This ensures we don't miss any types due to overly restrictive filtering
        let decl_text = source[field_decl_node.byte_range()].trim();

        // Use the string-based parsing which is more reliable
        fields.extend(self.parse_single_field_declaration(decl_text));

        if !fields.is_empty() {
            Some(fields)
        } else {
            None
        }
    }

    fn parse_single_field_declaration(&self, decl_text: &str) -> Vec<FieldInfo> {
        let mut fields = Vec::new();

        // Handle a single field declaration like "int x, y, z;" or "struct foo *ptr;"
        for line in decl_text.lines() {
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

                // Handle comma-separated fields like "int x, y, z;"
                if line.contains(',') {
                    fields.extend(self.parse_comma_separated_fields(line));
                } else {
                    // Single field declaration
                    fields.extend(self.parse_single_field_declaration_line(line));
                }
            }
        }

        fields
    }

    fn parse_comma_separated_fields(&self, line: &str) -> Vec<FieldInfo> {
        let mut fields = Vec::new();

        // Split by comma and parse each field
        let field_parts: Vec<&str> = line.split(',').collect();

        for (i, field_part) in field_parts.iter().enumerate() {
            let field_part = field_part.trim();

            if i == 0 {
                // First field has the complete type
                fields.extend(self.parse_single_field_declaration_line(field_part));
            } else {
                // Subsequent fields share the same base type as the first field
                if let Some(first_field) = fields.first() {
                    let (field_name, field_modifiers) =
                        self.extract_field_name_and_modifiers(field_part);
                    if !field_name.is_empty() {
                        // Extract base type from first field (remove any modifiers)
                        let base_type = self.extract_base_type(&first_field.type_name);
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
            }
        }

        fields
    }

    fn extract_base_type(&self, full_type: &str) -> String {
        // Extract base type by removing pointer/array modifiers from the end
        let parts: Vec<&str> = full_type.split_whitespace().collect();

        // Find where modifiers start (*, [, :)
        for (i, part) in parts.iter().enumerate() {
            if part.contains('*') || part.contains('[') || part.contains(':') {
                return parts[..i].join(" ");
            }
        }

        // If no modifiers found, return the whole type
        full_type.to_string()
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
    ) -> Result<(Vec<FunctionInfo>, Vec<TypeInfo>, Vec<MacroInfo>)> {
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
        if base_name.starts_with("struct ") {
            variants.push(base_name[7..].to_string());
        } else if base_name.starts_with("union ") {
            variants.push(base_name[6..].to_string());
        } else if base_name.starts_with("enum ") {
            variants.push(base_name[5..].to_string());
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

    /// Extract calls and types from macro definition (simple text-based analysis)
    fn extract_macro_calls_and_types(&self, definition: &str) -> (Vec<String>, Vec<String>) {
        let mut calls = Vec::new();
        let mut types = Vec::new();

        // Simple regex-like patterns for function calls: word followed by '('
        let definition_text = definition.trim();
        let words: Vec<&str> = definition_text.split_whitespace().collect();

        for (i, word) in words.iter().enumerate() {
            // Look for function call pattern: identifier followed by (
            if word.ends_with('(') || (i + 1 < words.len() && words[i + 1] == "(") {
                let potential_call = word.trim_end_matches('(');
                if self.is_valid_identifier(potential_call) {
                    calls.push(potential_call.to_string());
                }
            }

            // Look for type usage patterns (struct/union/enum keywords)
            if (*word == "struct" || *word == "union" || *word == "enum")
                && i + 1 < words.len() {
                    let type_name =
                        words[i + 1].trim_end_matches(&['*', '&', ';', ',', ')', '}'][..]);
                    if self.is_valid_identifier(type_name) {
                        types.push(type_name.to_string());
                    }
                }
        }

        // Remove duplicates and sort
        calls.sort();
        calls.dedup();
        types.sort();
        types.dedup();

        (calls, types)
    }

    /// Check if a string is a valid C identifier
    fn is_valid_identifier(&self, s: &str) -> bool {
        !s.is_empty()
            && s.chars().all(|c| c.is_alphanumeric() || c == '_')
            && s.chars()
                .next()
                .is_some_and(|c| c.is_alphabetic() || c == '_')
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
    fn deduplicate_macros_within_file(&self, raw_macros: Vec<MacroInfo>) -> Vec<MacroInfo> {
        use std::collections::HashMap;

        let mut seen_macros = HashMap::<String, MacroInfo>::new();

        for macro_info in raw_macros {
            let key = macro_info.name.clone();

            if let Some(existing) = seen_macros.get(&key) {
                // If definitions are identical, skip
                if existing.definition == macro_info.definition {
                    continue;
                }

                // Prefer longer/more detailed definitions
                let should_replace = macro_info.definition.len() > existing.definition.len();

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
        // Check if this node is a parameter_list
        if node.kind() == "parameter_list" {
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
