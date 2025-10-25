#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.8"
# dependencies = [
#     "tree-sitter>=0.23.0",
#     "tree-sitter-c>=0.23.0",
# ]
# ///
"""
Analyze Linux kernel C code to determine optimal SmallVec sizes and Vec allocation patterns.

This script parses C files using tree-sitter and collects statistics on:
1. Number of parameters per function (for SmallVec<[ParameterInfo; N]>)
2. Number of fields per struct/union/enum (for SmallVec<[FieldInfo; N]>)
3. Number of function calls per function (for calls Vec)
4. Number of types per function (for types Vec)
5. Number of member types per struct (for type references)
6. Number of comments per file section (for comment Vec)
7. Macro parameter counts (for macro parameter Vec)

Usage:
    uv run analyze_kernel_stats.py /path/to/linux

    or:

    ./analyze_kernel_stats.py /path/to/linux
"""

import sys
import os
from pathlib import Path
from collections import Counter, defaultdict
import tree_sitter_c as tsc
from tree_sitter import Language, Parser, Query

def get_c_files(root_path):
    """Find all .c and .h files in the directory."""
    root = Path(root_path)
    for ext in ['*.c', '*.h']:
        yield from root.rglob(ext)

def count_parameters(node, source_code):
    """Count parameters in a parameter_list node."""
    if node.type != 'parameter_list':
        return 0

    # Count parameter_declaration children
    count = 0
    for child in node.children:
        if child.type == 'parameter_declaration':
            count += 1
        # Handle variadic parameters (...)
        elif child.type == '...':
            count += 1

    return count

def count_fields(node, source_code):
    """Count fields in a struct/union/enum body."""
    if node.type not in ['field_declaration_list', 'enumerator_list']:
        return 0

    count = 0
    for child in node.children:
        if child.type == 'field_declaration':
            # A field_declaration can declare multiple fields: "int a, b, c;"
            # Count the number of declarators
            declarators = [c for c in child.children if c.type in ['field_identifier', 'pointer_declarator', 'array_declarator']]
            count += max(1, len(declarators))
        elif child.type == 'enumerator':
            count += 1

    return count

def count_function_calls(node, source_code):
    """Count call_expression nodes within a function."""
    count = 0
    def walk(n):
        nonlocal count
        if n.type == 'call_expression':
            count += 1
        for child in n.children:
            walk(child)
    walk(node)
    return count

def count_type_references(node, source_code):
    """Count struct/union/enum type references in a function or type definition."""
    type_refs = set()

    def walk(n):
        if n.type in ['struct_specifier', 'union_specifier', 'enum_specifier', 'type_identifier']:
            text = source_code[n.start_byte:n.end_byte]
            if text and not text.startswith('__'):  # Skip compiler built-ins
                type_refs.add(text)
        for child in n.children:
            walk(child)

    walk(node)
    # Filter out primitives
    primitives = {'void', 'char', 'short', 'int', 'long', 'float', 'double',
                  'unsigned', 'signed', 'bool', '_Bool'}
    return len([t for t in type_refs if t not in primitives])

def count_comments_before(node, all_comments, source_code):
    """Count comments immediately before a function/type (for top_comments Vec)."""
    function_line = node.start_point[0] + 1
    comment_count = 0

    # Count contiguous comments before the function
    for comment_line, _ in sorted(all_comments, reverse=True):
        if comment_line < function_line and comment_line >= function_line - 10:  # Within 10 lines
            comment_count += 1
        elif comment_line < function_line - 10:
            break

    return comment_count

def analyze_file(file_path, parser):
    """Analyze a single C file and return statistics."""
    try:
        with open(file_path, 'rb') as f:
            source_code = f.read()

        tree = parser.parse(source_code)
        root_node = tree.root_node

        # Statistics collectors
        param_counts = []
        field_counts = []
        call_counts = []
        function_type_counts = []
        struct_type_counts = []
        comment_counts = []
        macro_param_counts = []

        # Size tracking (bytes)
        function_sizes = []  # Bytes per function definition
        type_sizes = []      # Bytes per type definition
        macro_sizes = []     # Bytes per macro definition

        # Collect all comments first
        all_comments = []
        def find_comments(node):
            if node.type == 'comment':
                line = node.start_point[0] + 1
                all_comments.append((line, node))
            for child in node.children:
                find_comments(child)
        find_comments(root_node)

        # Walk the tree to find functions, types, and macros
        def walk_tree(node):
            # Function definitions with bodies
            if node.type == 'function_definition':
                # Track function size
                function_size = node.end_byte - node.start_byte
                function_sizes.append(function_size)

                # Count parameters
                for child in node.children:
                    if child.type == 'function_declarator' or child.type == 'pointer_declarator':
                        for subchild in child.children:
                            if subchild.type == 'parameter_list':
                                count = count_parameters(subchild, source_code)
                                param_counts.append(count)
                            elif subchild.type == 'function_declarator':
                                for subsubchild in subchild.children:
                                    if subsubchild.type == 'parameter_list':
                                        count = count_parameters(subsubchild, source_code)
                                        param_counts.append(count)

                # Count function calls in body
                call_count = count_function_calls(node, source_code)
                call_counts.append(call_count)

                # Count type references
                type_count = count_type_references(node, source_code)
                function_type_counts.append(type_count)

                # Count top comments
                comment_count = count_comments_before(node, all_comments, source_code)
                comment_counts.append(comment_count)

            # Function declarations (prototypes)
            elif node.type == 'declaration':
                for child in node.children:
                    if child.type == 'function_declarator':
                        for subchild in child.children:
                            if subchild.type == 'parameter_list':
                                count = count_parameters(subchild, source_code)
                                param_counts.append(count)

            # Struct/union definitions
            elif node.type in ['struct_specifier', 'union_specifier']:
                # Track type size
                type_size = node.end_byte - node.start_byte
                type_sizes.append(type_size)

                for child in node.children:
                    if child.type == 'field_declaration_list':
                        count = count_fields(child, source_code)
                        field_counts.append(count)

                        # Count type references in struct
                        type_count = count_type_references(child, source_code)
                        struct_type_counts.append(type_count)

            # Enum definitions
            elif node.type == 'enum_specifier':
                # Track enum size
                type_size = node.end_byte - node.start_byte
                type_sizes.append(type_size)

                for child in node.children:
                    if child.type == 'enumerator_list':
                        count = count_fields(child, source_code)
                        field_counts.append(count)

            # Macro definitions (function-like)
            elif node.type == 'preproc_function_def':
                # Track macro size
                macro_size = node.end_byte - node.start_byte
                macro_sizes.append(macro_size)

                for child in node.children:
                    if child.type == 'preproc_params':
                        # Count parameters in macro
                        param_count = len([c for c in child.children if c.type == 'identifier'])
                        macro_param_counts.append(param_count)

            # Recurse
            for child in node.children:
                walk_tree(child)

        walk_tree(root_node)
        return {
            'params': param_counts,
            'fields': field_counts,
            'calls': call_counts,
            'function_types': function_type_counts,
            'struct_types': struct_type_counts,
            'comments': comment_counts,
            'macro_params': macro_param_counts,
            'function_sizes': function_sizes,
            'type_sizes': type_sizes,
            'macro_sizes': macro_sizes,
        }

    except Exception as e:
        # Skip files that can't be parsed
        return {
            'params': [],
            'fields': [],
            'calls': [],
            'function_types': [],
            'struct_types': [],
            'comments': [],
            'macro_params': [],
            'function_sizes': [],
            'type_sizes': [],
            'macro_sizes': [],
        }

def calculate_percentiles(data, percentiles=[50, 75, 90, 95, 99]):
    """Calculate percentiles from a sorted list."""
    if not data:
        return {p: 0 for p in percentiles}

    sorted_data = sorted(data)
    n = len(sorted_data)

    result = {}
    for p in percentiles:
        index = int(n * p / 100)
        if index >= n:
            index = n - 1
        result[p] = sorted_data[index]

    return result

def print_statistics(name, data, smallvec_sizes, unit="items"):
    """Print detailed statistics for a dataset."""
    if not data:
        print(f"  No data collected")
        return

    counter = Counter(data)
    mean = sum(data) / len(data)
    max_val = max(data)

    print(f"  Mean: {mean:.2f} {unit}")
    print(f"  Max: {max_val} {unit}")
    print(f"  Total samples: {len(data)}")

    print(f"\n  Distribution (most common):")
    for count, freq in counter.most_common(15):
        percentage = (freq / len(data)) * 100
        bar = '█' * min(int(percentage), 50)
        print(f"    {count:2d} {unit}: {freq:7d} ({percentage:5.2f}%) {bar}")

    print(f"\n  Percentiles:")
    percentiles = calculate_percentiles(data)
    for p, value in percentiles.items():
        print(f"    {p:3d}th percentile: {value} {unit}")

    print(f"\n  SmallVec Coverage Analysis:")
    for size in smallvec_sizes:
        covered = sum(1 for c in data if c <= size)
        percentage = (covered / len(data)) * 100
        heap_allocs = len(data) - covered
        print(f"    Size {size:2d}: {percentage:5.2f}% on stack, {heap_allocs:7d} heap allocations")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path-to-linux-kernel>")
        sys.exit(1)

    kernel_path = sys.argv[1]
    if not os.path.isdir(kernel_path):
        print(f"Error: {kernel_path} is not a directory")
        sys.exit(1)

    print(f"Analyzing C files in {kernel_path}...")
    print("This may take several minutes...\n")

    # Initialize tree-sitter parser
    C_LANGUAGE = Language(tsc.language())
    parser = Parser(C_LANGUAGE)

    # Aggregate statistics
    all_stats = {
        'params': [],
        'fields': [],
        'calls': [],
        'function_types': [],
        'struct_types': [],
        'comments': [],
        'macro_params': [],
        'function_sizes': [],
        'type_sizes': [],
        'macro_sizes': [],
    }

    files_processed = 0
    for file_path in get_c_files(kernel_path):
        stats = analyze_file(file_path, parser)
        for key in all_stats:
            all_stats[key].extend(stats[key])

        files_processed += 1
        if files_processed % 1000 == 0:
            print(f"Processed {files_processed} files... "
                  f"({len(all_stats['params'])} functions, "
                  f"{len(all_stats['fields'])} types)")

    print(f"\n{'='*70}")
    print(f"Total files processed: {files_processed}")
    print(f"{'='*70}\n")

    # Print detailed statistics for each category
    print("=" * 70)
    print("1. FUNCTION PARAMETER COUNTS")
    print("   (for SmallVec<[ParameterInfo; N]>)")
    print("=" * 70)
    print_statistics("Parameters", all_stats['params'], [2, 3, 4, 5, 6, 8, 10, 12], "params")

    print(f"\n{'='*70}")
    print("2. STRUCT/UNION/ENUM FIELD COUNTS")
    print("   (for SmallVec<[FieldInfo; N]>)")
    print("=" * 70)
    print_statistics("Fields", all_stats['fields'], [4, 6, 8, 10, 12, 16, 20, 24], "fields")

    print(f"\n{'='*70}")
    print("3. FUNCTION CALL COUNTS PER FUNCTION")
    print("   (for calls: Vec<String> in extract_functions_with_calls)")
    print("=" * 70)
    print_statistics("Function Calls", all_stats['calls'], [4, 8, 12, 16, 20, 24, 32], "calls")

    print(f"\n{'='*70}")
    print("4. TYPE REFERENCES PER FUNCTION")
    print("   (for types: Vec<String> in extract_function_types)")
    print("=" * 70)
    print_statistics("Type References", all_stats['function_types'], [2, 4, 6, 8, 10, 12], "types")

    print(f"\n{'='*70}")
    print("5. TYPE REFERENCES PER STRUCT")
    print("   (for types: Vec<String> in extract_type_referenced_types)")
    print("=" * 70)
    print_statistics("Struct Type Refs", all_stats['struct_types'], [2, 4, 6, 8, 10, 12, 16], "types")

    print(f"\n{'='*70}")
    print("6. TOP COMMENTS PER FUNCTION/TYPE")
    print("   (for top_comments: Vec<String> in extract_function_with_comments)")
    print("=" * 70)
    print_statistics("Comments", all_stats['comments'], [1, 2, 3, 4, 5, 6, 8], "comments")

    print(f"\n{'='*70}")
    print("7. MACRO PARAMETER COUNTS")
    print("   (for parameters: Vec<String> in parse_macro_parameters)")
    print("=" * 70)
    print_statistics("Macro Parameters", all_stats['macro_params'], [1, 2, 3, 4, 5, 6, 8], "params")

    print(f"\n{'='*70}")
    print("8. FUNCTION DEFINITION SIZES")
    print("   (for estimating Vec pre-allocation based on file size)")
    print("=" * 70)
    if all_stats['function_sizes']:
        mean_func_size = sum(all_stats['function_sizes']) / len(all_stats['function_sizes'])
        median_func_size = calculate_percentiles(all_stats['function_sizes'], [50])[50]
        print(f"  Mean function size: {mean_func_size:.0f} bytes")
        print(f"  Median function size: {median_func_size} bytes")
        print(f"  Total functions: {len(all_stats['function_sizes'])}")

    print(f"\n{'='*70}")
    print("9. TYPE DEFINITION SIZES")
    print("   (for estimating Vec pre-allocation based on file size)")
    print("=" * 70)
    if all_stats['type_sizes']:
        mean_type_size = sum(all_stats['type_sizes']) / len(all_stats['type_sizes'])
        median_type_size = calculate_percentiles(all_stats['type_sizes'], [50])[50]
        print(f"  Mean type size: {mean_type_size:.0f} bytes")
        print(f"  Median type size: {median_type_size} bytes")
        print(f"  Total types: {len(all_stats['type_sizes'])}")

    print(f"\n{'='*70}")
    print("10. MACRO DEFINITION SIZES")
    print("   (for estimating Vec pre-allocation based on file size)")
    print("=" * 70)
    if all_stats['macro_sizes']:
        mean_macro_size = sum(all_stats['macro_sizes']) / len(all_stats['macro_sizes'])
        median_macro_size = calculate_percentiles(all_stats['macro_sizes'], [50])[50]
        print(f"  Mean macro size: {mean_macro_size:.0f} bytes")
        print(f"  Median macro size: {median_macro_size} bytes")
        print(f"  Total macros: {len(all_stats['macro_sizes'])}")

    print(f"\n{'='*70}")
    print("FINAL RECOMMENDATIONS")
    print("=" * 70)

    recommendations = []

    if all_stats['params']:
        p90 = calculate_percentiles(all_stats['params'], [90])[90]
        p95 = calculate_percentiles(all_stats['params'], [95])[95]
        recommendations.append(f"Function parameters: SmallVec<[ParameterInfo; {p90}]> (90% coverage, {p95} for 95%)")

    if all_stats['fields']:
        p90 = calculate_percentiles(all_stats['fields'], [90])[90]
        p95 = calculate_percentiles(all_stats['fields'], [95])[95]
        recommendations.append(f"Struct/union/enum fields: SmallVec<[FieldInfo; {p90}]> (90% coverage, {p95} for 95%)")

    if all_stats['calls']:
        p75 = calculate_percentiles(all_stats['calls'], [75])[75]
        p90 = calculate_percentiles(all_stats['calls'], [90])[90]
        recommendations.append(f"Function calls: Vec::with_capacity({p75}) for 75% coverage ({p90} for 90%)")

    if all_stats['function_types']:
        p75 = calculate_percentiles(all_stats['function_types'], [75])[75]
        p90 = calculate_percentiles(all_stats['function_types'], [90])[90]
        recommendations.append(f"Function type refs: Vec::with_capacity({p75}) for 75% coverage ({p90} for 90%)")

    if all_stats['struct_types']:
        p75 = calculate_percentiles(all_stats['struct_types'], [75])[75]
        p90 = calculate_percentiles(all_stats['struct_types'], [90])[90]
        recommendations.append(f"Struct type refs: Vec::with_capacity({p75}) for 75% coverage ({p90} for 90%)")

    if all_stats['comments']:
        p75 = calculate_percentiles(all_stats['comments'], [75])[75]
        p90 = calculate_percentiles(all_stats['comments'], [90])[90]
        recommendations.append(f"Top comments: Vec::with_capacity({p75}) for 75% coverage ({p90} for 90%)")

    if all_stats['macro_params']:
        p90 = calculate_percentiles(all_stats['macro_params'], [90])[90]
        recommendations.append(f"Macro parameters: Vec::with_capacity({p90}) (90% coverage)")

    # Add size-based recommendations
    if all_stats['function_sizes']:
        mean_func_size = sum(all_stats['function_sizes']) / len(all_stats['function_sizes'])
        recommendations.append(f"Function sizes: ~{mean_func_size:.0f} bytes average (use for file_size / BYTES_PER_FUNCTION)")

    if all_stats['type_sizes']:
        mean_type_size = sum(all_stats['type_sizes']) / len(all_stats['type_sizes'])
        recommendations.append(f"Type sizes: ~{mean_type_size:.0f} bytes average (use for file_size / BYTES_PER_TYPE)")

    if all_stats['macro_sizes']:
        mean_macro_size = sum(all_stats['macro_sizes']) / len(all_stats['macro_sizes'])
        recommendations.append(f"Macro sizes: ~{mean_macro_size:.0f} bytes average (use for file_size / BYTES_PER_MACRO)")

    for rec in recommendations:
        print(f"  • {rec}")

    print()

if __name__ == '__main__':
    main()
