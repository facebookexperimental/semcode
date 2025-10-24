#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.8"
# dependencies = [
#     "tree-sitter>=0.23.0",
#     "tree-sitter-c>=0.23.0",
# ]
# ///
"""
Analyze Linux kernel C code to determine optimal SmallVec sizes.

This script parses C files using tree-sitter and collects statistics on:
1. Number of parameters per function
2. Number of fields per struct/union/enum

Usage:
    uv run analyze_kernel_stats.py /path/to/linux

    or:

    ./analyze_kernel_stats.py /path/to/linux
"""

import sys
import os
from pathlib import Path
from collections import Counter
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

def analyze_file(file_path, parser):
    """Analyze a single C file and return statistics."""
    try:
        with open(file_path, 'rb') as f:
            source_code = f.read()

        tree = parser.parse(source_code)
        root_node = tree.root_node

        param_counts = []
        field_counts = []

        # Walk the tree to find functions and types
        def walk_tree(node):
            # Function definitions
            if node.type == 'function_definition':
                for child in node.children:
                    if child.type == 'function_declarator':
                        for subchild in child.children:
                            if subchild.type == 'parameter_list':
                                count = count_parameters(subchild, source_code)
                                param_counts.append(count)

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
                for child in node.children:
                    if child.type == 'field_declaration_list':
                        count = count_fields(child, source_code)
                        field_counts.append(count)

            # Enum definitions
            elif node.type == 'enum_specifier':
                for child in node.children:
                    if child.type == 'enumerator_list':
                        count = count_fields(child, source_code)
                        field_counts.append(count)

            # Recurse
            for child in node.children:
                walk_tree(child)

        walk_tree(root_node)
        return param_counts, field_counts

    except Exception as e:
        # Skip files that can't be parsed
        return [], []

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

    all_param_counts = []
    all_field_counts = []

    files_processed = 0
    for file_path in get_c_files(kernel_path):
        param_counts, field_counts = analyze_file(file_path, parser)
        all_param_counts.extend(param_counts)
        all_field_counts.extend(field_counts)

        files_processed += 1
        if files_processed % 1000 == 0:
            print(f"Processed {files_processed} files... "
                  f"({len(all_param_counts)} functions, {len(all_field_counts)} types)")

    print(f"\n{'='*70}")
    print(f"Total files processed: {files_processed}")
    print(f"Total functions found: {len(all_param_counts)}")
    print(f"Total types found: {len(all_field_counts)}")
    print(f"{'='*70}\n")

    # Parameter statistics
    print("FUNCTION PARAMETER COUNTS:")
    print("-" * 70)
    if all_param_counts:
        param_counter = Counter(all_param_counts)
        print(f"Mean: {sum(all_param_counts) / len(all_param_counts):.2f}")
        print(f"Max: {max(all_param_counts)}")

        print("\nDistribution (most common):")
        for count, freq in param_counter.most_common(15):
            percentage = (freq / len(all_param_counts)) * 100
            bar = '█' * int(percentage)
            print(f"  {count:2d} params: {freq:7d} ({percentage:5.2f}%) {bar}")

        print("\nPercentiles:")
        percentiles = calculate_percentiles(all_param_counts)
        for p, value in percentiles.items():
            print(f"  {p:3d}th percentile: {value}")

        # Calculate coverage for different SmallVec sizes
        print("\nCoverage by SmallVec size:")
        for size in [2, 3, 4, 5, 6, 8, 10]:
            covered = sum(1 for c in all_param_counts if c <= size)
            percentage = (covered / len(all_param_counts)) * 100
            print(f"  Size {size:2d}: {percentage:5.2f}% of functions fit on stack")

    print(f"\n{'='*70}\n")

    # Field statistics
    print("STRUCT/UNION/ENUM FIELD COUNTS:")
    print("-" * 70)
    if all_field_counts:
        field_counter = Counter(all_field_counts)
        print(f"Mean: {sum(all_field_counts) / len(all_field_counts):.2f}")
        print(f"Max: {max(all_field_counts)}")

        print("\nDistribution (most common):")
        for count, freq in field_counter.most_common(15):
            percentage = (freq / len(all_field_counts)) * 100
            bar = '█' * int(percentage)
            print(f"  {count:2d} fields: {freq:7d} ({percentage:5.2f}%) {bar}")

        print("\nPercentiles:")
        percentiles = calculate_percentiles(all_field_counts)
        for p, value in percentiles.items():
            print(f"  {p:3d}th percentile: {value}")

        # Calculate coverage for different SmallVec sizes
        print("\nCoverage by SmallVec size:")
        for size in [4, 6, 8, 10, 12, 16, 20]:
            covered = sum(1 for c in all_field_counts if c <= size)
            percentage = (covered / len(all_field_counts)) * 100
            print(f"  Size {size:2d}: {percentage:5.2f}% of types fit on stack")

    print(f"\n{'='*70}\n")

    # Recommendations
    print("RECOMMENDATIONS:")
    print("-" * 70)

    if all_param_counts:
        p90 = calculate_percentiles(all_param_counts, [90])[90]
        print(f"Function parameters: SmallVec<[ParameterInfo; {p90}]>")
        print(f"  (covers 90% of functions)")

    if all_field_counts:
        p90 = calculate_percentiles(all_field_counts, [90])[90]
        print(f"Struct/union/enum fields: SmallVec<[FieldInfo; {p90}]>")
        print(f"  (covers 90% of types)")

    print()

if __name__ == '__main__':
    main()
