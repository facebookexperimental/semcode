#!/bin/bash

# Test script to demonstrate call chain functionality
# This script indexes the test file and queries call relationships

set -e

echo "=== Call Chain Test ==="
echo "Testing with simple C file: test_callchain.c"
echo

# Clean up any existing test database
rm -rf test_callchain.db

echo "1. Indexing test file..."
./bin/semcode-index --source . --database test_callchain.db --extensions c --max-depth 1 --no-strict-compile-commands

echo
echo "2. Testing function queries..."
echo

# Test individual function lookups
echo "--- Looking up main function ---"
echo "func main" | ./bin/semcode --database test_callchain.db

echo
echo "--- Looking up add_numbers function ---"
echo "func add_numbers" | ./bin/semcode --database test_callchain.db

echo
echo "3. Testing call chain queries..."
echo

# Test callers (who calls this function)
echo "--- Who calls add_numbers? (should be: calculate_sum, process_math) ---"
echo "callers add_numbers" | ./bin/semcode --database test_callchain.db

echo
echo "--- Who calls print_result? (should be: calculate_product, process_math, main) ---"  
echo "callers print_result" | ./bin/semcode --database test_callchain.db

echo
echo "--- Who calls calculate_sum? (should be: process_math, main) ---"
echo "callers calculate_sum" | ./bin/semcode --database test_callchain.db

echo
echo "4. Testing callees (who this function calls)..."
echo

# Test callees (who this function calls)
echo "--- What does main call? (should be: process_math, calculate_sum, print_result) ---"
echo "callees main" | ./bin/semcode --database test_callchain.db

echo
echo "--- What does process_math call? (should be: calculate_sum, calculate_product, print_result, add_numbers) ---"
echo "callees process_math" | ./bin/semcode --database test_callchain.db

echo
echo "--- What does calculate_product call? (should be: multiply_numbers, print_result) ---"
echo "callees calculate_product" | ./bin/semcode --database test_callchain.db

echo
echo "5. Testing full call chain..."
echo

echo "--- Call chain for add_numbers ---"
echo "callchain add_numbers" | ./bin/semcode --database test_callchain.db

echo
echo "--- Call chain for print_result ---"
echo "callchain print_result" | ./bin/semcode --database test_callchain.db

echo
echo "6. Dumping functions to inspect call data..."
echo "dump-functions test_functions.json" | ./bin/semcode --database test_callchain.db

echo
echo "=== Test Complete ==="
echo "Check test_functions.json to see actual call data stored in database"
echo "Expected vs actual call relationships are documented in test_callchain.c"