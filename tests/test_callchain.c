/*
 * Test case to demonstrate call chain functionality
 * This file contains simple functions with clear call relationships
 */

#include <stdio.h>
#include "test_header.h"

// Level 1 functions (leaf functions - don't call others)
int add_numbers(int a, int b) {
    return a + b;
}

int multiply_numbers(int x, int y) {
    return x * y;
}

void print_result(int result) {
    printf("Result: %d\n", result);
}

// Level 2 functions (call level 1 functions)  
int calculate_sum(int a, int b, int c) {
    int sum1 = add_numbers(a, b);
    int sum2 = add_numbers(sum1, c);
    return sum2;
}

int calculate_product(int a, int b, int c) {
    int prod1 = multiply_numbers(a, b);
    int result = multiply_numbers(prod1, c);
    print_result(result);
    return result;
}

// Level 3 functions (call level 2 functions)
void process_math(int x, int y, int z) {
    int sum = calculate_sum(x, y, z);
    int product = calculate_product(x, y, z);
    
    // Also call level 1 directly
    print_result(sum);
    
    // Call level 1 with computed values
    int final = add_numbers(sum, product);
    print_result(final);
}

// Level 4 function (top level - calls level 3)
int main() {
    process_math(2, 3, 4);
    
    // Also call lower levels directly
    int direct_sum = calculate_sum(10, 20, 30);
    print_result(direct_sum);
    
    return 0;
}

/*
 * Expected call relationships:
 *
 * main() calls:
 *   - process_math()
 *   - calculate_sum()
 *   - print_result()
 *
 * process_math() calls:
 *   - calculate_sum()
 *   - calculate_product()
 *   - print_result()
 *   - add_numbers()
 *
 * calculate_sum() calls:
 *   - add_numbers()
 *
 * calculate_product() calls:
 *   - multiply_numbers()
 *   - print_result()
 *
 * Expected called_by relationships:
 *   - add_numbers() called by: [calculate_sum, process_math]
 *   - multiply_numbers() called by: [calculate_product]
 *   - print_result() called by: [calculate_product, process_math, main]
 *   - calculate_sum() called by: [process_math, main]
 *   - calculate_product() called by: [process_math]
 *   - process_math() called by: [main]
 */
