// SPDX-License-Identifier: MIT OR Apache-2.0
// Minimal test file for macro USR enrichment

#define MAX(a, b) ((a) > (b) ? (a) : (b))

int main() {
    return MAX(1, 2);
}
