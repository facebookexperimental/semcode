// SPDX-License-Identifier: MIT OR Apache-2.0
//! Basic integration tests for semcode indexing without clangd

mod common;

use common::*;
use common::predicates::*;
use rstest::*;

#[rstest]
fn test_index_without_clangd(test_env: TestEnv) {
    IndexRunner::new(&test_env)
        .assert()
        .success()
        .stdout(has_function_count(EXPECTED_FUNCTIONS))
        .stdout(has_type_count(EXPECTED_TYPES))
        .stdout(has_macro_count(EXPECTED_MACROS_WITHOUT_CLANGD));
}

#[rstest]
fn test_index_consecutive_runs(test_env: TestEnv) {
    IndexRunner::new(&test_env).assert().success();
    IndexRunner::new(&test_env).assert().success();
}

#[test]
fn test_graceful_degradation_without_compile_commands() {
    use ::predicates::prelude::*;

    IndexRunner::new(&TestEnv::with_custom_file("test.c", "int main() { return 0; }\n"))
        .with_clangd()
        .assert()
        .success()
        .stderr(::predicates::str::contains("compile_commands").or(::predicates::str::contains("clangd")));
}
