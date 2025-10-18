// SPDX-License-Identifier: MIT OR Apache-2.0
//! Tests for various compile_commands.json formats

mod common;

use common::*;
use common::predicates::*;
use rstest::*;

#[rstest]
#[case("compile_commands_gcc.json")]
#[case("compile_commands_complex.json")]
#[case("compile_commands_array.json")]
fn test_compile_commands_formats(#[case] cc_file: &str) {
    skip_if_no_libclang!();

    let test_env = TestEnv::with_compile_commands(cc_file);

    IndexRunner::new(&test_env)
        .with_clangd()
        .assert()
        .success()
        .stdout(has_enrichment_stats())
        .stdout(has_enriched_functions(EXPECTED_FUNCTIONS));
}

#[rstest]
fn test_clangd_with_spaces_and_quotes(test_env: TestEnv) {
    skip_if_no_libclang!();

    std::fs::write(test_env.path().join("compile_commands.json"),
        r#"[{"directory":".","command":"gcc -I\"/path with spaces\" -c test_sample.c","file":"test_sample.c"}]"#
    ).unwrap();

    IndexRunner::new(&test_env).with_clangd().assert().success();
}

#[rstest]
fn test_source_file_in_command_filtered(test_env: TestEnv) {
    skip_if_no_libclang!();

    std::fs::write(test_env.path().join("compile_commands.json"),
        r#"[{"directory":".","command":"gcc -Wall -c test_sample.c -o test.o","file":"test_sample.c"}]"#
    ).unwrap();

    IndexRunner::new(&test_env).with_clangd().assert().success();
}
