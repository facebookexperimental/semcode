// SPDX-License-Identifier: MIT OR Apache-2.0
//! Constants used throughout the codebase for SmallVec sizing and other configurations.
//!
//! SmallVec sizes are derived from statistical analysis of the Linux kernel codebase
//! using tools/analyze_kernel_stats.py. These sizes provide optimal stack allocation
//! for the vast majority of cases.

/// SmallVec size for function parameters.
/// Based on kernel analysis: 99.90% of functions have 10 or fewer parameters.
pub const SMALLVEC_PARAM_SIZE: usize = 10;

/// SmallVec size for struct/union/enum fields.
/// Based on kernel analysis: 94.92% of types have 20 or fewer fields.
pub const SMALLVEC_FIELD_SIZE: usize = 22;
