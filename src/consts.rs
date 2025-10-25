// SPDX-License-Identifier: MIT OR Apache-2.0
//! Constants used throughout the codebase for SmallVec sizing and other configurations.
//!
//! SmallVec sizes are derived from statistical analysis of the Linux kernel codebase
//! using tools/analyze_kernel_stats.py. These sizes provide optimal stack allocation
//! for the vast majority of cases.

/// SmallVec size for function parameters.
/// Based on kernel analysis: 94.66% of functions have 4 or fewer parameters (90th percentile: 4).
/// Using 4 provides excellent stack allocation coverage while keeping struct size reasonable.
pub const SMALLVEC_PARAM_SIZE: usize = 4;

/// SmallVec size for struct/union/enum fields.
/// Based on kernel analysis: 90th percentile is 15 fields, 95th percentile is 30 fields.
/// Using 15 balances stack usage with heap allocation frequency.
pub const SMALLVEC_FIELD_SIZE: usize = 15;

/// Default capacity for function call vectors.
/// Based on kernel analysis: 75th percentile is 2 calls, 90th percentile is 6 calls.
/// Most functions make 0-2 calls (76.43% combined).
pub const VEC_CALLS_CAPACITY: usize = 2;

/// Default capacity for top comment vectors.
/// Based on kernel analysis: 75th percentile is 1 comment, 90th percentile is 1 comment.
/// 93.05% of functions have 0-1 comments.
pub const VEC_COMMENTS_CAPACITY: usize = 1;

/// Default capacity for macro parameter vectors.
/// Based on kernel analysis: 90th percentile is 2 parameters.
/// 90.58% of macros have 1-2 parameters.
pub const VEC_MACRO_PARAMS_CAPACITY: usize = 2;

/// Average bytes per function definition.
/// Based on kernel analysis: mean function size is 327 bytes.
/// Used for Vec pre-allocation: estimated_functions = file_size / BYTES_PER_FUNCTION
pub const BYTES_PER_FUNCTION: usize = 327;

/// Average bytes per type definition (struct/union/enum).
/// Based on kernel analysis: mean type size is 123 bytes.
/// Used for Vec pre-allocation: estimated_types = file_size / BYTES_PER_TYPE
pub const BYTES_PER_TYPE: usize = 123;

/// Average bytes per macro definition.
/// Based on kernel analysis: mean macro size is 105 bytes.
/// Used for Vec pre-allocation: estimated_macros = file_size / BYTES_PER_MACRO
pub const BYTES_PER_MACRO: usize = 105;

/// Default capacity for temporary parameter parsing (95th percentile from analysis).
/// Used when parsing parameter lists before converting to SmallVec.
pub const TEMP_PARAM_PARSE_CAPACITY: usize = 5;

/// Comment to function ratio for estimating total comments in a file.
/// Analysis shows 0.43 comments per function, but extract_comments gets ALL comments.
/// Using 1:2 ratio (half as many comments as functions) as conservative estimate.
pub const COMMENTS_PER_FUNCTION_DIVISOR: usize = 2;

/// Call to function ratio multiplier for estimating total calls.
/// Analysis shows mean 2.65 calls per function across 5407 samples.
/// Using 3 (ceil of mean) as a reasonable safety margin.
pub const CALLS_PER_FUNCTION_MULTIPLIER: usize = 3;

/// Threshold for switching to parallel processing in batch operations.
/// Below this threshold, sequential processing provides better cache locality.
pub const BATCH_PARALLEL_THRESHOLD: usize = 1000;

/// Threshold for switching to parallel processing in SQL string formatting.
/// Below this threshold, sequential processing provides better cache locality.
pub const SQL_FORMAT_PARALLEL_THRESHOLD: usize = 100;

/// Threshold for switching to parallel processing in collection transformations.
/// Below this threshold, sequential processing provides better cache locality.
pub const COLLECTION_PARALLEL_THRESHOLD: usize = 1000;

/// Threshold for switching to parallel processing in filter operations.
/// Below this threshold, sequential processing provides better cache locality.
pub const FILTER_PARALLEL_THRESHOLD: usize = 500;

/// Number of distinct capture names in the Tree-sitter function query.
/// Based on the function_query definition in treesitter_analyzer.rs (lines 38-86):
/// @return_type, @function_name, @parameters, @body, @function, @function_ptr,
/// @function_ptr2, @declaration (8 total).
/// Used for HashSet capacity when tracking which capture patterns were matched.
pub const FUNCTION_QUERY_CAPTURE_NAMES: usize = 8;
