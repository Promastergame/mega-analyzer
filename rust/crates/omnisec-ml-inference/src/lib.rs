//! # omnisec-ml-inference
//!
//! High-performance ML inference engine for the OmniSec analyzer pipeline.
//!
//! This crate accelerates the Go-based ML suggester by offloading heavy
//! mathematical operations to Rust. It provides:
//!
//! - **Feature hashing:** SIMD-accelerated feature vector construction from
//!   raw analysis results (permissions, API calls, string patterns).
//! - **Hotspot ranking:** Vectorized scoring of code regions using HDC
//!   similarity against known-malicious anchors.
//! - **Batch pattern matching:** Compare thousands of vulnerability patterns
//!   against a target graph in microseconds.
//! - **FFI exports:** C-ABI functions callable from Go via cgo.

#![allow(unsafe_code)]

mod feature_hasher;
mod ffi;
pub mod pattern_matcher;
mod ranker;

pub use feature_hasher::FeatureHasher;
pub use pattern_matcher::PatternMatcher;
pub use ranker::HotspotRanker;
