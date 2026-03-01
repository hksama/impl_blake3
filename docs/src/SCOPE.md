# BLAKE3 Rust Implementation – Scope & Plan

## 1. Goal

Implement a single-threaded, non-SIMD BLAKE3 hash in Rust for learning and benchmarking.

- Focus: correctness, clear code, good docs.
- Out of scope (for now):
  - GPU acceleration
  - Exotic platforms

## 2. Features & Scope

### 2.1 Basic Setup(Phase 1)

- [ ] Unkeyed `hash` mode (32-byte output)
- [ ] Support arbitrary-length input
- [ ] Single-threaded, scalar implementation
- [ ] Test vectors from BLAKE3 spec
- [ ] Basic benchmarking (e.g. 1 KiB, 1 MiB, 100 MiB)
- [ ] Tracing setup for all intermediate values generated

### 2.2 Optimising for Zen 3 Architecture(Phase 2)

<!-- - [ ] `keyed_hash` mode
- [ ] `derive_key` mode
- [ ] XOF output (arbitrary-length) -->
- [ ] Simple Merkle tree visualizer (store CVs per level)
- [ ] SIMD optimization (AVX2 on Intel macOS)
- [ ] Multithreaded tree hashing using Rayon

### 2.3 Explicit non-goals

- [ ] Production-ready crypto library
- [ ] Constant-time side-channel hardening
- [ ] WASM or embedded targets





## 3. Design Overview

### 3.1 High-level components

### 3.2 Data types

### 3.3 Merkle tree



## 4. TODO / Issues

### 4.1 Core correctness

- [ ] Implement `permute(m: &mut [u32; 16])` exactly as spec
- [ ] Implement `compress(...)` and verify against Appendix B.1/B.2 examples
- [ ] Implement `compress_chunk` for 0..1024-byte inputs
- [ ] Handle partial final block with zero padding and correct `len`

### 4.2 Tree / Merkle

- [ ] Implement `reduce_tree(cvs: &[CV]) -> CV` with correct PARENT/ROOT flags
- [ ] Support non-power-of-two leaf counts
- [ ] Optional: store intermediate CV levels for visualization

### 4.3 API

- [ ] `Blake3::new_hash()`
- [ ] `Blake3::update(&mut self, data: &[u8])`
- [ ] `Blake3::finalize(&self, out: &mut [u8; 32])`
- [ ] Add simple `hash_bytes(&[u8]) -> [u8; 32]` helper

### 4.4 Error handling

- [ ] Define custom error enum:
  - `Blake3Error::OutputTooShort`
  - `Blake3Error::InvalidState`
- [ ] Make `finalize` return `Result<(), Blake3Error>`
- [ ] All public APIs should return `Result` where things can fail

### 4.5 Tracing / logging

- [ ] Decide on logging crate (`tracing` or `log`)
- [ ] Add trace logs for:
  - New chunk start (chunk index)
  - Tree reduction levels
  - Final root CV
- [ ] Add compile-time feature flag `trace` to enable/disable logs

### 4.6 Benchmarking

- [ ] Set up Criterion benchmarks
- [ ] Benchmarks for:
  - 1 KiB
  - 1 MiB
  - 100 MiB
- [ ] Compare with Rust `blake3` crate (optional sanity check)

### 4.7 Documentation

- [ ] API docs (`///`) for each public function
- [ ] Explain flags (CHUNKSTART, CHUNKEND, PARENT, ROOT) in comments
- [ ] Add `ARCHITECTURE.md` diagram of data flow
