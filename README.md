# BLAKE3 Microarchitecture Optimization

A Rust implementation of the BLAKE3 hash function, optimized for Intel's hybrid **Golden Cove (P-core)** and **Gracemont (E-core)** microarchitectures found in Alder Lake and later CPUs.

> **Status: Under active development.** APIs, correctness guarantees, and performance characteristics are not yet stable.

## Objective

Deliver a bit-exact BLAKE3 implementation whose hot paths are tuned for the execution characteristics of both core types on hybrid Intel processors:

- **P-cores (Golden Cove)** — wider SIMD pipelines, higher throughput; target aggressive AVX2 vectorization and parallel chunk processing.
- **E-cores (Gracemont)** — narrower execution units, different latency/throughput trade-offs; target leaner kernels and core-aware dispatch.

All optimizations preserve specification-correct output validated against the official `blake3` crate.

## Current Progress

### Scalar pipeline (complete)

- Compression function (`compress`), quarter-round, and message-word permutation per the [BLAKE3 specification](https://www.ietf.org/archive/id/draft-aumasson-blake3-00.html).
- End-to-end hasher: 1024-byte chunking, 64-byte block processing, Merkle tree CV stack, and root finalization.
- Structured error handling and optional `enable_tracing` feature for step-by-step debugging.

### AVX2 SIMD primitives (in progress)

- `quarter_round_simd` and `permute_simd` implemented with AVX2 intrinsics.
- Differential tests confirm SIMD output matches scalar across 10,000+ randomized inputs per primitive.
- Criterion benchmarks (`benches/compress.rs`) compare scalar vs. AVX2 throughput for quarter-round and permute.

### Validation infrastructure

- Differential tests against the official `blake3` crate across varied input lengths.
- Fuzz-style randomized tests with deterministic seeds for reproducibility.
- Standalone comparison utilities (`compare_compress.rs`, `test_ref.rs`) for targeted debugging.

## Planned Work

| Area | Description |
|------|-------------|
| **Full SIMD compress** | Wire AVX2 primitives into the complete 7-round compression loop and chunk pipeline. |
| **P-core tuning** | Profile and schedule for Golden Cove: wider SIMD batches, prefetching, and multi-chunk parallelism. |
| **E-core tuning** | Separate kernel variants or dispatch heuristics tuned for Gracemont's narrower execution width. |
| **Runtime dispatch** | Feature detection and core-type-aware path selection at runtime. |
| **Parallel hashing** | Multi-threaded chunk processing (`join` module scaffold). |
| **Extended output** | XOF support beyond 32-byte digests. |
| **mmap I/O** | Zero-copy file hashing via memory-mapped input (functional rewrite in `fp.rs`). |
| **Correctness hardening** | Enable full assertion coverage across all test vectors and input sizes. |

## Project Layout

```
src/
├── lib.rs          # Scalar hasher, compress, and core algorithm
├── simd/avx2.rs    # AVX2 quarter-round and permute primitives
├── fp.rs           # Functional-style rewrite (WIP)
├── join.rs         # Parallel hashing scaffold (WIP)
└── error.rs        # Error types
benches/compress.rs # Scalar vs. AVX2 micro-benchmarks
docs/skills/        # Development guidelines (crypto, Rust, testing)
```

A vendored copy of the upstream BLAKE3 repository is kept locally for reference and differential testing.

## Building & Testing

```bash
cargo test
cargo test --features enable_tracing
cargo bench --bench compress
```

Requires a CPU with AVX2 support for SIMD tests and benchmarks.

## Design Principles

- **Correctness first** — every optimization must produce bit-exact output; performance is secondary.
- **Incremental SIMD** — validate each primitive against its scalar counterpart before integration.
- **Microarchitecture awareness** — optimization decisions are driven by P-core vs. E-core profiling, not generic x86-64 tuning.
