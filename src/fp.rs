// Functional Paradigm rewrite of scalar implementation of BLAKE3

use memmap2::Mmap;
use std::fs::File;
use std::path::Path;
use rand::RngExt;

type Word = u32;

static IV: [Word; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/// Holds the 16-word output of the last compression.
/// Can be interpreted as a chaining value (first 8 words) or root output.
#[derive(Debug, Clone, Copy)]
pub struct Output {
    words: [Word; 16],
}

impl Output {
    pub fn new(words: [Word; 16]) -> Self {
        Self { words }
    }

    pub fn chaining_value(&self) -> [Word; 8] {
        self.words[0..8].try_into().unwrap()
    }

    pub fn root_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, &w) in self.words[0..8].iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&w.to_le_bytes());
        }
out
}
}

/* 

#[cfg(test)]
mod fp_tests {
    use super::*;

    fn generate_input(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn test_hash_all_against_reference() {
        let cases = [0usize, 1, 2, 64, 65, 128, 1024, 1025, 2048, 3072, 3073, 4096, 8192];
        for len in cases {
            let input = generate_input(len);
            let got = hash_all(&input);
            let expected = blake3::hash(&input);
            assert_eq!(&got, expected.as_bytes(), "mismatch for len={}", len);
        }
    }

    #[test]
    fn test_hash_all_fuzz_short() {
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};
        let mut rng = StdRng::seed_from_u64(0xB1A6_E3F0);
        for _ in 0..500 {
            let len = rng.random_range(1..=4096);
            let input: Vec<u8> = (0..len).map(|_| rng.random()).collect();
            let got = hash_all(&input);
            let expected = blake3::hash(&input);
            assert_eq!(&got, expected.as_bytes(), "fuzz mismatch for len={}", len);
        }
    }
}


// ---------------------------------------------------------------------------
// ChunkState
// ---------------------------------------------------------------------------

/// Accumulates up to 1024 bytes of a single chunk and produces its CV.
/// update() feeds data; finalize() runs the compression and returns the Output.
#[derive(Debug, Clone)]
pub struct ChunkState {
    buffer: [u8; 1024],
    buf_len: usize,
    blocks_compressed: usize,
}

impl ChunkState {

    // Create a new empty ChunkState.
    pub fn new() -> Self {
        Self {
            buffer: [0u8; 1024],
            buf_len: 0,
            blocks_compressed: 0,
        }
    }
    // Feed data into the chunk state, up to 1024 bytes.
    // TODO: handle more than 1024 bytes by returning an error and maybe initialising another chunk state
    pub fn update(&mut self, data: &[u8]) {
        let remaining = 1024 - self.buf_len;
        let take = data.len().min(remaining);
        self.buffer[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
        self.buf_len += take;
    }

    pub fn finalize(&self, chunk_counter: u64) -> Output {
        let mut cv = IV;
        let num_blocks = (self.buf_len + 63) / 64;
        for block_idx in 0..num_blocks {
            let start = block_idx * 64;
            let end = (start + 64).min(self.buf_len);
            let block = &self.buffer[start..end];

            let mut msg = [0u32; 16];
            for (i, &byte) in block.iter().enumerate() {
                msg[i / 4] |= (byte as u32) << ((i % 4) * 8);
            }

            let mut flags = 0u32;
            if block_idx == 0 {
                flags |= CHUNK_START;
            }
            if block_idx == num_blocks - 1 {
                flags |= CHUNK_END;
            }

            let counter = [chunk_counter as u32, (chunk_counter >> 32) as u32];
            let output = compress(cv, &mut msg, counter, block.len() as u32, flags);
            cv = output[0..8].try_into().unwrap();
        }
        Output::new(cv_to_16(cv))
    }

    pub fn is_full(&self) -> bool {
        self.buf_len == 1024
    }

    pub fn num_bytes(&self) -> usize {
        self.buf_len
    }
}

pub fn cv_to_16(cv: [Word; 8]) -> [Word; 16] {
    let mut out = [0u32; 16];
    out[0..8].copy_from_slice(&cv);
    out
}

// ---------------------------------------------------------------------------
// CvStack
// ---------------------------------------------------------------------------

/// Manages chaining values of completed subtrees.
/// push() inserts a new leaf CV and merges same-height entries.
/// merge() reduces the stack to a single root CV.
#[derive(Debug, Clone)]
pub struct CvStack {
    entries: Vec<([Word; 8], u8)>,
}

impl CvStack {
    pub fn new() -> Self {
        Self {
            entries: Vec::with_capacity(64),
        }
    }

    pub fn push(self, cv: [Word; 8], mut height: u8) -> Self {
        let mut entries = self.entries;
        let mut cv = cv;
        while let Some(&(top_cv, top_h)) = entries.last() {
            if top_h == height {
                cv = compress_parent(top_cv, cv, false);
                entries.pop();
                height += 1;
            } else {
                break;
            }
        }
        entries.push((cv, height));
        Self { entries }
    }

    pub fn merge(self) -> Self {
        let mut entries = self.entries;
        while entries.len() > 1 {
            let (right_cv, _) = entries.pop().unwrap();
            let (left_cv, _) = entries.pop().unwrap();
            let is_root = entries.is_empty();
            let parent = compress_parent(left_cv, right_cv, is_root);
            entries.push((parent, 0));
        }
        Self { entries }
    }

    pub fn root_cv(&self) -> Option<[Word; 8]> {
        self.entries.last().map(|&(cv, _)| cv)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

// ---------------------------------------------------------------------------
// Compression helpers
// ---------------------------------------------------------------------------

fn compress_parent(left: [Word; 8], right: [Word; 8], is_root: bool) -> [Word; 8] {
    let mut msg = [0u32; 16];
    msg[0..8].copy_from_slice(&left);
    msg[8..16].copy_from_slice(&right);
    let mut flags = PARENT;
    if is_root {
        flags |= ROOT;
    }
    let out = compress(IV, &mut msg, [0, 0], 64, flags);
    out[0..8].try_into().unwrap()
}

fn permute(msg: &mut [u32; 16]) -> [u32; 16] {
    let shifted: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
    let temp = *msg;
    for i in 0..16 {
        msg[i] = temp[shifted[i]];
    }
    *msg
}

fn quarter_round(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

fn compress(
    state: [u32; 8],
    msg: &mut [u32; 16],
    counter: [u32; 2],
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut v: [u32; 16] = [0; 16];
    v[0..8].copy_from_slice(&state);
    v[8..12].copy_from_slice(&IV);
    v[12] = counter[0];
    v[13] = counter[1];
    v[14] = block_len;
    v[15] = flags;

    for _ in 0..7 {
        quarter_round(&mut v, 0, 4, 8, 12, msg[0], msg[1]);
        quarter_round(&mut v, 1, 5, 9, 13, msg[2], msg[3]);
        quarter_round(&mut v, 2, 6, 10, 14, msg[4], msg[5]);
        quarter_round(&mut v, 3, 7, 11, 15, msg[6], msg[7]);
        quarter_round(&mut v, 0, 5, 10, 15, msg[8], msg[9]);
        quarter_round(&mut v, 1, 6, 11, 12, msg[10], msg[11]);
        quarter_round(&mut v, 2, 7, 8, 13, msg[12], msg[13]);
        quarter_round(&mut v, 3, 4, 9, 14, msg[14], msg[15]);
        permute(msg);
    }

    for i in 0..8 {
        v[i] ^= v[i + 8];
        v[i + 8] ^= state[i];
    }
    v
}

// ---------------------------------------------------------------------------
// mmap helpers
// ---------------------------------------------------------------------------

/// Memory-map a file and return the mapped slice.
pub fn mmap_file(path: impl AsRef<Path>) -> Result<Mmap, std::io::Error> {
    let file = File::open(path)?;
    // SAFETY: read-only, no concurrent file mutation assumed
    unsafe { Mmap::map(&file) }
}

/// Hash a memory-mapped file in one shot.
pub fn hash_mmap(mmap: &Mmap) -> [u8; 32] {
    hash_all(mmap)
}

/// Hash a byte slice in one shot using ChunkState + CvStack.
pub fn hash_all(data: &[u8]) -> [u8; 32] {
    if data.is_empty() {
        return [0u8; 32];
    }

    let mut stack = CvStack::new();
    let mut chunk_counter: u64 = 0;

    for chunk in data.chunks(1024) {
        let mut cs = ChunkState::new();
        cs.update(chunk);
        let output = cs.finalize(chunk_counter);
        stack = stack.push(output.chaining_value(), 0);
        chunk_counter += 1;
    }

    stack = stack.merge();
    let root = stack.root_cv().unwrap();
    let mut out = [0u8; 32];
    for (i, &w) in root.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}
    */