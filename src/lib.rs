type Word = u32;
use crate::error::{Blake3Error, ChunkingError};
use std::cmp::min;
use std::fs::File;
use std::io::Write;
use std::sync::{Arc, Mutex};
mod error;
use tracing_subscriber::fmt::MakeWriter;
/// initialisation vector
static IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// BLAKE3 Flags
const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;



#[derive(Debug, Clone)]
pub struct Blake3Hasher {
    cv_stack: Vec<([Word; 8], u8)>, // (Chaining Value, Height)
    chunk_count: u64,
}

impl Blake3Hasher {
    pub fn new() -> Self {
        Self {
            cv_stack: Vec::with_capacity(64), // Max height for 2^64 bytes
            chunk_count: 0,
        }
    }
    
    /// Entry point for hashing a full slice of data.
    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        
        // 1. Process 1024-byte chunks
        let mut chunks = data.chunks_exact(1024);
        for chunk in chunks.by_ref() {
            hasher.process_chunks(&mut chunk);
        }

        // 2. Process the final (possibly partial) chunk
        hasher.process_chunks(&mut chunks.remainder());
        // 3. Finalize and return bytes
        hasher.finalize()

    }

    /// Merkle Tree Logic: Pushes a CV at a specific height and merges if necessary.
    fn push_cv(&mut self, mut new_cv: [Word; 8], mut height: u8) {
        // While the top of the stack has the same height, merge them into a parent.
        while let Some(&(top_cv, top_height)) = self.cv_stack.last() {
            if top_height == height {
                new_cv = self.parent_output(top_cv, new_cv, false);
                self.cv_stack.pop();
                height += 1;
            } else {
                break;
            }
        }
        self.cv_stack.push((new_cv, height));
    }

    /// Compresses two children into a parent CV.
    fn parent_output(&self, left_child: [Word; 8], right_child: [Word; 8], is_root: bool) -> [Word; 8] {
        let mut msg = [0u32; 16];
        msg[0..8].copy_from_slice(&left_child);
        msg[8..16].copy_from_slice(&right_child);

        let mut flags = PARENT;
        if is_root { flags |= ROOT; }

        let res = compress(IV, &mut msg, [0, 0], 64, flags);
        res[0..8].try_into().unwrap()
    }
    /// breaks given data into chunks of 1024 bytes by mutating passed data in place.
    pub fn process_chunks<'a>(&mut self,input_data: &'a mut [u8]) -> Result<DataChunks<'a>, Blake3Error> {
        if input_data.len() == 0 {
            return Err(ChunkingError::InputTooShort.into());
        }
    
        let (chunks, remainder) = input_data.as_chunks::<1024>();
    
        return Ok(DataChunks {
            input_len: input_data.len(),
            slices: (chunks, remainder),
            chunks: min(chunks.len(), 1),
        });
    }


    /// Reduces the remaining stack and applies the ROOT flag.
    pub fn finalize(mut self) -> [u8; 32] {
        // Edge case: Empty input (not handled in process_chunk)
        if self.cv_stack.is_empty() {
            // Process an empty block as a single chunk
            self.process_chunks(&[], true);
        }

        // Final reduction: Merge from the bottom up until only one CV remains
        while self.cv_stack.len() > 1 {
            let (right_cv, _) = self.cv_stack.pop().unwrap();
            let (left_cv, _) = self.cv_stack.pop().unwrap();
            let parent = self.parent_output(left_cv, right_cv, self.cv_stack.is_empty());
            self.cv_stack.push((parent, 255)); // Height doesn't matter anymore
        }

        // Final compression with ROOT flag if it wasn't already applied
        // Note: For simplicity, we ensure the last node is compressed as ROOT.
        let (final_cv, _) = self.cv_stack.pop().unwrap();
        let mut result = [0u8; 32];
        for (i, &word) in final_cv.iter().enumerate() {
            result[i*4..(i+1)*4].copy_from_slice(&word.to_le_bytes());
        }
        result
    }
}


/// Logging struct
pub struct FileLogger {
    file: Arc<Mutex<File>>,
}

impl FileLogger {
    pub fn new(path: &str) -> Self {
        let file = File::create(path).expect("Failed to create log file");
        Self {
            file: Arc::new(Mutex::new(file)),
        }
    }
}

// This trait implementation tells 'tracing' how to get a handle to the file
impl<'a> MakeWriter<'a> for FileLogger {
    type Writer = FileWriter;

    fn make_writer(&self) -> Self::Writer {
        FileWriter {
            file: Arc::clone(&self.file),
        }
    }
}

pub struct FileWriter {
    file: Arc<Mutex<File>>,
}

impl Write for FileWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut file = self.file.lock().unwrap();
        file.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        let mut file = self.file.lock().unwrap();
        file.flush()
    }
}

#[cfg(feature = "trace_internals")]
use std::sync::Once;
#[cfg(feature = "trace_internals")]
static TRACING_INIT: Once = Once::new();
#[cfg(feature = "trace_internals")]
pub fn init_tracing() {
    TRACING_INIT.call_once(|| {
        let logger = FileLogger::new("blake3_trace.log");

        tracing_subscriber::fmt()
            .with_writer(logger)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    });
}

/// Breaks down the input data into chunks of sizes 1024 bytes.
#[derive(Debug, Clone)]
struct DataChunks<'a> {
    /// Number of bytes of a file.
    input_len: usize,

    /// Input data sliced into 1024 bytes.
    /// First vector is for all chunks of 1024 bytes and
    /// last chunk can be less than 1024 bytes.
    slices: (&'a [[u8; 1024]], &'a [u8]),

    /// No of chunks input data broken into.
    chunks: usize,
}


/// permute fn as  which shifts values at indices given in input_indices to shifted_indices
/// Mentioned in https://www.ietf.org/archive/id/draft-aumasson-blake3-00.html#name-message-word-permutation
fn permute(data_chunks: &mut [u32; 16]) -> [u32; 16] {
    let input_indices: [usize; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let shifted_indices: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

    let mut temp = *data_chunks;
    for i in 0..16 {
        data_chunks[i] = temp[shifted_indices[i]];
    }
    *data_chunks
}

/// Is the quarter round function inspired from the ChaCha20 algorithm.
/// Mentioned in https://www.ietf.org/archive/id/draft-aumasson-blake3-00.html#name-quarter-round-function-g
fn quarter_round_fn(
    word_in_process: &mut [Word; 16],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    x: Word,
    y: Word,
) -> [u32; 16] {
    word_in_process[a] = word_in_process[a]
        .wrapping_add(word_in_process[b])
        .wrapping_add(x);
    word_in_process[d] = (word_in_process[d] ^ word_in_process[a]).rotate_right(16);
    word_in_process[c] = word_in_process[c].wrapping_add(word_in_process[d]);
    word_in_process[b] = (word_in_process[b] ^ word_in_process[c]).rotate_right(12);
    word_in_process[a] = word_in_process[a]
        .wrapping_add(word_in_process[b])
        .wrapping_add(y);
    word_in_process[d] = (word_in_process[d] ^ word_in_process[a]).rotate_right(8);
    word_in_process[c] = word_in_process[c].wrapping_add(word_in_process[d]);
    word_in_process[b] = (word_in_process[b] ^ word_in_process[c]).rotate_right(7);

    //shadowing to make word_in_process immutable
    let word_in_process = word_in_process;
    *word_in_process
}

/// Is the BLAKE3_COMPRESS fn
/// mentioned in https://www.ietf.org/archive/id/draft-aumasson-blake3-00.html#name-compression-function-proces
fn compress<'a>(
    h: [u32; 8],
    msg: &'a mut [u32; 16],
    t: [u32; 2],
    len: u32,
    flags: u32,
) -> [u32; 16] {
    #[cfg(feature = "trace_internals")]
    let _span = tracing::info_span!("compress_op").entered();

    let mut v: [u32; 16] = [0; 16];
    for (index, val) in h.iter().enumerate() {
        v[index] = *val;
    }
    for (index, val) in IV.iter().enumerate() {
        v[index + 8] = *val;
    }
    v[12] = t[0];
    v[13] = t[1];
    v[14] = len;
    v[15] = flags;

    for rounds in 0..7 {
        v = quarter_round_fn(&mut v, 0, 4, 8, 12, msg[0], msg[1]);
        v = quarter_round_fn(&mut v, 1, 5, 9, 13, msg[2], msg[3]);
        v = quarter_round_fn(&mut v, 2, 6, 10, 14, msg[4], msg[5]);
        v = quarter_round_fn(&mut v, 3, 7, 11, 15, msg[6], msg[7]);

        v = quarter_round_fn(&mut v, 0, 5, 10, 15, msg[8], msg[9]);
        v = quarter_round_fn(&mut v, 1, 6, 11, 12, msg[10], msg[11]);
        v = quarter_round_fn(&mut v, 2, 7, 8, 13, msg[12], msg[13]);
        v = quarter_round_fn(&mut v, 3, 4, 9, 14, msg[15], msg[15]);

        #[cfg(feature = "trace_internals")]
        tracing::debug!(round = rounds, state = ?v, "Round completed");
    }
    permute(msg);

    for i in 0..8 {
        v[i] = v[i] ^ v[i + 8];
        v[i + 8] = v[i + 8] ^ h[i];
    }
    v
}

fn compress_parent(
    left_child: [u32; 8],
    right_child: [u32; 8],
    flags: u32,
) -> [u32; 8] {
    let mut msg = [0u32; 16];
    msg[0..8].copy_from_slice(&left_child);
    msg[8..16].copy_from_slice(&right_child);

    // Parents always use: IV as chaining value, 0 as counter, 64 as length
    let out = compress(IV, &mut msg, [0, 0], 64, flags | PARENT);
    
    // Truncate to 8 words (32 bytes)
    let mut cv = [0u32; 8];
    cv.copy_from_slice(&out[0..8]);
    cv
}


fn chain_cv(left_cv: [Word; 16]) {}

struct MerkleTree {
    depth: u8,
    leaf_nodes: Vec<[Word; 8]>,
    // intermediate_nodes:Has
}

#[cfg(test)]
mod preprocessing_tests {
    use rand::RngExt;

    use super::*;

    /// general test to see if chunking works
    #[test]
    fn test_chunking() {
        //general test
        let mut input: Vec<u8> = vec![0, 100, 21, 2, 4, 2, 3, 1];
        let mut hasher = Blake3Hasher::new();
        let rng = rand::rng();

        //if remainder is registered
        let mut rng_data: Vec<u8> = rng.clone().random_iter().take(1025).collect();

        // no elements edge case
        let mut rng_data_2: Vec<u8> = rng.random_iter().take(0).collect();
        let chunks_a = hasher.process_chunks(&mut input);
        let chunks_b = hasher.process_chunks(&mut rng_data);
        let chunks_c = hasher.process_chunks(&mut rng_data_2);
        // println!("{:?}", &chunks_a);
        // println!("{:?}", chunks_b);
        // println!("{:?}", chunks_c);

        assert_eq!(chunks_a.clone().unwrap().chunks, 0);
        assert_eq!(chunks_a.clone().unwrap().slices.0.len(), 0);
        assert_eq!(chunks_b.unwrap().chunks, 1);
    }
    #[test]
    fn test_error_formatting() {
        let err = Blake3Error::from(ChunkingError::InputTooShort);

        // 1. Test "Display" (The "Pretty" version for users)
        let display_msg = format!("{}", err);
        assert_eq!(
            display_msg,
            "Input length is zero; BLAKE3 requires at least 1 byte."
        );

        // 2. Test "Debug" (The "Technical" version for developers)
        let debug_msg = format!("{:?}", err);
        // Debug usually contains the Type names and variants
        assert!(debug_msg.contains("Chunking"));
        assert!(debug_msg.contains("InputTooShort"));
    }

    #[test]
    fn test_compress_with_logging() {
        // 1. Initialize tracing only if the feature is enabled
        #[cfg(feature = "trace_internals")]
        {
            init_tracing();
            tracing::info!("Starting compression test with tracing enabled...");
        }

        // 2. Setup dummy data for compression
        let h = [0u32; 8];
        let mut msg = [0u32; 16];
        let t = [0u32; 2];
        let len = 64;
        let flags = 0;

        // 3. Call the function
        let result = compress(h, &mut msg, t, len, flags);

        // 4. Basic assertion to ensure it ran
        assert_ne!(result, [0u32; 16]);

        #[cfg(feature = "trace_internals")]
        tracing::info!("Compression test finished. Check blake3_trace.log for details.");
    }

    #[test]
    fn test_trigger_error() {
        let mut empty_data: Vec<u8> = vec![];
        let result = break_into_chunks_inplace(&mut empty_data);

        // Check that it is specifically the ChunkingError variant
        match result {
            Err(Blake3Error::Chunking(ChunkingError::InputTooShort)) => (), // Success
            _ => panic!("Expected InputTooShort error, got {:?}", result),
        }
    }

    #[test]
    fn test_quarter_round() {
        let rng = rand::rng();
        let mut rng_data: Vec<u32> = rng.clone().random_iter().take(2).collect();
        let mut gen_word_in_process: Vec<u32> = rng.random_iter().take(16).collect();
        let array_ref: &mut [u32; 16] = gen_word_in_process.as_mut_slice().try_into().unwrap();
        let q_output = quarter_round_fn(array_ref, 0, 4, 8, 12, rng_data[0], rng_data[1]);
        println!("{:?}", q_output);
    }

    #[test]
    fn test_compress_fn() {}
}
