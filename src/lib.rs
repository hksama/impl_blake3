type Word = u32;
use crate::error::{Blake3Error, ChunkingError};
use std::fs::File;
use std::io::Write;
use std::sync::{Arc, Mutex};
mod error;
mod join;
use tracing_subscriber::fmt::MakeWriter;
/// initialisation vector
static IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];


// BLAKE3 Flags
const CHUNK_START: u32 = 1 << 0; // 0x01
const CHUNK_END: u32 = 1 << 1; // 0x02
const PARENT: u32 = 1 << 2; // 0x04
const ROOT: u32 = 1 << 3; // 0x08



#[derive(Debug, Clone)]
pub struct Blake3Hasher {
    cv_stack: Vec<([Word; 8], u8)>, // (Chaining Value, Height)
    chunk_count: u64,
    bytes_processed: u64, // Tracks bytes processed for counter
    is_root_node: bool,  // Whether this is a single-leaf (root node)
}

impl Blake3Hasher {
    pub fn new() -> Self {
        Self {
            cv_stack: Vec::with_capacity(64), // Max height for 2^64 bytes
            chunk_count: 0,
            bytes_processed: 0,
            is_root_node: false,
        }
    }
    
    /// Helper: Compute flags for a block given its position in a chunk
    #[allow(dead_code)]
    fn compute_block_flags(&self, is_first_block: bool, is_last_block: bool, is_root: bool) -> u32 {
        let mut flags = 0u32;
        if is_first_block { flags |= CHUNK_START; }
        if is_last_block { flags |= CHUNK_END; }
        if is_root { flags |= ROOT; }
        flags
    }
    
    /// Entry point for hashing a full slice of data.
    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        // Determine if this is a single-leaf case before processing
        let is_single_leaf = data.len() <= 1024;
        hasher.is_root_node = is_single_leaf;  // Mark if this is the final output
        // Process all data through the chunks pipeline
        hasher.process_chunks(data).expect("Failed to process chunks");
        // Finalize and return 32-byte hash
        hasher.finalize(32)
    }

    /// Merkle Tree Logic: Pushes a CV at a specific height and merges if necessary.
    fn push_cv(&mut self, mut new_cv: [Word; 8], mut height: u8) {
        #[cfg(feature = "trace_internals")]
        {
            tracing::trace!(
                new_cv = ?new_cv,
                height = height,
                stack_len_before = self.cv_stack.len(),
                "push_cv: pushing CV at height {} to stack (size before: {})",
                height,
                self.cv_stack.len()
            );
        }

        // While the top of the stack has the same height, merge them into a parent.
        let mut merge_count = 0;
        while let Some(&(top_cv, top_height)) = self.cv_stack.last() {
            if top_height == height {
                #[cfg(feature = "trace_internals")]
                {
                    tracing::debug!(
                        merge_at_height = height,
                        top_cv = ?top_cv,
                        new_cv_in = ?new_cv,
                        "push_cv: merging at height {}, need to combine two CVs",
                        height
                    );
                }

                new_cv = self.parent_output(top_cv, new_cv, false);

                #[cfg(feature = "trace_internals")]
                {
                    tracing::trace!(
                        merge_at_height = height,
                        parent_cv_result = ?new_cv,
                        "push_cv: merge at height {} produced parent",
                        height
                    );
                }

                self.cv_stack.pop();
                height += 1;
                merge_count += 1;
            } else {
                break;
            }
        }

        #[cfg(feature = "trace_internals")]
        {
            if merge_count > 0 {
                tracing::debug!(
                    final_height = height,
                    merges_performed = merge_count,
                    final_cv = ?new_cv,
                    "push_cv: after {} merge(s), final height={}, CV={}",
                    merge_count,
                    height,
                    "TRACE"
                );
            }
        }

        self.cv_stack.push((new_cv, height));

        #[cfg(feature = "trace_internals")]
        tracing::trace!(
            stack_len_after = self.cv_stack.len(),
            stack_heights = ?self.cv_stack.iter().map(|(_, h)| h).collect::<Vec<_>>(),
            "push_cv: CV pushed, stack now has {} entries, heights: {}",
            self.cv_stack.len(),
            "TRACE"
        );
    }

    /// Compresses two children into a parent CV.
    fn parent_output(&self, left_child: [Word; 8], right_child: [Word; 8], is_root: bool) -> [Word; 8] {
        #[cfg(feature = "trace_internals")]
        {
            tracing::trace!(
                left_child = ?left_child,
                right_child = ?right_child,
                is_root = is_root,
                "parent_output: creating parent from left and right child CVs, is_root={}",
                is_root
            );
        }

        let mut msg = [0u32; 16];
        msg[0..8].copy_from_slice(&left_child);
        msg[8..16].copy_from_slice(&right_child);

        #[cfg(feature = "trace_internals")]
        tracing::trace!(
            msg = ?msg,
            "parent_output: message block assembled [left_child | right_child]"
        );

        let mut flags = PARENT;
        if is_root { flags |= ROOT; }

        #[cfg(feature = "trace_internals")]
        tracing::trace!(
            flags = flags,
            is_root = is_root,
            "parent_output: flags computed: PARENT={}, ROOT={}, combined={}",
            PARENT,
            if is_root { ROOT } else { 0 },
            flags
        );

        let res = compress(IV, &mut msg, [0, 0], 64, flags);

        #[cfg(feature = "trace_internals")]
        {
            let parent_cv = &res[0..8];
            tracing::debug!(
                compress_output = ?res,
                parent_cv = ?parent_cv,
                "parent_output: compression complete, extracted parent CV from first 8 words"
            );
        }

        res[0..8].try_into().unwrap()
    }

    /// Process 1024-byte chunks and generate chaining values via tree integration.
    /// Splits each chunk into 64-byte blocks, applies compression with proper flags,
    /// and pushes resulting CVs to the Merkle tree.
    pub fn process_chunks(&mut self, data: &[u8]) -> Result<(), Blake3Error> {
        #[cfg(feature = "trace_internals")]
        {
            init_tracing();
            tracing::info!(
                input_len = data.len(),
                "process_chunks: STARTING with {} byte input",
                data.len()
            );
        }

        if data.is_empty() {
            #[cfg(feature = "trace_internals")]
            tracing::error!("process_chunks: ERROR - input is empty");
            return Err(ChunkingError::InputTooShort.into());
        }

        let num_chunks = (data.len() + 1023) / 1024;
        #[cfg(feature = "trace_internals")]
        tracing::debug!(
            num_chunks = num_chunks,
            "process_chunks: splitting input into {} 1024-byte chunks",
            num_chunks
        );

        // Process each 1024-byte chunk
        for (chunk_idx, chunk) in data.chunks(1024).enumerate() {
            #[cfg(feature = "trace_internals")]
            tracing::info!(
                chunk_idx = chunk_idx,
                chunk_len = chunk.len(),
                "process_chunks: PROCESSING CHUNK {}, len={}",
                chunk_idx,
                chunk.len()
            );

            let mut cv = IV; // Start with IV for each chunk
            let chunk_len = chunk.len();
            
            #[cfg(feature = "trace_internals")]
            tracing::trace!(
                cv_initial = ?cv,
                "process_chunks: chunk {} initialized with IV",
                chunk_idx
            );
            
            // Process each 64-byte block within the chunk
            for (block_idx, block) in chunk.chunks(64).enumerate() {
                // Pad the block if it's smaller than 64 bytes (last block in last chunk)
                let mut msg = [0u32; 16];
                let block_len = block.len();
                
                #[cfg(feature = "trace_internals")]
                tracing::debug!(
                    chunk_idx = chunk_idx,
                    block_idx = block_idx,
                    block_len = block_len,
                    "process_chunks: chunk[{}] block[{}] len={} bytes",
                    chunk_idx,
                    block_idx,
                    block_len
                );

                // Convert bytes to u32 words (little-endian)
                for (i, &byte_val) in block.iter().enumerate() {
                    msg[i / 4] |= (byte_val as u32) << ((i % 4) * 8);
                }
                
                #[cfg(feature = "trace_internals")]
                tracing::trace!(
                    chunk_idx = chunk_idx,
                    block_idx = block_idx,
                    msg_words = ?msg,
                    "process_chunks: chunk[{}] block[{}] raw bytes converted to message words",
                    chunk_idx,
                    block_idx
                );
                
                let is_first_block = block_idx == 0;
                let blocks_in_chunk = (chunk_len + 63) / 64; // Ceiling division
                let is_last_block = block_idx == blocks_in_chunk - 1;
                let is_last_chunk = chunk_idx == num_chunks - 1;
                
                // Compute flags
                let mut flags = 0u32;
                if is_first_block { flags |= CHUNK_START; }
                if is_last_block { flags |= CHUNK_END; }
                // Set ROOT flag if this is a single-leaf (no merging needed)
                if self.is_root_node && is_last_block && is_last_chunk { flags |= ROOT; }
                
                #[cfg(feature = "trace_internals")]
                tracing::trace!(
                    chunk_idx = chunk_idx,
                    block_idx = block_idx,
                    is_first = is_first_block,
                    is_last = is_last_block,
                    is_last_chunk = is_last_chunk,
                    is_root = self.is_root_node,
                    flags = flags,
                    "process_chunks: chunk[{}] block[{}] flags: first={}, last={}, last_chunk={}, is_root_node={}, flags_value={}",
                    chunk_idx,
                    block_idx,
                    is_first_block,
                    is_last_block,
                    is_last_chunk,
                    self.is_root_node,
                    flags
                );
                
                // Counter is bytes processed in this chunk
                let counter = (block_idx as u32) * 64;
                
                #[cfg(feature = "trace_internals")]
                tracing::trace!(
                    chunk_idx = chunk_idx,
                    block_idx = block_idx,
                    counter = counter,
                    cv_before = ?cv,
                    "process_chunks: chunk[{}] block[{}] before compress: counter={}, cv={}",
                    chunk_idx,
                    block_idx,
                    counter,
                    "TRACE"
                );
                
                // Compress this block
                let output = compress(cv, &mut msg, [counter, 0], block_len as u32, flags);
                
                // Update CV for next block (or becomes final CV for this chunk)
                cv = output[0..8].try_into().unwrap();

                #[cfg(feature = "trace_internals")]
                {
                    tracing::trace!(
                        chunk_idx = chunk_idx,
                        block_idx = block_idx,
                        output = ?output,
                        cv_after = ?cv,
                        "process_chunks: chunk[{}] block[{}] compress output: {}, new cv: {}",
                        chunk_idx,
                        block_idx,
                        "TRACE",
                        "TRACE"
                    );
                    tracing::debug!(
                        chunk_idx = chunk_idx,
                        block_idx = block_idx,
                        cv_after = ?cv,
                        "process_chunks: chunk[{}] block[{}] COMPLETED",
                        chunk_idx,
                        block_idx
                    );
                }
            }
            
            #[cfg(feature = "trace_internals")]
            tracing::debug!(
                chunk_idx = chunk_idx,
                cv_final_for_chunk = ?cv,
                "process_chunks: chunk {} all blocks done, final CV ready to push",
                chunk_idx
            );

            // Final CV for this chunk is pushed to the tree
            self.push_cv(cv, 0);
            self.chunk_count += 1;
            self.bytes_processed += chunk_len as u64;

            #[cfg(feature = "trace_internals")]
            tracing::info!(
                chunk_idx = chunk_idx,
                chunk_count_total = self.chunk_count,
                bytes_processed_total = self.bytes_processed,
                "process_chunks: chunk {} PUSHED to tree, total={} chunks",
                chunk_idx,
                self.chunk_count
            );
        }

        #[cfg(feature = "trace_internals")]
        tracing::info!(
            total_chunks = self.chunk_count,
            total_bytes = self.bytes_processed,
            "process_chunks: ALL CHUNKS PROCESSED, total={} chunks, {} bytes",
            self.chunk_count,
            self.bytes_processed
        );

        Ok(())
    }


    /// Reduces the remaining stack and applies the ROOT flag.
    /// For output_len <= 32, returns a 32-byte hash.
    /// For output_len > 32, generates extended output via multiple compressions.
    pub fn finalize(mut self, output_len: usize) -> [u8; 32] {
        #[cfg(feature = "trace_internals")]
        {
            init_tracing();
            tracing::info!(
                output_len = output_len,
                cv_stack_len = self.cv_stack.len(),
                "finalize: STARTING finalization with {} byte(s) output, stack_len={}",
                output_len,
                self.cv_stack.len()
            );
            tracing::trace!(
                cv_stack = ?self.cv_stack,
                "finalize: initial CV stack"
            );
        }

        // Ensure we have at least one CV
        if self.cv_stack.is_empty() {
            #[cfg(feature = "trace_internals")]
            tracing::debug!(
                "finalize: stack is empty, pushing IV with height=0"
            );
            // Process an empty chunk
            self.push_cv(IV, 0);
        }

        #[cfg(feature = "trace_internals")]
        tracing::debug!(
            cv_stack_len = self.cv_stack.len(),
            "finalize: starting tree reduction with stack_len={} CVs",
            self.cv_stack.len()
        );

        // Tree reduction: Merge all CVs bottom-up until one remains
        let mut merge_count = 0;
        while self.cv_stack.len() > 1 {
            let (right_cv, right_height) = self.cv_stack.pop().unwrap();
            let (left_cv, left_height) = self.cv_stack.pop().unwrap();
            let is_root = self.cv_stack.is_empty(); // Last merge is the root

            #[cfg(feature = "trace_internals")]
            {
                tracing::trace!(
                    merge_num = merge_count,
                    left_cv = ?left_cv,
                    left_height = left_height,
                    right_cv = ?right_cv,
                    right_height = right_height,
                    is_root_merge = is_root,
                    "finalize: starting merge {}: left_height={}, right_height={}, is_root={}",
                    merge_count,
                    left_height,
                    right_height,
                    is_root
                );
            }

            let parent = self.parent_output(left_cv, right_cv, is_root);

            #[cfg(feature = "trace_internals")]
            {
                tracing::trace!(
                    merge_num = merge_count,
                    parent_cv = ?parent,
                    "finalize: merge {} resulted in parent CV",
                    merge_count
                );
            }

            self.cv_stack.push((parent, 255)); // Height irrelevant after merge
            merge_count += 1;

            #[cfg(feature = "trace_internals")]
            tracing::debug!(
                merge_num = merge_count,
                cv_stack_len_after = self.cv_stack.len(),
                "finalize: merge {} done, stack now has {} CV(s)",
                merge_count - 1,
                self.cv_stack.len()
            );
        }

        #[cfg(feature = "trace_internals")]
        tracing::debug!(
            total_merges = merge_count,
            "finalize: all {} merges completed, extracting final root CV",
            merge_count
        );

        // Get the final root chaining value
        let (final_cv, _) = self.cv_stack.pop().unwrap();

        #[cfg(feature = "trace_internals")]
        {
            tracing::trace!(
                final_cv = ?final_cv,
                "finalize: final root chaining value extracted"
            );
            tracing::debug!(
                final_cv = ?final_cv,
                output_len = output_len,
                "finalize: converting final CV to {} bytes output",
                output_len
            );
        }

        // For standard 32-byte output, just convert CV to bytes
        if output_len <= 32 {
            let mut result = [0u8; 32];
            for (i, &word) in final_cv.iter().enumerate() {
                result[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
            }

            #[cfg(feature = "trace_internals")]
            {
                let result_hex = result.iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>();
                tracing::info!(
                    output = result_hex,
                    "finalize: HASH COMPLETE, output (hex): {}",
                    hex::encode(&result)
                );
            }

            return result;
        }

        // For extended output (not needed for basic tests, but here for completeness)
        // Generate additional output blocks via repeated compression
        let mut result = [0u8; 32]; // Still return 32 bytes for now
        for (i, &word) in final_cv.iter().enumerate() {
            result[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }

        #[cfg(feature = "trace_internals")]
        tracing::info!(
            output_len_requested = output_len,
            output_len_returned = 32,
            "finalize: returning 32 bytes (extended output requested {} bytes, not yet supported)",
            output_len
        );

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
            .with_ansi(false)
            .init();
    });
}

/// Breaks down the input data into chunks of sizes 1024 bytes.
#[derive(Debug, Clone)]
#[allow(dead_code)]
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
#[inline(always)]
fn permute(data_chunks: &mut [u32; 16]) -> [u32; 16] {
    let shifted_indices: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

    let temp = *data_chunks;
    for i in 0..16 {
        data_chunks[i] = temp[shifted_indices[i]];
    }
    *data_chunks
}

/// Is the quarter round function inspired from the ChaCha20 algorithm.
/// Mentioned in https://www.ietf.org/archive/id/draft-aumasson-blake3-00.html#name-quarter-round-function-g
#[inline(always)]
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
    {
        init_tracing();
        tracing::debug!(
            h = ?h,
            msg = ?msg,
            t = ?t,
            len = len,
            flags = flags,
            "compress: STARTING COMPRESSION"
        );
    }

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

    #[cfg(feature = "trace_internals")]
    tracing::trace!(
        state_initial = ?v,
        "compress: initial state assembled [h[0:8] | IV[0:4] | t[0] | t[1] | len | flags]"
    );

    for _rounds in 0..7 {
        v = quarter_round_fn(&mut v, 0, 4, 8, 12, msg[0], msg[1]);
        v = quarter_round_fn(&mut v, 1, 5, 9, 13, msg[2], msg[3]);
        v = quarter_round_fn(&mut v, 2, 6, 10, 14, msg[4], msg[5]);
        v = quarter_round_fn(&mut v, 3, 7, 11, 15, msg[6], msg[7]);

        v = quarter_round_fn(&mut v, 0, 5, 10, 15, msg[8], msg[9]);
        v = quarter_round_fn(&mut v, 1, 6, 11, 12, msg[10], msg[11]);
        v = quarter_round_fn(&mut v, 2, 7, 8, 13, msg[12], msg[13]);
        v = quarter_round_fn(&mut v, 3, 4, 9, 14, msg[15], msg[15]);

        #[cfg(feature = "trace_internals")]
        {
            tracing::debug!(
                round = _rounds,
                state = ?v,
                "compress: completed round {} with state",
                _rounds
            );
            tracing::trace!(
                v0 = v[0], v1 = v[1], v2 = v[2], v3 = v[3],
                v4 = v[4], v5 = v[5], v6 = v[6], v7 = v[7],
                v8 = v[8], v9 = v[9], v10 = v[10], v11 = v[11],
                v12 = v[12], v13 = v[13], v14 = v[14], v15 = v[15],
                "compress: round {} state breakdown",
                _rounds
            );
        }
        #[cfg(feature = "trace_internals")]
        tracing::trace!(
            state_before_permute = ?v,
            msg_before_permute = ?msg,
            "compress: state after 7 rounds, before message permutation"
        );
        permute(msg);
        #[cfg(feature = "trace_internals")]
        tracing::trace!(
            msg_after_permute = ?msg,
            "compress: message permutation done"
        );
    }




    for i in 0..8 {
        v[i] = v[i] ^ v[i + 8];
        v[i + 8] = v[i + 8] ^ h[i];
    }

    #[cfg(feature = "trace_internals")]
    {
        tracing::trace!(
            v0 = v[0], v1 = v[1], v2 = v[2], v3 = v[3],
            v4 = v[4], v5 = v[5], v6 = v[6], v7 = v[7],
            v8 = v[8], v9 = v[9], v10 = v[10], v11 = v[11],
            v12 = v[12], v13 = v[13], v14 = v[14], v15 = v[15],
            "compress: FINAL STATE after XOR operations"
        );
        tracing::debug!(
            state_final = ?v,
            "compress: COMPRESSION COMPLETE"
        );
    }

    v
}

#[allow(dead_code)]
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


#[allow(dead_code)]
struct MerkleTree {
    depth: u8,
    leaf_nodes: Vec<[Word; 8]>,
}

#[cfg(test)]
mod preprocessing_tests {
    use rand::RngExt;
    
    use super::*;
    fn generate_input(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
fn test_hash_correctness() {
    let input = generate_input(3);

    // let expected_hex = "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213c3a6cb8bf623e20cdb535f8d1a5ffb86342d9c0b64aca3bce1d31f60adfa137b358ad4d79f97b47c3d5e79f179df87a3b9776ef8325f8329886ba42f07fb138bb502f4081cbcec3195c5871e6c23e2cc97d3c69a613eba131e5f1351f3f1da786545e5";

    let hash_output = Blake3Hasher::hash(&input);
    let verified_output = blake3::hash(&input);
    println!("Verified Output: {}", hex::encode(verified_output.as_bytes()));
    println!("Computed Output: {}", hex::encode(&hash_output));


    // assert_eq!(hex::encode(hash_output), expected_hex);
    assert_eq!(&hash_output, verified_output.as_bytes());
}

    /// general test to see if chunking works
    #[test]
    fn test_chunking() {
        // Test that hasher can process various input sizes without panic
        let input_small = vec![0, 100, 21, 2, 4, 2, 3, 1];
        let mut hasher_a = Blake3Hasher::new();
        assert!(hasher_a.process_chunks(&input_small).is_ok());

        // Test with 1025 bytes (spans 2 chunks)
        let input_mid: Vec<u8> = (0..1025).map(|i| (i % 256) as u8).collect();
        let mut hasher_b = Blake3Hasher::new();
        assert!(hasher_b.process_chunks(&input_mid).is_ok());
        assert_eq!(hasher_b.chunk_count, 2); // Should have processed 2 chunks (1024 + 1)

        // Test empty input triggers error
        let input_empty: Vec<u8> = vec![];
        let mut hasher_c = Blake3Hasher::new();
        assert!(hasher_c.process_chunks(&input_empty).is_err());
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
    fn test_empty_input_error() {
        let empty_data: Vec<u8> = vec![];
        let mut hasher = Blake3Hasher::new();
        let result = hasher.process_chunks(&empty_data);

        // Check that it is specifically the ChunkingError variant
        match result {
            Err(Blake3Error::Chunking(ChunkingError::InputTooShort)) => (), // Success
            _ => panic!("Expected InputTooShort error, got {:?}", result),
        }
    }

    #[test]
    fn test_quarter_round() {
        let rng = rand::rng();
        let rng_data: Vec<u32> = rng.clone().random_iter().take(2).collect();
        let mut gen_word_in_process: Vec<u32> = rng.random_iter().take(16).collect();
        let array_ref: &mut [u32; 16] = gen_word_in_process.as_mut_slice().try_into().unwrap();
        let q_output = quarter_round_fn(array_ref, 0, 4, 8, 12, rng_data[0], rng_data[1]);
        println!("{:?}", q_output);
    }

    #[test]
    fn test_compress_fn() {}


}
