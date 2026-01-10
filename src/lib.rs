type Word = u32;

static iv: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[derive(Debug)]
struct DataChunks<'a> {
    /// Number of bytes of a file.
    input_len: usize,

    /// Input data sliced into 64*64 bits.
    /// First vector is for all chunks of 1024 bytes and
    slices: (Vec<[u8; 1024]>, &'a [u8]),

    /// No of chunks input data broken into.
    chunks: usize,
}

/// breaks given data into chunks of 1024 bytes by mutating passed data.
fn break_into_chunks_at_once_mut<'a>(input_data: &'a mut [u8]) -> DataChunks<'a> {
    /*
    let chunks = input_data.len().div_ceil(1024);
    let mut mem_ptr_front: usize = 0;
    let mut mem_ptr_back: usize = 0;
    let mut chunks_vec: Vec<[u8; 512]> = Vec::new();

    input is less than 1024 elements
    if (mem_ptr_front + 1024).min(input_data.len()) == input_data.len() {
        return DataChunks {
            input_len: input_data.len(),
            slices: ([], input_data.clone().as_slice()),
            chunks: 1,
        };
    }

    while mem_ptr_front <= input_data.len() && mem_ptr_back < input_data.len() {
        // println!("{},{},{} \n",mem_ptr_front,mem_ptr_back,input_data[mem_ptr_back..mem_ptr_front].len());
        mem_ptr_front = (mem_ptr_front + 1024).min(input_data.len());

        chunks_vec.push(input_data[mem_ptr_back..mem_ptr_front].try_into().unwrap());
        mem_ptr_back = (mem_ptr_back + 1024).min(input_data.len());
        // println!("{},{} \n",mem_ptr_front,mem_ptr_back);
    }
    return DataChunks {
        input_len: input_data.len(),
        slices: chunks_vec.as_slice(),
        chunks: chunks,
    };
    */

    let (chunks, remainder) = input_data.as_chunks::<1024>();

    return DataChunks {
        input_len: input_data.len(),
        slices: (chunks.to_vec(), remainder),
        chunks: chunks.len(),
    };
}

/// permute fn as  which shifts values at indices given in input_indices to shifted_indices
/// Mentioned in https://www.ietf.org/archive/id/draft-aumasson-blake3-00.html#name-message-word-permutation
fn permute(data_chunks: [u32; 16]) {
    let input_indices: [usize; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let shifted_indices: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
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
    word_in_process[a] = (word_in_process[a] + word_in_process[b] + x) % u32::MAX;
    word_in_process[d] = (word_in_process[d] ^ word_in_process[a]).rotate_right(16);
    word_in_process[c] = (word_in_process[c] + word_in_process[d]) % u32::MAX;
    word_in_process[b] = (word_in_process[b] ^ word_in_process[c]).rotate_right(12);
    word_in_process[a] = (word_in_process[a] + word_in_process[b] + y) % u32::MAX;
    word_in_process[d] = (word_in_process[d] ^ word_in_process[a]).rotate_right(12);
    word_in_process[c] = (word_in_process[c] + word_in_process[d]) % u32::MAX;
    word_in_process[b] = (word_in_process[b] ^ word_in_process[c]).rotate_right(7);

    let word_in_process = word_in_process;
    *word_in_process
}

fn compress(h: [u32; 8], msg: [u32; 16], t: [u32; 2], len: u32, flags: u32) {
    let mut v: [u32; 16] = [0; 16];
    for (index, val) in h.iter().enumerate() {
        v[index] = *val;
    }
    for (index, val) in iv.iter().enumerate() {
        v[index + 8] = *val;
    }
    v[12] = t[0];
    v[13] = t[1];
    v[14] = len;
    v[15] = flags;

    for rounds in 0..6 {
        v = quarter_round_fn(&mut v, 0, 4, 8, 12, msg[0], msg[1]);
        v = quarter_round_fn(&mut v, 1, 5, 9, 13, msg[2], msg[3]);
        v = quarter_round_fn(&mut v, 2, 6, 10, 14, msg[4], msg[5]);
        v = quarter_round_fn(&mut v, 3, 7, 11, 15, msg[6], msg[7]);

        v = quarter_round_fn(&mut v, 0, 5, 10, 15, msg[8], msg[9]);
        v = quarter_round_fn(&mut v, 1, 6, 11, 12, msg[10], msg[11]);
        v = quarter_round_fn(&mut v, 2, 7, 8, 13, msg[12], msg[13]);
        v = quarter_round_fn(&mut v, 3, 4, 9, 14, msg[15], msg[15]);
    }
    permute(msg);
}

// fn construct_merkle_tree() {}

#[cfg(test)]
mod preprocessing_tests {
    use super::*;
    #[test]
    fn check_chunking_general() {
        let input: Vec<u8> = vec![0, 100, 21, 2, 4, 2, 3, 1];
        // let chunked_op = break_into_chunks_at_once(BreakIntoChunksOptions::CopyValue(input));
        // println!("{:?}", chunked_op);
    }
}
