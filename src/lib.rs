type Word = u32;
use std::cmp::min;
mod error;
/// initialisation vector
static IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];


/// Breaks down the input data into chunks of sizes 1024 bytes.
#[derive(Debug,Clone)]
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

/// breaks given data into chunks of 1024 bytes by mutating passed data in place.
fn break_into_chunks_inplace<'a>(input_data: &'a mut [u8]) -> Result<DataChunks<'a>,String> {
    if input_data.len() == 0{
        return Err(String::from("Input length too short!"))
    }

    let (chunks, remainder) = input_data.as_chunks::<1024>();

    return Ok(DataChunks {
        input_len: input_data.len(),
        slices: (chunks, remainder),
        chunks: min(chunks.len(),1),
    })

}

/// permute fn as  which shifts values at indices given in input_indices to shifted_indices
/// Mentioned in https://www.ietf.org/archive/id/draft-aumasson-blake3-00.html#name-message-word-permutation
fn permute(data_chunks: &mut [u32; 16])->[u32;16] {
    let input_indices: [usize; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let shifted_indices: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

    let mut temp = *data_chunks;
    for i in 0..17{
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
    word_in_process[a] = (word_in_process[a] + word_in_process[b] + x) % u32::MAX;
    word_in_process[d] = (word_in_process[d] ^ word_in_process[a]).rotate_right(16);
    word_in_process[c] = (word_in_process[c] + word_in_process[d]) % u32::MAX;
    word_in_process[b] = (word_in_process[b] ^ word_in_process[c]).rotate_right(12);
    word_in_process[a] = (word_in_process[a] + word_in_process[b] + y) % u32::MAX;
    word_in_process[d] = (word_in_process[d] ^ word_in_process[a]).rotate_right(8);
    word_in_process[c] = (word_in_process[c] + word_in_process[d]) % u32::MAX;
    word_in_process[b] = (word_in_process[b] ^ word_in_process[c]).rotate_right(7);

    //shadowing to make word_in_process immutable
    let word_in_process = word_in_process;
    *word_in_process
}

/// Is the BLAKE3_COMPRESS fn 
/// mentioned in https://www.ietf.org/archive/id/draft-aumasson-blake3-00.html#name-compression-function-proces
fn compress<'a>(h: [u32; 8], msg: &'a mut [u32; 16], t: [u32; 2], len: u32, flags: u32) {
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

struct MerkleTree{
    depth:u8,
    leaf_nodes:Vec<[Word;8]>,
    // intermediate_nodes:Has
}

#[cfg(test)]
mod preprocessing_tests {
    use rand::{RngExt, rng};

    use super::*;

    /// general test to see if chunking works 
    #[test]
    fn test_chunking() {
        //general test
        let mut input: Vec<u8> = vec![0, 100, 21, 2, 4, 2, 3, 1];
        let rng = rand::rng();

        //if remainder is registered
        let mut rng_data:Vec<u8> = rng.clone().random_iter().take(1025).collect();

        // no elements edge case
        let mut rng_data_2:Vec<u8> = rng.random_iter().take(0).collect();
        let chunks_a = break_into_chunks_inplace(&mut input);
        let chunks_b=break_into_chunks_inplace(&mut rng_data);
        let chunks_c=break_into_chunks_inplace(&mut rng_data_2);
        println!("{:?}",&chunks_a);
        println!("{:?}",chunks_b);
        println!("{:?}",chunks_c);

        assert_eq!(chunks_a.clone().unwrap().chunks,0);
        assert_eq!(chunks_a.clone().unwrap().slices.0.len(),0);
        assert_eq!(chunks_b.unwrap().chunks,1);
        // assert_eq!(chunks_b)

    }

    #[test]
    fn test_quarter_round(){
        let rng = rand::rng();
        let mut rng_data:Vec<u32> = rng.clone().random_iter().take(2).collect();
        let mut gen_word_in_process:Vec<u32> = rng.random_iter().take(16).collect();
        let array_ref: &mut [u32; 16] = gen_word_in_process.as_mut_slice().try_into().unwrap();
        let q_output = quarter_round_fn(array_ref, 0,4,8,12,rng_data[0],rng_data[1]);
    }
}
