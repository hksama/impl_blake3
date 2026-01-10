type Word = u32;


static iv:[u32;8] = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];


#[derive(Debug)]
struct DataChunks<'a> {
    /// Number of bytes of a file.
    input_len: usize,

    /// Input data sliced into 64*64 bits.
    /// First vector is for all chunks of 1024 bytes and
    slices: (ReturnedChunks<'a>, &'a [u8]),

    /// No of chunks input data broken into.
    chunks: usize,
}

union ReturnedChunks<'a> {
    non_empty_chunks: &'a [[u8; 512]],
    empty_chunks: [u8; 0],
}

pub enum BreakIntoChunksOptions {
    /// Mutate passed input.
    MutateValue(Vec<u8>),

    /// Creates a copy of the values and works on them.
    CopyValue(Vec<u8>),
}

fn break_into_chunks_at_once<'a>(input_data_with_flags: BreakIntoChunksOptions) -> DataChunks<'a> {
    match input_data_with_flags {
        BreakIntoChunksOptions::CopyValue(input_data) => {
            let chunks = input_data.len().div_ceil(1024);
            let mut mem_ptr_front: usize = 0;
            let mut mem_ptr_back: usize = 0;
            let mut chunks_vec: Vec<[u8; 512]> = Vec::new();

            // input is less than 1024 elements
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
        }
        BreakIntoChunksOptions::MutateValue(input_data) => {
            let (chunks, remainder) = input_data.as_chunks::<512>();

            return DataChunks {
                input_len: input_data.len(),
                slices: (chunks, remainder),
                chunks: chunks.len(),
            };
        }
    }
}

/// permute fn as  which shifts values at indices given in input_indices to shifted_indices
/// Mentioned in https://www.ietf.org/archive/id/draft-aumasson-blake3-00.html#name-message-word-permutation
fn permute(data_chunks: ()) {
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
    x: [Word; 1],
    y: [Word; 1],
)->[u32;16] {
    word_in_process[a] = (word_in_process[a] + word_in_process[b] + x[0]) % u32::MAX;
    word_in_process[d] = (word_in_process[d] ^ word_in_process[a]).rotate_right(16); 
    word_in_process[c] = (word_in_process[c] + word_in_process[d]) % u32::MAX;
    word_in_process[b] = (word_in_process[b] ^ word_in_process[c]).rotate_right(12); 
    word_in_process[a] = (word_in_process[a] + word_in_process[b] + y[0]) % u32::MAX;
    word_in_process[d] = (word_in_process[d] ^ word_in_process[a]).rotate_right(12); 
    word_in_process[c] = (word_in_process[c] + word_in_process[d]) % u32::MAX;
    word_in_process[b] = (word_in_process[b] ^ word_in_process[c]).rotate_right(7); 


    let word_in_process =word_in_process;
    *word_in_process
}


fn compress(h:[u32;8],msg:[u32;16],t:[u32;2],len:u32,flags:u32){
    let mut v:[u32;16]=[0;16];
    v[0..7] = h[0..7];
    v[8..11] = iv[0..3];
}






#[cfg(test)]
mod preprocessing_tests {
    use super::*;
    #[test]
    fn check_chunking_general() {
        let input: Vec<u8> = vec![0, 100, 21, 2, 4, 2, 3, 1];
        let chunked_op = break_into_chunks_at_once(BreakIntoChunksOptions::CopyValue(input));
        println!("{:?}", chunked_op);
    }
}
