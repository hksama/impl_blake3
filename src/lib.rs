
#[derive(Debug)]
struct DataChunks<'a>{
    /// Number of bytes of a file.
    input_len:usize,

    /// Input data sliced into 64*64 bits.
    /// First vector is for all chunks of 1024 bytes and 
    slices:(Vec<[u8;512]>,Vec<&'a[u8]>),

    /// No of chunks input data broken into.
    chunks:usize


}

pub enum BreakIntoChunksOptions{
    /// Mutate passed input data; need to pass input data as mutable reference
    MutateValue(Vec<u8>),

    /// Creates a copy of the value; passed value need not be mutable.
    CopyValue(Vec<u8>)
}


fn break_into_chunks_at_once(input_data_with_flags:BreakIntoChunksOptions)->DataChunks{


   match input_data_with_flags{
    BreakIntoChunksOptions::CopyValue(input_data)=>{
        let chunks = input_data.len().div_ceil(1024);
        let mut mem_ptr_front:usize=0;
        let mut mem_ptr_back:usize=0;
        let mut chunks_vec:Vec<[u8;512]> = Vec::new();

        while mem_ptr_front<=input_data.len() && mem_ptr_back<input_data.len(){
            // println!("{},{},{} \n",mem_ptr_front,mem_ptr_back,input_data[mem_ptr_back..mem_ptr_front].len());
            mem_ptr_front = (mem_ptr_front+1024).min(input_data.len());
            chunks_vec.push(input_data[mem_ptr_back..mem_ptr_front].try_into().unwrap());
            mem_ptr_back = (mem_ptr_back+1024).min(input_data.len());
            // println!("{},{} \n",mem_ptr_front,mem_ptr_back);
        }
        return DataChunks { input_len: input_data.len(), slices: chunks_vec, chunks:chunks }
    },
    BreakIntoChunksOptions::MutateValue(input_data)=>{
        let chunks = input_data.len().div_ceil(1024);
        let mut mem_ptr_front:usize=0;
        let mut mem_ptr_back:usize=0;
        let mut chunks_vec:Vec<[u8;512]> = Vec::new();

        while mem_ptr_front<=input_data.len() && mem_ptr_back<input_data.len(){
            mem_ptr_front = (mem_ptr_front+1024).min(input_data.len());
            chunks_vec.push(input_data[mem_ptr_back..mem_ptr_front].try_into().unwrap());
            mem_ptr_back = (mem_ptr_back+1024).min(input_data.len());
        }   
        return DataChunks { input_len: input_data.len(), slices: chunks_vec, chunks:chunks }
    }
   }
}

#[cfg(test)]
mod preprocessing_tests{
    use super::*;
    #[test]
    fn check_chunking_general(){
        let input:Vec<u8> = vec![0,100,21,2,4,2,3,1];
        let chunked_op = break_into_chunks_at_once(BreakIntoChunksOptions::CopyValue(input));
        println!("{:?}",chunked_op);
    }
}