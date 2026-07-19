// Methods for AVX2 SIMD operations.
use std::arch::x86_64::*;
#[expect(clippy::undocumented_unsafe_blocks)]
#[deny(unsafe_op_in_unsafe_fn)]

#[target_feature(enable = "avx2")]
pub unsafe fn quarter_round_avx2(data_in_process: &mut [u32; 64], a: &mut [u32; 16], b: &mut [u32; 16], c: &mut [u32; 16], d: &mut [u32; 16],x:[u32; 4],y:[u32; 4]) {
    // Implement the quarter round operation using AVX2 intrinsics.
    // let op1 = add(a, b)
    let values = [0u32; 8];



}


// /// Helper function to extract required u32 from different slices and feed them
// fn extract_u32_and_feed(data:){

// }

#[target_feature(enable = "avx2")]
unsafe fn add(a: __m256i, b: __m256i) -> __m256i {
    _mm256_add_epi32(a, b)
}

#[target_feature(enable = "avx2")]
unsafe fn add_msg(
    state: __m256i,
    msg: __m256i,
) -> __m256i {
    _mm256_add_epi32(state, msg)
}

#[target_feature(enable = "avx2")]
unsafe fn xor(
    a: __m256i,
    b: __m256i,
) -> __m256i {
    _mm256_xor_si256(a, b)
}


#[target_feature(enable = "avx2")]
unsafe fn rotr16(x: __m256i) -> __m256i {
    let r = _mm256_srli_epi32(x, 16);
    let l = _mm256_slli_epi32(x, 16);
    _mm256_or_si256(r, l)
}


#[target_feature(enable = "avx2")]
unsafe fn rotr12(x: __m256i) -> __m256i {
    let r = _mm256_srli_epi32(x, 12);
    let l = _mm256_slli_epi32(x, 20);
    _mm256_or_si256(r, l)
}

#[target_feature(enable = "avx2")]
unsafe fn rotr7(x: __m256i) -> __m256i {
    let r = _mm256_srli_epi32(x, 7);
    let l = _mm256_slli_epi32(x, 25);
    _mm256_or_si256(r, l)
}

#[target_feature(enable = "avx2")]
unsafe fn rotr8(x: __m256i) -> __m256i {
    let r = _mm256_srli_epi32(x, 8);
    let l = _mm256_slli_epi32(x, 24);
    _mm256_or_si256(r, l)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        let a = unsafe { _mm256_setzero_si256() };
        let b = unsafe { _mm256_setzero_si256() };
        let result = unsafe { add(a, b) };
        assert_eq!(unsafe { _mm256_extract_epi32(result, 0) }, 0);
    }
}
