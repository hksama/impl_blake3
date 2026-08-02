// Methods for AVX2 SIMD operations.
use std::arch::x86_64::*;

// #[target_feature(enable = "avx2")]
// pub unsafe fn quarter_round_avx2(word_in_process: &mut [u32; 16], a: &mut [u32; 4], b: &mut [u32; 4], c: &mut [u32; 4], d: &mut [u32; 4],x:Word,y:Word) {
//     // Implement the quarter round operation using AVX2 intrinsics.
// }

#[repr(C)]
pub struct SimdState {
    pub v: [__m256i; 16],
}

// #[inline(always)]
#[target_feature(enable = "avx2")]
unsafe fn rotr16(x: __m256i) -> __m256i {
    let r = _mm256_srli_epi32(x, 16);
    let l = _mm256_slli_epi32(x, 16);
    _mm256_or_si256(r, l)
}

// #[inline(always)]
#[target_feature(enable = "avx2")]
unsafe fn rotr12(x: __m256i) -> __m256i {
    let r = _mm256_srli_epi32(x, 12);
    let l = _mm256_slli_epi32(x, 20);
    _mm256_or_si256(r, l)
}

// #[inline(always)]
#[target_feature(enable = "avx2")]
unsafe fn rotr8(x: __m256i) -> __m256i {
    let r = _mm256_srli_epi32(x, 8);
    let l = _mm256_slli_epi32(x, 24);
    _mm256_or_si256(r, l)
}

// #[inline(always)]
#[target_feature(enable = "avx2")]
unsafe fn rotr7(x: __m256i) -> __m256i {
    let r = _mm256_srli_epi32(x, 7);
    let l = _mm256_slli_epi32(x, 25);
    _mm256_or_si256(r, l)
}

#[target_feature(enable = "avx2")]
pub unsafe fn quarter_round_simd(
    state: &mut SimdState,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    x: __m256i,
    y: __m256i,
) {
    state.v[a] = _mm256_add_epi32(state.v[a], state.v[b]);
    state.v[a] = _mm256_add_epi32(state.v[a], x);

    state.v[d] = _mm256_xor_si256(state.v[d], state.v[a]);
    state.v[d] = unsafe { rotr16(state.v[d]) };

    state.v[c] = _mm256_add_epi32(state.v[c], state.v[d]);

    state.v[b] = _mm256_xor_si256(state.v[b], state.v[c]);
    state.v[b] = unsafe { rotr12(state.v[b]) };

    state.v[a] = _mm256_add_epi32(state.v[a], state.v[b]);
    state.v[a] = _mm256_add_epi32(state.v[a], y);

    state.v[d] = _mm256_xor_si256(state.v[d], state.v[a]);
    state.v[d] = unsafe{rotr8(state.v[d])};

    state.v[c] = _mm256_add_epi32(state.v[c], state.v[d]);

    state.v[b] = _mm256_xor_si256(state.v[b], state.v[c]);
    state.v[b] = unsafe { rotr7(state.v[b]) };
}

/// Applies the BLAKE3 message-word permutation to two packed eight-word vectors.
/// `words[0]` contains words 0..8 and `words[1]` contains words 8..16.
// #[inline(always)]
#[target_feature(enable = "avx2")]
pub unsafe fn permute_simd(words: &mut [__m256i; 2]) {
    let low = words[0];
    let high = words[1];

    let low_from_low = _mm256_permutevar8x32_epi32(low, _mm256_setr_epi32(2, 6, 3, 0, 7, 0, 4, 0));
    let low_from_high = _mm256_permutevar8x32_epi32(high, _mm256_setr_epi32(0, 0, 0, 2, 0, 0, 0, 5));
    let high_from_low = _mm256_permutevar8x32_epi32(low, _mm256_setr_epi32(1, 0, 0, 5, 0, 0, 0, 0));
    let high_from_high = _mm256_permutevar8x32_epi32(high, _mm256_setr_epi32(0, 3, 4, 0, 1, 6, 7, 0));

    words[0] = _mm256_blend_epi32(low_from_low, low_from_high, 0b1000_1000);
    words[1] = _mm256_blend_epi32(high_from_low, high_from_high, 0b1111_0110);
}

#[cfg(target_arch = "x86_64")]
    mod avx2_simd_tests {
    use super::*;
    use rand::{rngs::StdRng,SeedableRng,RngExt};

    #[test]
    fn quarter_round_simd_matches_scalar_for_random_batches() {
        use std::arch::is_x86_feature_detected;
        use std::arch::x86_64::{__m256i, _mm256_loadu_si256, _mm256_storeu_si256};

        if !is_x86_feature_detected!("avx2") {
            return;
        }

        const LANES: usize = 8;
        const BATCHES: usize = 10_000;
        const INDEX_SETS: [(usize, usize, usize, usize); 8] = [
            (0, 4, 8, 12),
            (1, 5, 9, 13),
            (2, 6, 10, 14),
            (3, 7, 11, 15),
            (0, 5, 10, 15),
            (1, 6, 11, 12),
            (2, 7, 8, 13),
            (3, 4, 9, 14),
        ];

        let mut rng = StdRng::seed_from_u64(0xA2_56_2D_71_FF_09_C3_4B);

        for batch in 0..BATCHES {
            let (a, b, c, d) = INDEX_SETS[rng.random_range(0..INDEX_SETS.len())];
            let mut scalar_states = [[0u32; 16]; LANES];
            let mut simd_words = [[0u32; LANES]; 16];
            let mut x = [0u32; LANES];
            let mut y = [0u32; LANES];

            for lane in 0..LANES {
                for word in 0..16 {
                    let value = rng.random();
                    scalar_states[lane][word] = value;
                    simd_words[word][lane] = value;
                }
                x[lane] = rng.random();
                y[lane] = rng.random();
                crate::quarter_round_fn(&mut scalar_states[lane], a, b, c, d, x[lane], y[lane]);
            }

            let mut simd_state: SimdState = unsafe { std::mem::zeroed() };
            unsafe {
                for word in 0..16 {
                    simd_state.v[word] = _mm256_loadu_si256(simd_words[word].as_ptr().cast::<__m256i>());
                }
                quarter_round_simd(
                    &mut simd_state,
                    a,
                    b,
                    c,
                    d,
                    _mm256_loadu_si256(x.as_ptr().cast::<__m256i>()),
                    _mm256_loadu_si256(y.as_ptr().cast::<__m256i>()),
                );
                for word in 0..16 {
                    _mm256_storeu_si256(simd_words[word].as_mut_ptr().cast::<__m256i>(), simd_state.v[word]);
                }
            }

            for lane in 0..LANES {
                let actual = std::array::from_fn(|word| simd_words[word][lane]);
                assert_eq!(
                    actual, scalar_states[lane],
                    "SIMD/scalar mismatch in batch {batch}, lane {lane}, indices ({a}, {b}, {c}, {d})"
                );
            }
        }
    }

    #[test]
    fn permute_simd_matches_scalar_for_random_inputs() {
        use std::arch::x86_64::{__m256i, _mm256_loadu_si256, _mm256_storeu_si256};

        const CASES: usize = 10_000;
        let mut rng = StdRng::seed_from_u64(0xB1_A6_E3_F0_2026_0415);

        for case in 0..CASES {
            let mut expected = std::array::from_fn(|_| rng.random::<u32>());
            let mut actual = expected;
            let mut packed = unsafe {
                [
                    _mm256_loadu_si256(actual[..8].as_ptr().cast::<__m256i>()),
                    _mm256_loadu_si256(actual[8..].as_ptr().cast::<__m256i>()),
                ]
            };

            crate::permute(&mut expected);
            unsafe {
                permute_simd(&mut packed);
                _mm256_storeu_si256(actual[..8].as_mut_ptr().cast::<__m256i>(), packed[0]);
                _mm256_storeu_si256(actual[8..].as_mut_ptr().cast::<__m256i>(), packed[1]);
            }

            assert_eq!(actual, expected, "SIMD/scalar permutation mismatch in case {case}");
        }
    }

    
    
}
