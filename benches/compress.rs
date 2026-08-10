    fn criterion_bench_quarter_round_scalar_vs_avx2() {
        use criterion::Criterion;
        use std::hint::black_box;
        use std::arch::is_x86_feature_detected;
        use std::arch::x86_64::{__m256i, _mm256_loadu_si256};
        use blake3_optimized::quarter_round_fn;
        use blake3_optimized::simd::avx2::{quarter_round_simd,SimdState};

        if !is_x86_feature_detected!("avx2") {
            eprintln!("skipping Criterion benchmark: AVX2 is not available on this CPU");
            return;
        }

        const LANES: usize = 8;
        const INDICES: (usize, usize, usize, usize) = (0, 4, 8, 12);

        let initial_states: [[u32; 16]; LANES] = std::array::from_fn(|lane| {
            std::array::from_fn(|word| {
                (lane as u32).wrapping_mul(0x9E37_79B9)
                    ^ (word as u32).wrapping_mul(0x85EB_CA6B)
                    ^ 0xC2B2_AE35
            })
        });
        let x: [u32; LANES] = std::array::from_fn(|lane| {
            0xA5A5_A5A5u32.wrapping_add((lane as u32).wrapping_mul(0x0101_0101))
        });
        let y: [u32; LANES] = std::array::from_fn(|lane| {
            0x5A5A_5A5Au32.wrapping_add((lane as u32).wrapping_mul(0x0101_0101))
        });

        let simd_words: [[u32; LANES]; 16] =
            std::array::from_fn(|word| std::array::from_fn(|lane| initial_states[lane][word]));
        let mut criterion = Criterion::default();
        let mut group = criterion.benchmark_group("quarter_round");

        group.bench_function("scalar_x8", |bencher| {
            let mut scalar_states = initial_states;
            bencher.iter(|| {
                for lane in 0..LANES {
                    quarter_round_fn(
                        &mut scalar_states[lane],
                        INDICES.0,
                        INDICES.1,
                        INDICES.2,
                        INDICES.3,
                        x[lane],
                        y[lane],
                    );
                }
                black_box(&scalar_states);
            });
        });

        group.bench_function("avx2_x8", |bencher| {
            let mut simd_state: SimdState = unsafe { std::mem::zeroed() };
            let (x, y) = unsafe {
                for word in 0..16 {
                    simd_state.v[word] =
                        _mm256_loadu_si256(simd_words[word].as_ptr().cast::<__m256i>());
                }
                (
                    _mm256_loadu_si256(x.as_ptr().cast::<__m256i>()),
                    _mm256_loadu_si256(y.as_ptr().cast::<__m256i>()),
                )
            };
            bencher.iter(|| unsafe {
                quarter_round_simd(
                    &mut simd_state,
                    INDICES.0,
                    INDICES.1,
                    INDICES.2,
                    INDICES.3,
                    x,
                    y,
                );
                black_box(&simd_state);
            });
        });

        group.finish();
        criterion.final_summary();
    }

    #[inline(always)]
    fn criterion_bench_permute_scalar_vs_avx2() {
        use blake3_optimized::permute;
        use blake3_optimized::simd::avx2::permute_simd;
        use criterion::Criterion;
        use std::hint::black_box;
        use std::arch::x86_64::{__m256i, _mm256_loadu_si256};

        let initial: [u32; 16] = std::array::from_fn(|word| {
            (word as u32).wrapping_mul(0x9E37_79B9) ^ 0xC2B2_AE35
        });
        let mut criterion = Criterion::default();
        let mut group = criterion.benchmark_group("permute");

        group.bench_function("scalar", |bencher| {
            let mut words = initial;
            bencher.iter(|| black_box(permute(black_box(&mut words))));
        });

        group.bench_function("avx2", |bencher| {
            let mut words = unsafe {
                [
                    _mm256_loadu_si256(initial[..8].as_ptr().cast::<__m256i>()),
                    _mm256_loadu_si256(initial[8..].as_ptr().cast::<__m256i>()),
                ]
            };
            bencher.iter(|| unsafe {
                permute_simd(black_box(&mut words));
                black_box(&words);
            });
        });

        group.finish();
        criterion.final_summary();
    }

    fn main(){
        criterion_bench_quarter_round_scalar_vs_avx2();
        criterion_bench_permute_scalar_vs_avx2();
    }
