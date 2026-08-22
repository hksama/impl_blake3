use blake3_optimized::Blake3Hasher;
use memmap2::Mmap;
use std::env;
use std::fs::File;
use std::process;

fn main() {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "vtune_bench".to_string());

    let input_path = match args.next() {
        Some(path) => path,
        None => {
            eprintln!("Usage: {program} <input_file> <iterations>");
            process::exit(1);
        }
    };

    let iterations: usize = match args.next().and_then(|s| s.parse().ok()) {
        Some(n) if n > 0 => n,
        _ => {
            eprintln!("Usage: {program} <input_file> <iterations>");
            eprintln!("iterations must be a positive integer");
            process::exit(1);
        }
    };

    if args.next().is_some() {
        eprintln!("Usage: {program} <input_file> <iterations>");
        process::exit(1);
    }

    let file = File::open(&input_path).unwrap_or_else(|err| {
        eprintln!("failed to open {input_path}: {err}");
        process::exit(1);
    });

    // SAFETY: read-only mapping; input file is not mutated during profiling.
    let mmap = unsafe { Mmap::map(&file) }.unwrap_or_else(|err| {
        eprintln!("failed to mmap {input_path}: {err}");
        process::exit(1);
    });

    let file_size = mmap.len();
    if file_size == 0 {
        eprintln!("input file is empty; BLAKE3 requires at least 1 byte");
        process::exit(1);
    }

    println!("input_file={input_path}");
    println!("file_size_bytes={file_size}");
    println!("iterations={iterations}");

    let mut digest = [0u8; 32];
    for _ in 0..iterations {
        digest = Blake3Hasher::hash(&mmap);
    }

    println!("digest={}", hex::encode(digest));
}
