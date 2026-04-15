fn main() {
    let input = vec![0u8];
    let hash = blake3::hash(&input);
    println!("Hash of single 0x00 byte: {}", hash.to_hex());
    
    // Also test empty scenario
    let hash_empty = blake3::hash(&[]);
    println!("Hash of empty: {}", hash_empty.to_hex());
    
    // Test 0-2 bytes
    for len in 0..3 {
        let input: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
        let hash = blake3::hash(&input);
        println!("Hash of {} bytes: {}", len, hash.to_hex());
    }
}
