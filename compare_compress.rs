// Direct comparison of compress functions
use blake3::BLAKE3_Hasher;

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn main() {
    // 1-byte input [0]
    let input = [0u8];
    
    // User's implementation
    let user_hash = BLAKE3_Hasher::hash(&input);
    println!("User's hash:      {}", hex::encode(&user_hash));
    
    // Reference implementation
    let ref_hash = blake3::hash(&input);
    println!("Reference hash:   {}", hex::encode(ref_hash.as_bytes()));
    
    // Expected
    println!("Expected:         2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213");
    
    // Message block for 1-byte input [0] padded to 64 bytes
    let mut block = [0u8; 64];
    block[0] = 0;  // The actual input byte
    
    println!("\n=== Message block (first 16 bytes) ===");
    println!("{:?}", &block[..16]);
}
