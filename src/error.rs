use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum Blake3Error {
    /// Errors related to the chunking process
    #[error(transparent)]
    Chunking(#[from] ChunkingError),
}

#[derive(Error, Debug, Clone)]
pub enum ChunkingError {
    #[error("Input length is zero; BLAKE3 requires at least 1 byte.")]
    InputTooShort,
}
