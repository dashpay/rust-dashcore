#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct LLMQIndexedHash {
    pub index: u32,
    pub hash: [u8; 32],
}

impl LLMQIndexedHash {
    pub fn new(hash: [u8; 32], index: u32) -> Self { LLMQIndexedHash { index, hash } }
}

impl From<([u8; 32], usize)> for LLMQIndexedHash {
    fn from(value: ([u8; 32], usize)) -> Self { Self::new(value.0, value.1 as u32) }
}
impl From<([u8; 32], u32)> for LLMQIndexedHash {
    fn from(value: ([u8; 32], u32)) -> Self { Self::new(value.0, value.1) }
}
