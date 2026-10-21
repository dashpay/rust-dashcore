use crate::chain::ChainWork;

impl ChainWork {
    pub fn dummy(work_value: u8) -> ChainWork {
        let mut work_bytes = [0u8; 32];
        work_bytes[31] = work_value;
        ChainWork::from_bytes(work_bytes)
    }
}
