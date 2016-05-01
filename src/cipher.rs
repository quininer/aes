pub trait SingleBlockEncrypt {
    fn bs() -> usize;
    fn encrypt(&self, data: &[u8]) -> Vec<u8>;
}

pub trait SingleBlockDecrypt {
    fn bs() -> usize;
    fn decrypt(&self, data: &[u8]) -> Vec<u8>;
}
