use ::utils::padding::{ Padding, PaddingError };


pub trait SingleBlockEncrypt {
    fn bs() -> usize;
    fn encrypt(&self, data: &[u8]) -> Vec<u8>;
}

pub trait SingleBlockDecrypt {
    fn bs() -> usize;
    fn decrypt(&self, data: &[u8]) -> Vec<u8>;
}


pub trait BlockEncrypt {
    fn bs(&self) -> usize;
    fn encrypt<P: Padding>(&mut self, data: &[u8]) -> Vec<u8>;
}

pub trait BlockDecrypt {
    fn bs(&self) -> usize;
    fn decrypt<P: Padding>(&mut self, data: &[u8]) -> Result<Vec<u8>, PaddingError>;
}


pub trait StreamEncrypt {
    fn encrypt(&mut self, data: &[u8]) -> Vec<u8>;
}

pub trait StreamDecrypt {
    fn decrypt(&mut self, data: &[u8]) -> Vec<u8>;
}
