#[derive(Debug, PartialEq)]
pub enum PaddingError {
    BadData,
    BadPadding,
    Other
}

pub trait Padding {
    fn padding(&[u8], usize) -> Vec<u8>;
    fn unpadding(&[u8], usize) -> Result<Vec<u8>, PaddingError>;
}


pub struct NoPadding;

impl Padding for NoPadding {
    fn padding(data: &[u8], _: usize) -> Vec<u8> { data.into() }
    fn unpadding(data: &[u8], _: usize) -> Result<Vec<u8>, PaddingError> { Ok(data.into()) }
}


pub struct Pkcs7Padding;

impl Padding for Pkcs7Padding {
    fn padding(data: &[u8], len: usize) -> Vec<u8> {
        let pad = len - data.len() % len;
        let mut out: Vec<u8> = data.into();
        out.append(&mut vec![pad as u8; pad]);
        out
    }
    fn unpadding(data: &[u8], len: usize) -> Result<Vec<u8>, PaddingError> {
        if data.len() % len != 0 { Err(PaddingError::BadData)? };
        let &pad = data.last().unwrap();
        if len < pad as usize { Err(PaddingError::BadPadding)? };
        let data_len = data.len() - pad as usize;

        if !data[data_len..].iter().any(|&r| r != pad) {
            Ok(data[..data_len].into())
        } else {
            Err(PaddingError::BadPadding)
        }
    }
}
