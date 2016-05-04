use ::AES;
use ::utils::padding::Padding;
use ::cipher::{
    DecryptFail,
    SingleBlockEncrypt, SingleBlockDecrypt,
    BlockEncrypt, BlockDecrypt
};


#[derive(Clone, Debug)]
pub struct Ecb<C> {
    cipher: C
}

impl Ecb<AES> {
    pub fn new(key: &[u8]) -> Ecb<AES> {
        Ecb { cipher: AES::new(key) }
    }
}

impl<C> BlockEncrypt for Ecb<C> where C: SingleBlockEncrypt {
    fn bs(&self) -> usize { C::bs() }
    fn encrypt<P: Padding>(&mut self, data: &[u8]) -> Vec<u8> {
        P::padding(data, self.bs()).chunks(self.bs())
            .map(|b| self.cipher.encrypt(b))
            .fold(Vec::new(), |mut sum, mut next| {
                sum.append(&mut next);
                sum
            })
    }
}

impl<C> BlockDecrypt for Ecb<C> where C: SingleBlockDecrypt {
    fn bs(&self) -> usize { C::bs() }
    fn decrypt<P: Padding>(&mut self, data: &[u8]) -> Result<Vec<u8>, DecryptFail> {
        P::unpadding(
            &data.chunks(self.bs())
                .map(|b| self.cipher.decrypt(b))
                .fold(Vec::new(), |mut sum, mut next| {
                    sum.append(&mut next);
                    sum
                }),
            self.bs()
        ).map_err(|err| err.into())
    }
}
