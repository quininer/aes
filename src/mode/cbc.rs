use ::AES;
use ::utils::xor;
use ::utils::padding::Padding;
use ::cipher::{
    DecryptFail,
    SingleBlockEncrypt, SingleBlockDecrypt,
    BlockEncrypt, BlockDecrypt
};


#[derive(Clone, Debug)]
pub struct Cbc<C> {
    cipher: C,
    iv: Vec<u8>
}

impl<C> Cbc<C> {
    pub fn set_iv(&mut self, iv: &[u8]) -> &mut Self {
        self.iv = iv.into();
        self
    }
}

impl Cbc<AES> {
    pub fn new(key: &[u8], iv: &[u8]) -> Cbc<AES> {
        Cbc { cipher: AES::new(key), iv: iv.into() }
    }
}

impl<C> BlockEncrypt for Cbc<C> where C: SingleBlockEncrypt {
    fn bs(&self) -> usize { C::bs() }
    fn encrypt<P: Padding>(&mut self, data: &[u8]) -> Vec<u8> {
        debug_assert_eq!(self.iv.len(), self.bs());
        P::padding(data, self.bs()).chunks(self.bs())
            .map(|b| {
                let text = self.cipher.encrypt(&xor(
                    b,
                    &self.iv
                ));
                self.set_iv(&text);
                text
            })
            .fold(Vec::new(), |mut sum, mut next| {
                sum.append(&mut next);
                sum
            })
    }
}

impl<C> BlockDecrypt for Cbc<C> where C: SingleBlockDecrypt {
    fn bs(&self) -> usize { C::bs() }
    fn decrypt<P: Padding>(&mut self, data: &[u8]) -> Result<Vec<u8>, DecryptFail> {
        debug_assert_eq!(self.iv.len(), self.bs());
        let out = data.chunks(self.bs())
            .map(|b| {
                let iv = self.iv.clone();
                self.set_iv(b);
                xor(
                    &self.cipher.decrypt(b),
                    &iv
                )
            })
            .fold(Vec::new(), |mut sum, mut next| {
                sum.append(&mut next);
                sum
            });
        P::unpadding(&out, self.bs()).map_err(|err| err.into())
    }
}
