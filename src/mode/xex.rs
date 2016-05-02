use ::AES;
use ::utils::xor;
use ::utils::padding::{ Padding, PaddingError };
use ::cipher::{
    SingleBlockEncrypt, SingleBlockDecrypt,
    BlockEncrypt, BlockDecrypt
};


pub struct Xex<C> {
    cipher: C,
    tweak: Vec<u8>,
}

impl Xex<AES> {
    pub fn new(key1: &[u8], key2: &[u8], i: &[u8]) -> Xex<AES> {
        Xex {
            cipher: AES::new(key1),
            tweak: AES::new(key2).encrypt(i),
        }
    }
}

impl<C> Xex<C> {
    pub fn set_tweak(&mut self, tweak: &[u8]) -> &mut Self {
        self.tweak = tweak.into();
        self
    }
}

impl<C> BlockEncrypt for Xex<C> where C: SingleBlockEncrypt {
    fn bs(&self) -> usize { C::bs() }
    fn encrypt<P: Padding>(&mut self, data: &[u8]) -> Vec<u8> {
        debug_assert_eq!(self.tweak.len(), self.bs());
        P::padding(data, self.bs()).chunks(self.bs())
            .map(|b| {
                let tweak = self.tweak.clone();
                self.set_tweak(&next_tweak(&tweak));
                xor(
                    &self.cipher.encrypt(&xor(b, &tweak)),
                    &tweak
                )
            })
            .fold(Vec::new(), |mut sum, mut next| {
                sum.append(&mut next);
                sum
            })
    }
}

impl<C> BlockDecrypt for Xex<C> where C: SingleBlockDecrypt {
    fn bs(&self) -> usize { C::bs() }
    fn decrypt<P: Padding>(&mut self, data: &[u8]) -> Result<Vec<u8>, PaddingError> {
        debug_assert_eq!(self.tweak.len(), self.bs());
        let out = data.chunks(self.bs())
            .map(|b| {
                let tweak = self.tweak.clone();
                self.set_tweak(&next_tweak(&tweak));
                xor(
                    &self.cipher.decrypt(&xor(b, &tweak)),
                    &tweak
                )
            })
            .fold(Vec::new(), |mut sum, mut next| {
                sum.append(&mut next);
                sum
            });
        P::unpadding(&out, self.bs())
    }
}

pub fn next_tweak(tweak: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tweak.len());
    let (mut x, mut y) = (0, 0);

    for &b in tweak.iter() {
        y = (b >> 7) & 1;
        out.push(((b << 1) + x) & 0xff);
        x = y
    }

    if y == 0 {
        out[0] ^= 0x87;
    }

    out
}

