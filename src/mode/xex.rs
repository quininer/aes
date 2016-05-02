use ::AES;
use ::utils::xor;
use ::utils::padding::{ Padding, NoPadding };
use ::cipher::{
    DecryptFail,
    SingleBlockEncrypt, SingleBlockDecrypt,
    BlockEncrypt, BlockDecrypt,
    CtsBlockEncrypt, CtsBlockDecrypt
};


pub struct Xex<C> {
    cipher: C,
    tweak: Vec<u8>,
}
pub type Xts<C> = Xex<C>;

impl Xex<AES> {
    pub fn new(key1: &[u8], key2: &[u8], i: &[u8]) -> Self {
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

    pub fn next_tweak(tweak: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(tweak.len());
        let (mut x, mut y) = (0, 0);

        for &b in tweak {
            y = (b >> 7) & 1;
            out.push(((b << 1) + x) & 0xff);
            x = y
        }

        if y != 0 {
            out[0] ^= 0x87;
        }

        out
    }
}

impl<C> BlockEncrypt for Xex<C> where C: SingleBlockEncrypt {
    fn bs(&self) -> usize { C::bs() }
    fn encrypt<P: Padding>(&mut self, data: &[u8]) -> Vec<u8> {
        debug_assert_eq!(self.tweak.len(), self.bs());
        P::padding(data, self.bs()).chunks(self.bs())
            .map(|b| {
                let tweak = self.tweak.clone();
                self.set_tweak(&Self::next_tweak(&tweak));
                xex_encrypt(&self.cipher, b, &tweak)
            })
            .fold(Vec::new(), |mut sum, mut next| {
                sum.append(&mut next);
                sum
            })
    }
}

impl<C> BlockDecrypt for Xex<C> where C: SingleBlockDecrypt {
    fn bs(&self) -> usize { C::bs() }
    fn decrypt<P: Padding>(&mut self, data: &[u8]) -> Result<Vec<u8>, DecryptFail> {
        debug_assert_eq!(self.tweak.len(), self.bs());
        let out = data.chunks(self.bs())
            .map(|b| {
                let tweak = self.tweak.clone();
                self.set_tweak(&Self::next_tweak(&tweak));
                xex_decrypt(&self.cipher, b, &tweak)
            })
            .fold(Vec::new(), |mut sum, mut next| {
                sum.append(&mut next);
                sum
            });
        P::unpadding(&out, self.bs()).map_err(|err| err.into())
    }
}

impl<C> CtsBlockEncrypt for Xts<C> where C: SingleBlockEncrypt {
    fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        debug_assert!(data.len() >= self.bs());
        let bs = self.bs();
        let pos = data.len() / bs * bs;
        let (head, stealer) = data.split_at(pos);
        let head = BlockEncrypt::encrypt::<NoPadding>(self, head);
        let (head, tail) = head.split_at(pos - bs);

        if stealer.is_empty() {
            [
                &head[..pos-bs],
                tail,
                &head[pos-bs..]
            ].concat()
        } else {
            let tweak = self.tweak.clone();
            self.set_tweak(&Self::next_tweak(&tweak));

            [
                head,
                &xex_encrypt(&self.cipher, &[
                    &stealer,
                    &tail[stealer.len()..]
                ].concat(), &tweak),
                &tail[..stealer.len()]
            ].concat()
        }
    }
}

impl<C> CtsBlockDecrypt for Xts<C> where C: SingleBlockDecrypt {
    fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        debug_assert!(data.len() >= self.bs());
        let bs = self.bs();
        let pos = data.len() / bs * bs;
        let (head, tail) = data.split_at(pos);
        let (head, stealer) = head.split_at(pos - bs);

        if tail.is_empty() {
            BlockDecrypt::decrypt::<NoPadding>(self, &[
                &head[..pos-bs],
                stealer,
                &head[pos-bs..]
            ].concat()).unwrap()
        } else {
            let head = BlockDecrypt::decrypt::<NoPadding>(self, head).unwrap();
            let tweak_tail = self.tweak.clone();
            self.set_tweak(&Self::next_tweak(&tweak_tail));
            let tweak_stealer = self.tweak.clone();
            self.set_tweak(&Self::next_tweak(&tweak_stealer));

            let stealer = xex_decrypt(&self.cipher, stealer, &tweak_stealer);

            [
                &head,
                &xex_decrypt(
                    &self.cipher,
                    &[tail, &stealer[tail.len()..]].concat(),
                    &tweak_tail
                ),
                &stealer[..tail.len()]
            ].concat()
        }
    }
}

pub fn xex_encrypt<C: SingleBlockEncrypt>(cipher: &C, data: &[u8], tweak: &[u8]) -> Vec<u8> {
    xor(
        &cipher.encrypt(&xor(data, tweak)),
        tweak
    )
}

pub fn xex_decrypt<C: SingleBlockDecrypt>(cipher: &C, data: &[u8], tweak: &[u8]) -> Vec<u8> {
    xor(
        &cipher.decrypt(&xor(data, tweak)),
        tweak
    )
}
