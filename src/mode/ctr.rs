use ::AES;
use ::utils::xor;
use ::cipher::{
    SingleBlockEncrypt, SingleBlockDecrypt,
    StreamEncrypt, StreamDecrypt
};


#[derive(Clone)]
pub struct Ctr<C> {
    cipher: C,
    counter: Vec<u8>,
    buffer: Vec<u8>
}

impl<C> Ctr<C> {
    pub fn set_ctr(&mut self, ctr: &[u8]) -> &mut Self {
        self.counter = ctr.into();
        self.buffer.clear();
        self
    }
}

impl Ctr<AES> {
    pub fn new(key: &[u8], counter: &[u8]) -> Ctr<AES> {
        Ctr {
            cipher: AES::new(key),
            counter: counter.into(),
            buffer: Vec::with_capacity(15)
        }
    }
}

impl<C> StreamEncrypt for Ctr<C> where C: SingleBlockEncrypt {
    fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let buff_len = self.buffer.len();
        let buff = xor(&self.buffer, &data[..buff_len]);

        data[buff_len..].chunks(C::bs())
            .map(|b| {
                let counter = self.counter.clone();
                self.counter = add_ctr(&counter, 1);
                let keystream = self.cipher.encrypt(&counter);

                if b.len() < keystream.len() {
                    self.buffer = keystream[b.len()..].into();
                }

                xor(b, &keystream[..b.len()])
            })
            .fold(buff, |mut sum, mut next| {
                sum.append(&mut next);
                sum
            })
    }
}

impl<C> StreamDecrypt for Ctr<C> where C: SingleBlockEncrypt {
    fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        StreamEncrypt::encrypt(self, data)
    }
}

// from rust-crypto
fn add_ctr(ctr: &[u8], mut ammount: u8) -> Vec<u8> {
    let mut ctr: Vec<u8> = ctr.into();
    for (i, &b) in ctr.clone().iter().enumerate().rev() {
        ctr[i] = b.wrapping_add(ammount);
        if ctr[i] >= b { break };
        ammount = 1;
    }
    ctr.into()
}
