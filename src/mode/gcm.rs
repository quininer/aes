use ::AES;
use ::utils::{ xor, eq };
use ::utils::ghash::Ghash;
use ::mode::Ctr;
use ::cipher::{
    DecryptFail,
    SingleBlockEncrypt,
    StreamEncrypt, StreamDecrypt,
    AeadStreamEncrypt, AeadStreamDecrypt
};


#[derive(Clone, Debug)]
pub struct Gcm<C> {
    cipher: C,
    mac: Ghash,
    end_tag: Vec<u8>
}

impl Gcm<Ctr<AES>> {
    pub fn new(key: &[u8], nonce: &[u8], aad: &[u8]) -> Self {
        debug_assert_eq!(nonce.len(), 12);
        let x: &[u8] = &[0x00, 0x00, 0x00, 0x01];
        let mut cipher = Ctr::new(key, &[nonce, x].concat());
        let hash_key = AES::new(key).encrypt(&[0; 16]);
        let end_tag = cipher.encrypt(&[0; 16]);
        let ghash = Ghash::new(&hash_key, aad);

        Gcm {
            cipher: cipher,
            mac: ghash,
            end_tag: end_tag
        }
    }
}

impl<C> AeadStreamEncrypt for Gcm<C> where C: StreamEncrypt {
    fn encrypt(&mut self, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let out = self.cipher.encrypt(data);
        let tag = xor(
            &self.end_tag,
            &self.mac.input(&out).result()
        );

        (out, tag)
    }
}

impl<C> AeadStreamDecrypt for Gcm<C> where C: StreamDecrypt {
    fn decrypt(&mut self, data: &[u8], tag: &[u8]) -> Result<Vec<u8>, DecryptFail> {
        let calc_tag = xor(
            &self.end_tag,
            &self.mac.input(data).result()
        );

        if eq(&calc_tag, tag) {
            Ok(self.cipher.decrypt(data))
        } else {
            Err(DecryptFail::Auth)
        }
    }
}
